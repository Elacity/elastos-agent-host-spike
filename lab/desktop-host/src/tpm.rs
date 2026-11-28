//! Passkey keys in this computer's TPM security chip (ELASTOS-DESKTOP-APP P8 L2,
//! LAB DRAFT). The private key is made inside the TPM and never leaves it; the saved
//! blob loads only on this TPM. The key's TPM authorization comes from a PIN, so the
//! TPM itself checks the PIN and locks out after repeated wrong tries.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public,
    PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::utils::{create_unrestricted_signing_ecc_public, PublicKey};
use tss_esapi::{Context, Error};

const DEVICE: &str = "/dev/tpmrm0";
const GROUP: &str = "tss";
const MIN_PIN: usize = 6;
const TRIES: usize = 3;

struct State {
    epoch: u64,
    dialog: Option<Child>,
}

static STATE: Mutex<State> = Mutex::new(State {
    epoch: 0,
    dialog: None,
});

pub fn epoch() -> u64 {
    STATE.lock().map(|state| state.epoch).unwrap_or(u64::MAX)
}

/// Closes a PIN dialog in progress; the request it belonged to is refused.
pub fn cancel() {
    if let Ok(mut state) = STATE.lock() {
        state.epoch = state.epoch.wrapping_add(1);
        if let Some(dialog) = state.dialog.as_mut() {
            let _ = dialog.kill();
        }
    }
}

/// A new signing key in the TPM, guarded by a PIN the person chooses: the key blob
/// to save and the uncompressed P-256 public point.
pub fn create(expected: u64) -> Result<(Vec<u8>, [u8; 65]), ()> {
    let mut context = open(expected).ok_or(())?;
    let pin = new_pin(expected).ok_or(())?;
    let template = create_unrestricted_signing_ecc_public(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .map_err(|_| ())?;
    let auth = auth(&pin).map_err(|_| ())?;
    let parent = primary(&mut context).map_err(|_| ())?;
    let created = context.execute_with_nullauth_session(|ctx| {
        ctx.create(parent, template, Some(auth), None, None, None)
    });
    let _ = context.flush_context(parent.into());
    let created = created.map_err(|_| ())?;
    if epoch() != expected {
        return Err(());
    }

    let PublicKey::Ecc { x, y } = PublicKey::try_from(created.out_public.clone()).map_err(|_| ())?
    else {
        return Err(());
    };
    let mut point = [0u8; 65];
    point[0] = 0x04;
    if x.len() > 32 || y.len() > 32 {
        return Err(());
    }
    point[33 - x.len()..33].copy_from_slice(&x);
    point[65 - y.len()..].copy_from_slice(&y);

    let private = created.out_private.value();
    let public = created.out_public.marshall().map_err(|_| ())?;
    let mut blob = (private.len() as u32).to_be_bytes().to_vec();
    blob.extend(private);
    blob.extend(public);
    Ok((blob, point))
}

/// A DER ECDSA signature over SHA-256(message), after the person enters the key's PIN.
pub fn sign(expected: u64, blob: &[u8], message: &[u8], reason: &str) -> Result<Vec<u8>, ()> {
    let (private, public) = decode(blob).ok_or(())?;
    let mut context = open(expected).ok_or(())?;
    let digest = Digest::try_from(Sha256::digest(message).to_vec()).map_err(|_| ())?;
    for _ in 0..TRIES {
        let pin = ask(expected, &format!("Enter your PIN to {}.", markup(reason))).ok_or(())?;
        match sign_once(&mut context, &private, &public, &pin, &digest) {
            Ok(Signature::EcDsa(signature)) if epoch() == expected => {
                return Ok(der(
                    signature.signature_r().value(),
                    signature.signature_s().value(),
                ))
            }
            Ok(_) | Err(None) => return Err(()),
            Err(Some(error)) => match kind(error) {
                Some(Tss2ResponseCodeKind::AuthFail) => {
                    tell(expected, "--warning", "That PIN is not right.").ok_or(())?;
                }
                Some(Tss2ResponseCodeKind::Lockout) => {
                    tell(
                        expected,
                        "--error",
                        "Too many wrong PINs. The security chip has locked your passkeys for a while; try again later.",
                    );
                    return Err(());
                }
                _ => return Err(()),
            },
        }
    }
    Err(())
}

/// The signature, or the TPM's error from the step that checks the PIN (None when an
/// earlier step failed).
fn sign_once(
    context: &mut Context,
    private: &Private,
    public: &Public,
    pin: &str,
    digest: &Digest,
) -> Result<Signature, Option<Error>> {
    let parent = primary(context).map_err(|_| None)?;
    let key = context.execute_with_nullauth_session(|ctx| {
        ctx.load(parent, private.clone(), public.clone())
    });
    let _ = context.flush_context(parent.into());
    let key = key.map_err(|_| None)?;
    let ready = auth(pin)
        .and_then(|auth| context.tr_set_auth(key.into(), auth))
        .and_then(|()| {
            HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
                tag: TPM2_ST_HASHCHECK,
                hierarchy: TPM2_RH_NULL,
                digest: Default::default(),
            })
        });
    let signed = match ready {
        Ok(ticket) => context
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(key, digest.clone(), SignatureScheme::Null, ticket)
            })
            .map_err(Some),
        Err(_) => Err(None),
    };
    let _ = context.flush_context(key.into());
    signed
}

fn kind(error: Error) -> Option<Tss2ResponseCodeKind> {
    match error {
        Error::Tss2Error(code) => code.kind(),
        Error::WrapperError(_) => None,
    }
}

/// The TPM's standard ECC P-256 storage key, the same every time from the owner seed.
fn primary(context: &mut Context) -> Result<KeyHandle, Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;
    Ok(context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })?
        .key_handle)
}

fn auth(pin: &str) -> Result<Auth, Error> {
    Auth::try_from(Sha256::digest(pin.as_bytes()).to_vec())
}

fn decode(blob: &[u8]) -> Option<(Private, Public)> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    let private = blob.get(4..4usize.checked_add(len)?)?;
    let public = blob.get(4 + len..)?;
    Some((
        Private::try_from(private.to_vec()).ok()?,
        Public::unmarshall(public).ok()?,
    ))
}

fn der_integer(value: &[u8], out: &mut Vec<u8>) {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let value = &value[start..];
    let pad = value.first().map_or(true, |&b| b & 0x80 != 0);
    out.push(0x02);
    out.push((value.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend(value);
}

fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    der_integer(r, &mut body);
    der_integer(s, &mut body);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// The TPM, or None after telling the person why passkeys cannot be kept here.
fn open(expected: u64) -> Option<Context> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE)
    {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            grant(expected);
            return None;
        }
        Err(_) => {
            tell(
                expected,
                "--error",
                "This computer has no TPM security chip that ElastOS can use, so it cannot keep passkeys here.",
            );
            return None;
        }
    }
    let config = DeviceConfig::from_str(DEVICE).ok()?;
    Context::new(TctiNameConf::Device(config)).ok()
}

/// Asks once for an administrator to let this account use the TPM, which takes
/// effect at the next login.
fn grant(expected: u64) {
    let (Some(user), Some(gid)) = (user_name(), group_id(GROUP)) else {
        tell(expected, "--error", "ElastOS cannot use this computer's TPM security chip.");
        return;
    };
    let tss_device = std::fs::metadata(DEVICE).is_ok_and(|meta| meta.gid() == gid);
    if !tss_device {
        tell(expected, "--error", "ElastOS cannot use this computer's TPM security chip.");
        return;
    }
    let asked = run(
        expected,
        &[
            "--question".into(),
            "--ok-label=Allow".into(),
            "--cancel-label=Not Now".into(),
            "--text=ElastOS keeps your passkeys in this computer's TPM security chip. Your account needs permission to use it, which an administrator gives once.".into(),
        ],
    );
    if asked.is_none() || epoch() != expected {
        return;
    }
    let granted = Command::new("/usr/bin/pkexec")
        .args(["/usr/sbin/usermod", "-a", "-G", GROUP, &user])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if granted {
        tell(
            expected,
            "--info",
            "Done. Log out and back in, then open ElastOS and try again.",
        );
    } else {
        tell(expected, "--error", "Permission was not given, so passkeys stay off.");
    }
}

fn user_name() -> Option<String> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; 4096];
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .ok()?
        .to_owned();
    let valid = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    valid.then_some(name)
}

fn group_id(name: &str) -> Option<libc::gid_t> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; 16384];
    let status = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    (status == 0 && !found.is_null()).then_some(entry.gr_gid)
}

fn new_pin(expected: u64) -> Option<String> {
    for _ in 0..TRIES {
        let pin = ask(
            expected,
            &format!("Choose a PIN for this passkey (at least {MIN_PIN} characters). The TPM security chip checks it each time you sign in to your ElastOS Home."),
        )?;
        if pin.chars().count() < MIN_PIN {
            tell(expected, "--warning", &format!("Use at least {MIN_PIN} characters."))?;
            continue;
        }
        let again = ask(expected, "Enter the same PIN again.")?;
        if again == pin {
            return Some(pin);
        }
        tell(expected, "--warning", "The PINs did not match.")?;
    }
    None
}

fn ask(expected: u64, text: &str) -> Option<String> {
    let out = run(
        expected,
        &[
            "--entry".into(),
            "--hide-text".into(),
            "--ok-label=Continue".into(),
            format!("--text={text}"),
        ],
    )?;
    let pin = out.strip_suffix('\n').unwrap_or(&out).to_owned();
    (!pin.is_empty()).then_some(pin)
}

fn tell(expected: u64, kind: &str, text: &str) -> Option<String> {
    run(expected, &[kind.into(), format!("--text={text}")])
}

/// One zenity dialog for this request: its output when the person confirms, or None
/// when they cancel, the request is cancelled, or zenity is missing.
fn run(expected: u64, args: &[String]) -> Option<String> {
    {
        let mut state = STATE.lock().ok()?;
        if state.epoch != expected {
            return None;
        }
        state.dialog = Some(
            Command::new("zenity")
                .arg("--title=ElastOS")
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .ok()?,
        );
    }
    loop {
        {
            let mut state = STATE.lock().ok()?;
            let dialog = state.dialog.as_mut()?;
            match dialog.try_wait() {
                Ok(None) => {}
                Ok(Some(status)) => {
                    let mut dialog = state.dialog.take()?;
                    if !status.success() || state.epoch != expected {
                        return None;
                    }
                    let mut out = String::new();
                    dialog.stdout.take()?.read_to_string(&mut out).ok()?;
                    return Some(out);
                }
                Err(_) => {
                    state.dialog = None;
                    return None;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// zenity reads dialog text as Pango markup.
fn markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
