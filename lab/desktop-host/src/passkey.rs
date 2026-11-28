//! Passkeys for the Home window (ELASTOS-DESKTOP-APP P6, LAB DRAFT).
//!
//! A script in Home's top page hands each passkey request to this app, which
//! answers it with its own Secure Enclave passkeys (`authenticator`). Home's server
//! calls and session stay in the window.

use crate::runtime::HOME_URL;

const MAX_REQUEST_CHARS: usize = 16384;
const MAX_ANSWER_CHARS: usize = 65536;

/// Runs in Home's top page only. Passkey requests go to the app; anything else to
/// WebKit as before. WebKitGTK has no WebAuthn, so there the script supplies the
/// two names Home checks for.
#[cfg_attr(windows, allow(dead_code))]
pub const WINDOW_SCRIPT: &str = r#"(() => {
  if (window.location.origin !== "http://localhost:8090" || window.location.pathname !== "/home/"
    || !window.ipc) return;
  const native = navigator.credentials;
  const refuse = () => Promise.reject(new DOMException("Passkeys are not available here.", "NotSupportedError"));
  const create = native ? native.create.bind(native) : refuse;
  const get = native ? native.get.bind(native) : refuse;
  if (!native) Object.defineProperty(navigator, "credentials", { value: {} });
  if (!window.PublicKeyCredential) Object.defineProperty(window, "PublicKeyCredential", { value: class PublicKeyCredential {} });
  const pending = new Map();
  const names = ["NotAllowedError", "AbortError", "InvalidStateError", "SecurityError", "NotSupportedError"];
  let next = crypto.getRandomValues(new Uint32Array(1))[0];
  const b64 = (value) => {
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64 = (text) => {
    const base = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base + "=".repeat((4 - (base.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };
  const plain = (value) => value instanceof ArrayBuffer || ArrayBuffer.isView(value) ? b64(value)
    : Array.isArray(value) ? value.map(plain)
    : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
    : value;
  const ask = (kind, options) => {
    if (!options || !options.publicKey) return kind === "create" ? create(options) : get(options);
    const id = String(++next);
    const publicKey = plain(options.publicKey);
    const request = b64(new TextEncoder().encode(JSON.stringify({ v: 1, id, kind, publicKey })));
    if (request.length > 16384) {
      return Promise.reject(new DOMException("The passkey request is too large.", "NotSupportedError"));
    }
    return new Promise((resolve, reject) => {
      pending.set(id, { kind, resolve, reject });
      window.ipc.postMessage(`${id}:${request}`);
    });
  };
  navigator.credentials.create = (options) => ask("create", options);
  navigator.credentials.get = (options) => ask("get", options);
  Object.defineProperty(window, "__elastosPasskeys", { value: Object.freeze({ finish(id, answer) {
    const entry = pending.get(id);
    if (!entry) return false;
    pending.delete(id);
    let result = null;
    try { result = answer ? JSON.parse(new TextDecoder().decode(unb64(answer))) : null; } catch (_error) {}
    if (!result || result.v !== 1 || result.id !== id || !result.ok) {
      const name = names.includes(result && result.name) ? result.name : "NotAllowedError";
      entry.reject(new DOMException("The passkey request did not finish.", name));
      return false;
    }
    try {
      const credential = result.credential;
      const answerFields = credential.response;
      const response = { clientDataJSON: unb64(answerFields.clientDataJSON) };
      if (entry.kind === "create") {
        response.attestationObject = unb64(answerFields.attestationObject);
      } else {
        response.authenticatorData = unb64(answerFields.authenticatorData);
        response.signature = unb64(answerFields.signature);
        response.userHandle = answerFields.userHandle ? unb64(answerFields.userHandle) : null;
      }
      entry.resolve({ id: credential.id, rawId: unb64(credential.rawId), type: credential.type, response,
        getClientExtensionResults: () => ({}) });
      return true;
    } catch (_error) {
      entry.reject(new DOMException("The passkey request did not finish.", "NotAllowedError"));
      return false;
    }
  } }) });
})();"#;

fn base64url(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A passkey request `(id, request)` from the Home window, or `None` when the
/// message is malformed or did not come from Home's top page.
pub fn request(page: &str, body: &str) -> Option<(String, String)> {
    if page.split(['#', '?']).next() != Some(HOME_URL) {
        return None;
    }
    let (id, request) = body.split_once(':')?;
    let id_ok = !id.is_empty() && id.len() <= 12 && id.bytes().all(|b| b.is_ascii_digit());
    (id_ok && base64url(request, MAX_REQUEST_CHARS)).then(|| (id.to_owned(), request.to_owned()))
}

/// The script that returns `answer` (or a refusal) to request `id` in the window;
/// it evaluates to `true` only when that page took the credential.
pub fn finish_script(id: &str, answer: Option<&str>) -> String {
    match answer.filter(|answer| base64url(answer, MAX_ANSWER_CHARS)) {
        Some(answer) => {
            format!("window.__elastosPasskeys?.finish({id:?}, {answer:?}) === true;")
        }
        None => format!("window.__elastosPasskeys?.finish({id:?}, null) === true;"),
    }
}
