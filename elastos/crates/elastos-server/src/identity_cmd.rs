use std::io::{self, IsTerminal, Write};
use std::path::Path;

use anyhow::Context;

use elastos_server::sources::default_data_dir;

#[derive(Debug, Clone, Default)]
pub(crate) struct IdentityProfile {
    pub(crate) did: Option<String>,
    pub(crate) nickname: Option<String>,
}

pub async fn run_identity(cmd: crate::IdentityCommand) -> anyhow::Result<()> {
    match cmd {
        crate::IdentityCommand::ArmOwner {
            origin,
            rp_id,
            expires_in,
        } => {
            if !io::stdout().is_terminal() {
                anyhow::bail!("owner enrollment requires a local operator terminal");
            }
            let secret = elastos_server::auth::arm_owner_enrollment(
                &default_data_dir(),
                &origin,
                &rp_id,
                expires_in,
            )?;
            println!("Enter this one-use token in Home's owner setup field. It expires in {expires_in} seconds:");
            println!("{}", secret.as_str());
        }
        crate::IdentityCommand::ArmOwnerRecovery {
            origin,
            rp_id,
            expires_in,
        } => {
            if !io::stdout().is_terminal() {
                anyhow::bail!("owner recovery requires a local operator terminal");
            }
            let code = elastos_server::auth::arm_owner_recovery(
                &default_data_dir(),
                &origin,
                &rp_id,
                expires_in,
            )?;
            println!("On the Home sign-in screen, choose \"Recover this Home with your Recovery Kit\" and enter this code. It works once and expires in {expires_in} seconds:");
            println!("{}", code.as_str());
        }
        crate::IdentityCommand::Show => {
            let profile = load_identity_profile(&default_data_dir()).await?;
            print_identity_profile(&profile)?;
        }
        crate::IdentityCommand::Nickname(cmd) => match cmd {
            crate::IdentityNicknameCommand::Get => {
                let profile = load_identity_profile(&default_data_dir()).await?;
                if let Some(nick) = profile.nickname {
                    println!("{}", nick);
                }
            }
            crate::IdentityNicknameCommand::Set { value } => {
                let nick = set_local_nickname(&default_data_dir(), value).await?;
                println!("Nickname set to '{}'.", nick);
            }
        },
    }
    Ok(())
}

pub(crate) async fn load_identity_profile(data_dir: &Path) -> anyhow::Result<IdentityProfile> {
    let did = elastos_identity::load_or_create_did(data_dir)
        .ok()
        .map(|(_, did)| did)
        .filter(|did| !did.trim().is_empty());
    // A storage error is not absence: report it instead of showing "not set".
    let nickname = elastos_identity::load_nickname(data_dir).with_context(|| {
        format!(
            "nickname unreadable: {}",
            data_dir.join("did").join("nickname.enc").display()
        )
    })?;
    Ok(IdentityProfile { did, nickname })
}

pub(crate) async fn set_local_nickname(
    data_dir: &Path,
    value: Option<String>,
) -> anyhow::Result<String> {
    let current = load_identity_profile(data_dir).await.unwrap_or_default();
    let value = resolve_nickname_input(value, current.nickname.as_deref())?;
    let value = elastos_identity::validate_nickname(&value)?;
    elastos_identity::save_nickname(data_dir, &value)?;
    Ok(value)
}

fn print_identity_profile(profile: &IdentityProfile) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "Profile:   {}",
        if profile.did.is_some() {
            "initialized"
        } else {
            "not initialized yet"
        }
    )?;
    writeln!(
        out,
        "DID:       {}",
        profile.did.as_deref().unwrap_or("(not initialized yet)")
    )?;
    writeln!(
        out,
        "Nickname:  {}",
        profile.nickname.as_deref().unwrap_or("(not set)")
    )?;
    Ok(())
}

fn resolve_nickname_input(value: Option<String>, current: Option<&str>) -> anyhow::Result<String> {
    match value {
        Some(value) => Ok(value.trim().to_string()),
        None => prompt_for_nickname(current),
    }
}

fn prompt_for_nickname(current: Option<&str>) -> anyhow::Result<String> {
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        anyhow::bail!("nickname value missing; pass a value or run in an interactive terminal");
    }

    let prompt = current
        .filter(|nick| !nick.is_empty())
        .map(|nick| format!("Nickname [{}]: ", nick))
        .unwrap_or_else(|| "Nickname: ".to_string());
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    let read = io::stdin()
        .read_line(&mut input)
        .context("failed to read nickname")?;
    if read == 0 {
        anyhow::bail!("nickname prompt ended before a value was provided");
    }

    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        if let Some(current) = current.filter(|nick| !nick.is_empty()) {
            return Ok(current.to_string());
        }
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::{load_identity_profile, prompt_for_nickname};
    use std::io::IsTerminal;

    #[test]
    fn identity_profile_reports_three_nickname_path_states() {
        use std::os::unix::fs::PermissionsExt;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let did_dir = dir.path().join("did");
        std::fs::create_dir_all(&did_dir).unwrap();
        let nickname_path = did_dir.join("nickname.enc");

        // Absent: no nickname file means no nickname and no error.
        let absent = rt.block_on(load_identity_profile(dir.path())).unwrap();
        assert_eq!(absent.nickname, None);

        // Stored but unreadable: the check must report it, not read absence.
        std::fs::write(&nickname_path, b"permission-denied").unwrap();

        std::fs::set_permissions(&did_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = std::fs::read(&nickname_path).err();
        let unreadable = rt.block_on(load_identity_profile(dir.path()));
        std::fs::set_permissions(&did_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let Some(_denied) = denied else {
            eprintln!("skipping: running with permission override (root)");
            return;
        };

        let err = unreadable.expect_err("storage error must not be read as absence");
        let message = format!("{err:#}");
        assert!(message.starts_with("nickname unreadable: "), "{message}");
        assert!(message.contains("nickname.enc"), "{message}");

        // Present: the nickname is returned with no error.
        let data_dir = tempfile::tempdir().unwrap();
        let (signing_key, _did) = elastos_identity::load_or_create_did(data_dir.path()).unwrap();
        drop(signing_key);
        elastos_identity::save_nickname(data_dir.path(), "owner").unwrap();
        let present = rt.block_on(load_identity_profile(data_dir.path())).unwrap();
        assert_eq!(present.nickname.as_deref(), Some("owner"));
    }

    #[test]
    fn nickname_validation_rejects_empty() {
        assert!(elastos_identity::validate_nickname("   ").is_err());
    }

    #[test]
    fn nickname_validation_rejects_control_chars() {
        assert!(elastos_identity::validate_nickname("bad\nnick").is_err());
    }

    #[test]
    fn nickname_validation_accepts_simple_value() {
        assert!(elastos_identity::validate_nickname("owner").is_ok());
    }

    #[test]
    fn prompt_without_tty_and_without_value_would_fail() {
        // The helper must not silently invent a nickname when there is no tty.
        if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
            assert!(prompt_for_nickname(None).is_err());
        }
    }
}
