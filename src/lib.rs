mod args;
mod crypto;
mod pubkey;
mod secure;
mod tpm;

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use args::{parse_args, PubkeyConfig};
use nonstick::{
    error, info, pam_export, warn, AuthnFlags, AuthtokAction, AuthtokFlags, BaseFlags, CredAction,
    ErrorCode, ModuleClient, PamModule, Result as PamResult,
};
use secure::SecureBuffer;
use zeroize::{Zeroize, Zeroizing};

struct TpmPamModule;
pam_export!(TpmPamModule);

impl<M: ModuleClient> PamModule<M> for TpmPamModule {
    fn authenticate(handle: &mut M, args: Vec<&CStr>, _flags: AuthnFlags) -> PamResult<()> {
        match authenticate(handle, &args) {
            Ok(()) => {
                info!(handle, "TPM ECC authentication succeeded");
                Ok(())
            }
            Err((code, message)) => {
                if code == ErrorCode::Ignore {
                    info!(handle, "{message}");
                } else {
                    error!(handle, "{message}");
                }
                Err(code)
            }
        }
    }

    fn account_management(_handle: &mut M, _args: Vec<&CStr>, _flags: AuthnFlags) -> PamResult<()> {
        Ok(())
    }

    fn set_credentials(
        _handle: &mut M,
        _args: Vec<&CStr>,
        _action: CredAction,
        _flags: BaseFlags,
    ) -> PamResult<()> {
        Ok(())
    }

    fn open_session(_handle: &mut M, _args: Vec<&CStr>, _flags: BaseFlags) -> PamResult<()> {
        Ok(())
    }

    fn close_session(_handle: &mut M, _args: Vec<&CStr>, _flags: BaseFlags) -> PamResult<()> {
        Ok(())
    }

    fn change_authtok(
        _handle: &mut M,
        _args: Vec<&CStr>,
        _action: AuthtokAction,
        _flags: AuthtokFlags,
    ) -> PamResult<()> {
        Ok(())
    }
}

pub fn diagnostic_sign(
    pin: &[u8],
    key_handle: u32,
    tcti: &str,
) -> Result<[u8; crypto::RAW_SIGNATURE_SIZE], Box<dyn std::error::Error>> {
    let challenge = crypto::generate_challenge()?;
    Ok(tpm::sign_challenge(tcti, key_handle, pin, &challenge)?)
}

fn authenticate<M: ModuleClient>(
    handle: &mut M,
    args: &[&CStr],
) -> Result<(), (ErrorCode, String)> {
    let args = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            (
                ErrorCode::ServiceError,
                "PAM argument is not UTF-8".to_string(),
            )
        })?;
    let config = parse_args(&args).map_err(service_error)?;
    let public_key = load_configured_public_key(handle, &config.pubkey)?;
    let pin = prompt_pin(handle)?;

    let mut challenge = SecureBuffer::new(crypto::CHALLENGE_SIZE);
    if !challenge.locked() {
        warn!(handle, "mlock failed for challenge buffer; continuing");
    }
    let challenge_bytes = Zeroizing::new(crypto::generate_challenge().map_err(auth_error)?);
    challenge.copy_from_slice(challenge_bytes.as_ref());

    let signature_bytes = Zeroizing::new(
        tpm::sign_challenge(&config.tcti, config.key_handle, &pin, &challenge)
            .map_err(auth_error)?,
    );
    let signature = SecureBuffer::from_slice(signature_bytes.as_ref());
    if !signature.locked() {
        warn!(handle, "mlock failed for signature buffer; continuing");
    }

    crypto::verify_challenge(&public_key, &challenge, &signature).map_err(auth_error)
}

fn load_configured_public_key<M: ModuleClient>(
    handle: &mut M,
    config: &PubkeyConfig,
) -> Result<p256::ecdsa::VerifyingKey, (ErrorCode, String)> {
    match config {
        PubkeyConfig::File(path) => pubkey::load_public_key(path).map_err(service_error),
        PubkeyConfig::Dir(dir) => {
            let username = handle.username(None).map_err(|err| {
                (
                    err,
                    "failed to get PAM username for pubkey_dir lookup".to_string(),
                )
            })?;
            let path = user_pubkey_path(dir, username.as_bytes())?;
            match pubkey::load_public_key(&path) {
                Ok(key) => Ok(key),
                Err(pubkey::PubkeyError::Open { path, source })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    Err((
                        ErrorCode::Ignore,
                        format!(
                            "no TPM public key configured for user at {}; ignoring module",
                            path.display()
                        ),
                    ))
                }
                Err(err) => Err(service_error(err)),
            }
        }
    }
}

fn user_pubkey_path(dir: &Path, username: &[u8]) -> Result<PathBuf, (ErrorCode, String)> {
    let username = std::str::from_utf8(username).map_err(|_| {
        (
            ErrorCode::ServiceError,
            "PAM username is not UTF-8; cannot use pubkey_dir".to_string(),
        )
    })?;

    if !is_safe_username_component(username) {
        return Err((
            ErrorCode::ServiceError,
            format!("PAM username is not safe for pubkey_dir lookup: {username:?}"),
        ));
    }

    Ok(dir.join(format!("{username}.pem")))
}

fn is_safe_username_component(username: &str) -> bool {
    !username.is_empty()
        && username != "."
        && username != ".."
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn prompt_pin<M: ModuleClient>(handle: &mut M) -> Result<SecureBuffer, (ErrorCode, String)> {
    let mut pin_bytes = Zeroizing::new(
        handle
            .authtok(Some(OsStr::from_bytes(b"[TPM] authenticate: ")))
            .map_err(|err| (err, "conversation failed".to_string()))?
            .into_vec(),
    );

    let pin = SecureBuffer::from_slice(&pin_bytes);
    pin_bytes.zeroize();
    if !pin.locked() && !pin.is_empty() {
        warn!(handle, "mlock failed for PIN buffer; continuing");
    }

    Ok(pin)
}

fn service_error(error: impl ToString) -> (ErrorCode, String) {
    (ErrorCode::ServiceError, error.to_string())
}

fn auth_error(error: impl ToString) -> (ErrorCode, String) {
    (ErrorCode::AuthenticationError, error.to_string())
}
