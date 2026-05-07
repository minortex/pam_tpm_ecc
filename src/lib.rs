mod args;
mod crypto;
mod pubkey;
mod secure;
mod tpm;

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use args::parse_args;
use nonstick::{
    error, info, pam_export, warn, AuthnFlags, AuthtokAction, AuthtokFlags, BaseFlags, CredAction,
    ErrorCode, ModuleClient, PamModule, Result as PamResult,
};
use secure::SecureBuffer;
use zeroize::Zeroize;

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
                error!(handle, "{message}");
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
    let public_key = pubkey::load_public_key(&config.pubkey).map_err(service_error)?;
    let pin = prompt_pin(handle)?;

    let mut challenge = SecureBuffer::new(crypto::CHALLENGE_SIZE);
    if !challenge.locked() {
        warn!(handle, "mlock failed for challenge buffer; continuing");
    }
    challenge.copy_from_slice(&crypto::generate_challenge().map_err(auth_error)?);

    let signature = tpm::sign_challenge(&config.tcti, config.key_handle, &pin, &challenge)
        .map_err(auth_error)?;
    let signature = SecureBuffer::from_slice(&signature);
    if !signature.locked() {
        warn!(handle, "mlock failed for signature buffer; continuing");
    }

    crypto::verify_challenge(&public_key, &challenge, &signature).map_err(auth_error)
}

fn prompt_pin<M: ModuleClient>(handle: &mut M) -> Result<SecureBuffer, (ErrorCode, String)> {
    let mut pin_bytes = handle
        .authtok(Some(OsStr::from_bytes(b"[TPM] authenticate: ")))
        .map_err(|err| (err, "conversation failed".to_string()))?
        .into_vec();

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
