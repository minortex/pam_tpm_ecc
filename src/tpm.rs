use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use thiserror::Error;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::{StartupType, StructureTag};
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Digest, HashScheme, HashcheckTicket, Signature, SignatureScheme,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK};
use tss_esapi::{Context, Error as TssError};

use crate::crypto;

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("invalid TCTI {value}: {detail}")]
    Tcti {
        value: String,
        detail: String,
        source: TssError,
    },
    #[error("TPM operation failed at {where_}: {detail}")]
    Operation {
        where_: &'static str,
        detail: String,
        source: TssError,
    },
    #[error("TPM did not return an ECDSA signature")]
    NonEcdsaSignature,
    #[error("invalid P-256 signature component size")]
    InvalidSignatureSize,
}

pub fn sign_challenge(
    tcti: &str,
    key_handle: u32,
    pin: &[u8],
    challenge: &[u8],
) -> Result<[u8; crypto::RAW_SIGNATURE_SIZE], TpmError> {
    let tcti_name = TctiNameConf::from_str(tcti).map_err(|source| {
        let detail = tss_error_detail(&source);
        TpmError::Tcti {
            value: tcti.to_string(),
            detail,
            source,
        }
    })?;
    let mut context =
        Context::new(tcti_name).map_err(|source| tpm_operation_error("Context::new", source))?;

    match context.startup(StartupType::Clear) {
        Ok(()) => {}
        Err(TssError::Tss2Error(code)) if code.kind() == Some(Tss2ResponseCodeKind::Initialize) => {
        }
        Err(source) => {
            return Err(tpm_operation_error("Startup", source));
        }
    }

    let tpm_handle = TpmHandle::try_from(key_handle)
        .map_err(|source| tpm_operation_error("TpmHandle::try_from", source))?;
    let key = context
        .tr_from_tpm_public(tpm_handle)
        .map_err(|source| tpm_operation_error("TR_FromTPMPublic", source))?;

    if !pin.is_empty() {
        let auth =
            Auth::try_from(pin).map_err(|source| tpm_operation_error("Auth::try_from", source))?;
        context
            .tr_set_auth(key, auth)
            .map_err(|source| tpm_operation_error("TR_SetAuth", source))?;
    }

    context.set_sessions((Some(AuthSession::Password), None, None));

    let digest = Digest::try_from(crypto::sha256(challenge).as_slice())
        .map_err(|source| tpm_operation_error("Digest::try_from", source))?;
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };
    let ticket = null_hashcheck_ticket()?;

    let signature = context
        .sign(key.into(), digest, scheme, ticket)
        .map_err(|source| tpm_operation_error("Sign", source))?;

    raw_p256_signature(signature)
}

fn null_hashcheck_ticket() -> Result<HashcheckTicket, TpmError> {
    let raw = TPMT_TK_HASHCHECK {
        tag: StructureTag::Hashcheck.into(),
        hierarchy: TpmHandle::from(Hierarchy::Null).into(),
        digest: TPM2B_DIGEST {
            size: 0,
            buffer: [0; 64],
        },
    };

    raw.try_into()
        .map_err(|source| tpm_operation_error("HashcheckTicket::try_from", source))
}

fn tpm_operation_error(where_: &'static str, source: TssError) -> TpmError {
    let detail = tss_error_detail(&source);
    TpmError::Operation {
        where_,
        detail,
        source,
    }
}

fn tss_error_detail(error: &TssError) -> String {
    match error {
        TssError::Tss2Error(code) => {
            let debug = format!("{code:?}");
            let raw = raw_response_code_from_debug(&debug)
                .map(|raw| format!("; raw={raw} (0x{raw:08x})"))
                .unwrap_or_default();
            format!("{code}{raw}; debug={debug}; kind={:?}", code.kind())
        }
        TssError::WrapperError(kind) => {
            format!("{kind}; debug={kind:?}")
        }
    }
}

fn raw_response_code_from_debug(debug: &str) -> Option<u32> {
    let start = debug.find(".0: ")? + 4;
    let end = debug[start..]
        .find(|ch: char| !ch.is_ascii_digit())
        .map(|offset| start + offset)
        .unwrap_or(debug.len());
    debug[start..end].parse().ok()
}

fn raw_p256_signature(signature: Signature) -> Result<[u8; crypto::RAW_SIGNATURE_SIZE], TpmError> {
    let Signature::EcDsa(sig) = signature else {
        return Err(TpmError::NonEcdsaSignature);
    };

    let r = sig.signature_r().value();
    let s = sig.signature_s().value();
    if r.len() > 32 || s.len() > 32 {
        return Err(TpmError::InvalidSignatureSize);
    }

    let mut raw = [0u8; crypto::RAW_SIGNATURE_SIZE];
    raw[32 - r.len()..32].copy_from_slice(r);
    raw[64 - s.len()..64].copy_from_slice(s);
    Ok(raw)
}
