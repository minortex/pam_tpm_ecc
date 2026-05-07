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
    #[error("invalid TCTI {value}: {source}")]
    Tcti { value: String, source: TssError },
    #[error("TPM operation failed at {where_}: {source}")]
    Operation {
        where_: &'static str,
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
    let tcti_name = TctiNameConf::from_str(tcti).map_err(|source| TpmError::Tcti {
        value: tcti.to_string(),
        source,
    })?;
    let mut context = Context::new(tcti_name).map_err(|source| TpmError::Operation {
        where_: "Context::new",
        source,
    })?;

    match context.startup(StartupType::Clear) {
        Ok(()) => {}
        Err(TssError::Tss2Error(code)) if code.kind() == Some(Tss2ResponseCodeKind::Initialize) => {
        }
        Err(source) => {
            return Err(TpmError::Operation {
                where_: "Startup",
                source,
            });
        }
    }

    let tpm_handle = TpmHandle::try_from(key_handle).map_err(|source| TpmError::Operation {
        where_: "TpmHandle::try_from",
        source,
    })?;
    let key = context
        .tr_from_tpm_public(tpm_handle)
        .map_err(|source| TpmError::Operation {
            where_: "TR_FromTPMPublic",
            source,
        })?;

    if !pin.is_empty() {
        let auth = Auth::try_from(pin).map_err(|source| TpmError::Operation {
            where_: "Auth::try_from",
            source,
        })?;
        context
            .tr_set_auth(key, auth)
            .map_err(|source| TpmError::Operation {
                where_: "TR_SetAuth",
                source,
            })?;
    }

    context.set_sessions((Some(AuthSession::Password), None, None));

    let digest = Digest::try_from(crypto::sha256(challenge).as_slice()).map_err(|source| {
        TpmError::Operation {
            where_: "Digest::try_from",
            source,
        }
    })?;
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };
    let ticket = null_hashcheck_ticket()?;

    let signature = context
        .sign(key.into(), digest, scheme, ticket)
        .map_err(|source| TpmError::Operation {
            where_: "Sign",
            source,
        })?;

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

    raw.try_into().map_err(|source| TpmError::Operation {
        where_: "HashcheckTicket::try_from",
        source,
    })
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
