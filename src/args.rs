use std::path::PathBuf;

use thiserror::Error;

pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub key_handle: u32,
    pub pubkey: PubkeyConfig,
    pub tcti: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyConfig {
    File(PathBuf),
    Dir(PathBuf),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArgsError {
    #[error("key_handle= missing")]
    MissingKeyHandle,
    #[error("pubkey= or pubkey_dir= missing")]
    MissingPubkey,
    #[error("pubkey= and pubkey_dir= are mutually exclusive")]
    ConflictingPubkey,
    #[error("invalid key_handle: {0}")]
    InvalidKeyHandle(String),
}

pub fn parse_args(args: &[&str]) -> Result<Config, ArgsError> {
    let mut key_handle = None;
    let mut pubkey = None;
    let mut pubkey_dir = None;
    let mut tcti = DEFAULT_TCTI.to_string();

    for arg in args {
        if let Some(value) = arg.strip_prefix("key_handle=") {
            let parsed =
                parse_u32(value).ok_or_else(|| ArgsError::InvalidKeyHandle(value.to_string()))?;
            key_handle = Some(parsed);
        } else if let Some(value) = arg.strip_prefix("pubkey=") {
            if !value.is_empty() {
                pubkey = Some(PathBuf::from(value));
            }
        } else if let Some(value) = arg.strip_prefix("pubkey_dir=") {
            if !value.is_empty() {
                pubkey_dir = Some(PathBuf::from(value));
            }
        } else if let Some(value) = arg.strip_prefix("tcti=") {
            if !value.is_empty() {
                tcti = value.to_string();
            }
        }
    }

    let key_handle = key_handle.ok_or(ArgsError::MissingKeyHandle)?;
    if key_handle == 0 {
        return Err(ArgsError::MissingKeyHandle);
    }

    let pubkey = match (pubkey, pubkey_dir) {
        (Some(path), None) => PubkeyConfig::File(path),
        (None, Some(path)) => PubkeyConfig::Dir(path),
        (Some(_), Some(_)) => return Err(ArgsError::ConflictingPubkey),
        (None, None) => return Err(ArgsError::MissingPubkey),
    };

    Ok(Config {
        key_handle,
        pubkey,
        tcti,
    })
}

fn parse_u32(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }

    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u64>().ok()?
    };

    u32::try_from(parsed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_and_default_tcti() {
        let cfg = parse_args(&["key_handle=0x81020000", "pubkey=/etc/tpm.pub"]).unwrap();
        assert_eq!(cfg.key_handle, 0x8102_0000);
        assert_eq!(
            cfg.pubkey,
            PubkeyConfig::File(PathBuf::from("/etc/tpm.pub"))
        );
        assert_eq!(cfg.tcti, DEFAULT_TCTI);
    }

    #[test]
    fn parses_pubkey_dir() {
        let cfg = parse_args(&[
            "key_handle=0x81020000",
            "pubkey_dir=/etc/security/pam_tpm_ecc/keys",
        ])
        .unwrap();
        assert_eq!(
            cfg.pubkey,
            PubkeyConfig::Dir(PathBuf::from("/etc/security/pam_tpm_ecc/keys"))
        );
    }

    #[test]
    fn parses_decimal_handle_and_custom_tcti() {
        let cfg = parse_args(&[
            "key_handle=2164391936",
            "pubkey=/etc/tpm.pub",
            "tcti=swtpm:host=127.0.0.1,port=2321",
        ])
        .unwrap();
        assert_eq!(cfg.key_handle, 0x8102_0000);
        assert_eq!(cfg.tcti, "swtpm:host=127.0.0.1,port=2321");
    }

    #[test]
    fn rejects_invalid_handle() {
        assert_eq!(
            parse_args(&["key_handle=wat", "pubkey=/etc/tpm.pub"]).unwrap_err(),
            ArgsError::InvalidKeyHandle("wat".to_string())
        );
    }

    #[test]
    fn rejects_conflicting_pubkey_sources() {
        assert_eq!(
            parse_args(&[
                "key_handle=0x81020000",
                "pubkey=/etc/tpm.pub",
                "pubkey_dir=/etc/security/pam_tpm_ecc/keys",
            ])
            .unwrap_err(),
            ArgsError::ConflictingPubkey
        );
    }
}
