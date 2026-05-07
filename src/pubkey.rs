use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PubkeyError {
    #[error("open({path}) failed: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("fstat({path}) failed: {source}")]
    Metadata { path: PathBuf, source: io::Error },
    #[error("{0} is not a regular file")]
    NotRegular(PathBuf),
    #[error("{0} is not owned by root")]
    NotRootOwned(PathBuf),
    #[error("{path} has overly-permissive mode {mode:o}")]
    PermissiveMode { path: PathBuf, mode: u32 },
    #[error("read({path}) failed: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to parse P-256 SPKI PEM public key: {0}")]
    Parse(String),
}

pub fn load_public_key(path: &Path) -> Result<VerifyingKey, PubkeyError> {
    let mut file = open_and_validate(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)
        .map_err(|source| PubkeyError::Read {
            path: path.to_path_buf(),
            source,
        })?;

    VerifyingKey::from_public_key_pem(&pem).map_err(|err| PubkeyError::Parse(err.to_string()))
}

fn open_and_validate(path: &Path) -> Result<File, PubkeyError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_CLOEXEC);

    let file = options.open(path).map_err(|source| PubkeyError::Open {
        path: path.to_path_buf(),
        source,
    })?;

    let metadata = file.metadata().map_err(|source| PubkeyError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;

    if !metadata.file_type().is_file() {
        return Err(PubkeyError::NotRegular(path.to_path_buf()));
    }
    if metadata.uid() != 0 {
        return Err(PubkeyError::NotRootOwned(path.to_path_buf()));
    }

    let mode = metadata.mode() & 0o7777;
    if (mode & !0o644) != 0 {
        return Err(PubkeyError::PermissiveMode {
            path: path.to_path_buf(),
            mode,
        });
    }

    Ok(file)
}
