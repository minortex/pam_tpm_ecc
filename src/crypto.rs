use std::fs::File;
use std::io::{self, Read};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CHALLENGE_SIZE: usize = 32;
pub const RAW_SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to read random challenge: {0}")]
    Random(io::Error),
    #[error("invalid P-256 ECDSA signature")]
    InvalidSignature,
    #[error("signature mismatch")]
    SignatureMismatch,
}

pub fn generate_challenge() -> Result<[u8; CHALLENGE_SIZE], CryptoError> {
    let mut challenge = [0u8; CHALLENGE_SIZE];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut challenge))
        .map_err(CryptoError::Random)?;
    Ok(challenge)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn verify_challenge(
    key: &VerifyingKey,
    challenge: &[u8],
    raw_signature: &[u8],
) -> Result<(), CryptoError> {
    if raw_signature.len() != RAW_SIGNATURE_SIZE {
        return Err(CryptoError::InvalidSignature);
    }

    let signature =
        Signature::from_slice(raw_signature).map_err(|_| CryptoError::InvalidSignature)?;
    key.verify(challenge, &signature)
        .map_err(|_| CryptoError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn verifies_matching_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let challenge = b"challenge";
        let signature: Signature = signing_key.sign(challenge);

        verify_challenge(&verifying_key, challenge, &signature.to_bytes()).unwrap();
    }

    #[test]
    fn rejects_mismatched_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let signature: Signature = signing_key.sign(b"challenge");

        assert!(matches!(
            verify_challenge(&verifying_key, b"other", &signature.to_bytes()),
            Err(CryptoError::SignatureMismatch)
        ));
    }
}
