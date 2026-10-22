use std::env;

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::HmacSha256;

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing auth secret")]
    MissingSecret,

    #[error("invalid HMAC secret length")]
    InvalidSecretLength,
}

pub struct Auth {
    pub mac: HmacSha256,
    pub secret: [u8; 32],
}

impl Auth {
    pub fn new() -> Result<Self, Error> {
        let raw_secret = env::var("SECRET").map_err(|_| Error::MissingSecret)?;
        Self::from_secret(raw_secret.as_bytes())
    }

    pub fn from_secret(raw_secret: &[u8]) -> Result<Self, Error> {
        let secret: [u8; 32] = Sha256::digest(raw_secret).into();
        let mac = HmacSha256::new_from_slice(&secret).map_err(|_| Error::InvalidSecretLength)?;

        Ok(Self { mac, secret })
    }
}

#[cfg(test)]
mod tests {
    use hmac::Mac;
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn from_secret_hashes_raw_secret_for_hmac_key() {
        let raw_secret = b"test secret";
        let auth = Auth::from_secret(raw_secret).unwrap();

        let expected: [u8; 32] = Sha256::digest(raw_secret).into();
        assert_eq!(auth.secret, expected);
    }

    #[test]
    fn from_secret_initializes_working_hmac() {
        let auth = Auth::from_secret(b"test secret").unwrap();
        let mut mac = auth.mac.clone();
        mac.update(b"message");
        let tag = mac.finalize().into_bytes();

        let mut expected = HmacSha256::new_from_slice(&auth.secret).unwrap();
        expected.update(b"message");
        assert_eq!(tag.as_slice(), expected.finalize().into_bytes().as_slice());
    }
}
