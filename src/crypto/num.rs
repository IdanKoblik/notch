use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn encrypt_u32(value: u32, key: &[u8; 32]) -> u32 {
    let mut left = (value >> 16) as u16;
    let mut right = value as u16;

    for round in 0u8..8 {
        let f = round_function(right, round, key);

        (left, right) = (right, left ^ f);
    }

    ((left as u32) << 16) | right as u32
}

pub fn decrypt_u32(value: u32, key: &[u8; 32]) -> u32 {
    let mut left = (value >> 16) as u16;
    let mut right = value as u16;

    for round in (0u8..8).rev() {
        let f = round_function(left, round, key);

        (left, right) = (right ^ f, left);
    }

    ((left as u32) << 16) | right as u32
}

fn round_function(value: u16, round: u8, key: &[u8; 32]) -> u16 {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("32-byte HMAC key is valid");

    mac.update(&[round]);
    mac.update(&value.to_be_bytes());

    let result = mac.finalize().into_bytes();

    u16::from_be_bytes([result[0], result[1]])
}

#[cfg(test)]
mod tests {
    use rand::RngExt;
    use super::*;

    #[test]
    fn test_transcript() {
        let payload: u32 = 1234;
        let mut rng = rand::rng();
        let mut value = [0u8; 32];

        rng.fill(&mut value);
        assert!(value.iter().any(|&b| b != 0));

        let encrypted = encrypt_u32(payload, &value);
        let decrypted = decrypt_u32(encrypted, &value);

        assert_eq!(payload, decrypted);
    }
}
