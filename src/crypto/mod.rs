use hmac::Hmac;
use sha2::Sha256;

pub mod auth;
pub mod num;

pub type HmacSha256 = Hmac<Sha256>;
