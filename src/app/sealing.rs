pub const SEALING_KEY_SIZE: usize = 128;
pub const SIGNATURE_SIZE: usize = 64;

pub struct SealingKey {
    pub key: [u8; SEALING_KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
}
