use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use sha2::{Sha256, Digest};

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

pub struct TokenCrypto {
    cipher: Aes256Gcm,
}

impl TokenCrypto {
    pub fn new(password: &str) -> Self {
        let key = Self::derive_key(password);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");
        Self { cipher }
    }
    
    fn derive_key(password: &str) -> [u8; KEY_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"NullSecDiscordShield_v1");
        let result = hasher.finalize();
        
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result);
        key
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        
        Ok(result)
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if data.len() < NONCE_SIZE {
            return Err("Data too short".into());
        }
        
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];
        
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;
        
        Ok(plaintext)
    }
}

/// Obfuscate token in memory to prevent simple memory scanning
pub fn obfuscate_token(token: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let key: u8 = rng.gen();
    
    let mut obfuscated = vec![key];
    for byte in token.bytes() {
        obfuscated.push(byte ^ key);
    }
    
    obfuscated
}

pub fn deobfuscate_token(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    
    let key = data[0];
    let deobfuscated: Vec<u8> = data[1..].iter().map(|b| b ^ key).collect();
    
    String::from_utf8(deobfuscated).ok()
}
