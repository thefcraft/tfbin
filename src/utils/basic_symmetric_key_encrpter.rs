use super::sha256::sha256;
use super::random::Random;
#[derive(Clone)]
pub struct BasicSymmetricKeyEncrpter{
    pub key: Vec<u8>,
    pub key_len: usize,
    pub key_hash_sha256_pow_10: [u8; 32] // taking power of 10 to increase safty aginest brute force
}
impl BasicSymmetricKeyEncrpter {
    pub fn new(key: Vec<u8>) -> Self{
        let key_len = key.len();
        let mut key_hash_sha256_pow_10 = sha256(key.clone());
        for _ in 0..9{
            key_hash_sha256_pow_10 = sha256(Vec::from(key_hash_sha256_pow_10));
        }
        Self { key, key_len, key_hash_sha256_pow_10 }
    }
    
    pub fn set_key(&mut self, key: Vec<u8>){
        let key_len = key.len();
        let mut key_hash_sha256_pow_10 = sha256(key.clone());
        for _ in 0..9{
            key_hash_sha256_pow_10 = sha256(Vec::from(key_hash_sha256_pow_10));
        }
        self.key = key;
        self.key_hash_sha256_pow_10 = key_hash_sha256_pow_10;
        self.key_len = key_len;
    }
    pub fn from_random_key(key_len: usize) -> Self{
        let mut random = Random::new();
        let mut key = Vec::<u8>::with_capacity(key_len);
        for _ in 0..key_len{
            key.push(random.randint(0, 255) as u8);
        }
        Self::new(key)
    }
    fn new_key(mut old_key: Vec<u8>, data_last: &Vec<u8>)->Vec<u8>{
        old_key.extend(data_last.iter());
        Vec::from(sha256(old_key))
    }
    fn encrypt_chunk(&self, chunk: &[u8], key: &[u8])->Vec<u8>{
        return chunk.iter().zip(key.iter()).map(|(&a, &b)| a ^ b).collect();
    }
    pub fn encrypt(&self, data: &[u8])->Vec<u8>{
        let mut result = Vec::<u8>::with_capacity(data.len());
        // Process the initial chunk separately
        let mut initial_chunk = Vec::<u8>::with_capacity(self.key_len);
        for i in 0..usize::min(self.key_len, data.len()){
            initial_chunk.push(data[i]);
        }
        result.extend(self.encrypt_chunk(&initial_chunk, &self.key).iter());
        let mut key = BasicSymmetricKeyEncrpter::new_key(self.key.clone(), &initial_chunk);
        
        // Process the rest of the data in chunks of 32 bytes
        let mut i = self.key_len;
        while i<data.len() {
            let mut chunk = Vec::<u8>::with_capacity(32);
            for offset in 0..32{
                if offset+i < data.len() {
                    chunk.push(data[offset+i]);
                }
            }
            result.extend(self.encrypt_chunk(&chunk, &key).iter());
            key = BasicSymmetricKeyEncrpter::new_key(key.clone(), &chunk);
            i += 32;
        }
        result
    }
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8>{
        let mut result = Vec::<u8>::with_capacity(data.len());
        // Process the initial chunk separately
        let mut initial_chunk = Vec::<u8>::with_capacity(self.key_len);
        for i in 0..usize::min(self.key_len, data.len()){
            initial_chunk.push(data[i]);
        }
        result.extend(self.encrypt_chunk(&initial_chunk, &self.key).iter());
        let mut key = BasicSymmetricKeyEncrpter::new_key(self.key.clone(), &result);
        // Process the rest of the data in chunks of 32 bytes
        let mut i = self.key_len;
        while i<data.len() {
            let mut chunk = Vec::<u8>::with_capacity(32);
            for offset in 0..32{
                if offset+i < data.len() {
                    chunk.push(data[offset+i]);
                }
            }
            let decrypted = self.encrypt_chunk(&chunk, &key);
            result.extend(decrypted.iter());
            key = BasicSymmetricKeyEncrpter::new_key(key.clone(), &decrypted);
            i += 32;
        }
        result
    }
}