// Compile using release flag e.g., cargo run --release or cargo r -r
// Test File Size :- 36.2 MB
// Time Taken in python :- 126077.307701ms
// Time Taken in Rust :- 253.673ms 
// (300-500x faster then python approch)

use std::fs::File;
use std::io::Read;
use std::time::Instant;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (g & !e)
}
#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}
// fn rotate(x:u32, n: u8) -> u32 {
//     (x >> n) | (x << (32-n))
// }
#[inline(always)]
fn s0(x:u32) -> u32{
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    // rotate(x, 7) ^ rotate(x, 18) ^ x>>3
}
#[inline(always)]
fn s1(x: u32) -> u32{
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    // rotate(x, 17) ^ rotate(x, 19) ^ x>>10
}
#[inline(always)]
fn sigma0(x: u32) -> u32{
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    // rotate(x, 2) ^ rotate(x, 13) ^ rotate(x, 22)
}
#[inline(always)]
fn sigma1(x: u32) -> u32{
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    // rotate(x, 6) ^ rotate(x, 11) ^ rotate(x, 25)
}

fn int2vec(num: usize) -> Vec<u8>{
    let mut result = Vec::with_capacity(8);
    for i in (0..8).rev() {
        let byte = (num >> (i * 8)) as u8;
        result.push(byte);
    }
    result
}

fn preprocess(data: Vec<u8>) -> Vec<u8>{
    let length_bits = data.len()*8;
    let mut result = data;
    result.push(128); // 128 => b'\x80'
    while result.len() % 64 != 56 {
        result.push(0);
    }
    for i in int2vec(length_bits){
        result.push(i);
    }
    result
}

fn unpack_chunk(chunk: &[u8]) -> Vec<u32> {
    assert_eq!(chunk.len(), 16 * 4); // Ensure chunk length is exactly 64 bytes (16 * 4)

    let mut result = Vec::with_capacity(64);

    for i in 0..16 {
        let idx = i * 4;
        let value: u32 = ((chunk[idx] as u32) << 24) |
                    ((chunk[idx + 1] as u32) << 16) |
                    ((chunk[idx + 2] as u32) << 8) |
                    (chunk[idx + 3] as u32);
        result.push(value);
    }
    for _ in 16..64{
        result.push(0);
    }
    result
}

pub fn sha256(data: Vec<u8>) -> [u8; 32]{
    let data = preprocess(data);
    let H = (0x6a09e667 as u32, 0xbb67ae85 as u32, 0x3c6ef372 as u32, 0xa54ff53a as u32, 
                                           0x510e527f as u32, 0x9b05688c as u32, 0x1f83d9ab as u32, 0x5be0cd19 as u32);
    
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = H;

    for chunk in data.chunks(64) {
        let mut W = unpack_chunk(chunk);
        for t in 16..64{
            W[t] = (s1(W[t-2]) as u64 + W[t-7] as u64 + s0(W[t-15]) as u64 + W[t-16] as u64) as u32;
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (h0, h1, h2, h3, h4, h5, h6, h7);
        for t in 0..64{
            let T1 = (h as u64 + sigma1(e) as u64 + ch(e, f, g) as u64 + K[t] as u64 + W[t] as u64) as u32;
            let T2 = (sigma0(a) as u64 + maj(a, b, c) as u64) as u32;
            h = g;
            g = f;
            f = e;
            e = (d as u64 + T1 as u64) as u32;
            d = c;
            c = b;
            b = a;
            a = (T1 as u64 + T2 as u64) as u32;
        }
        h0 = (a as u64 + h0 as u64) as u32;
        h1 = (b as u64 + h1 as u64) as u32;
        h2 = (c as u64 + h2 as u64) as u32;
        h3 = (d as u64 + h3 as u64) as u32;
        h4 = (e as u64 + h4 as u64) as u32;
        h5 = (f as u64 + h5 as u64) as u32;
        h6 = (g as u64 + h6 as u64) as u32;
        h7 = (h as u64 + h7 as u64) as u32;
    }
    let h = [
        (h0 & 0xFF) as u8,
        ((h0 >> 8) & 0xFF) as u8,
        ((h0 >> 16) & 0xFF) as u8,
        ((h0 >> 24) & 0xFF) as u8,

        (h1 & 0xFF) as u8,
        ((h1 >> 8) & 0xFF) as u8,
        ((h1 >> 16) & 0xFF) as u8,
        ((h1 >> 24) & 0xFF) as u8,

        (h2 & 0xFF) as u8,
        ((h2 >> 8) & 0xFF) as u8,
        ((h2 >> 16) & 0xFF) as u8,
        ((h2 >> 24) & 0xFF) as u8,

        (h3 & 0xFF) as u8,
        ((h3 >> 8) & 0xFF) as u8,
        ((h3 >> 16) & 0xFF) as u8,
        ((h3 >> 24) & 0xFF) as u8,

        (h4 & 0xFF) as u8,
        ((h4 >> 8) & 0xFF) as u8,
        ((h4 >> 16) & 0xFF) as u8,
        ((h4 >> 24) & 0xFF) as u8,

        (h5 & 0xFF) as u8,
        ((h5 >> 8) & 0xFF) as u8,
        ((h5 >> 16) & 0xFF) as u8,
        ((h5 >> 24) & 0xFF) as u8,

        (h6 & 0xFF) as u8,
        ((h6 >> 8) & 0xFF) as u8,
        ((h6 >> 16) & 0xFF) as u8,
        ((h6 >> 24) & 0xFF) as u8,

        (h7 & 0xFF) as u8,
        ((h7 >> 8) & 0xFF) as u8,
        ((h7 >> 16) & 0xFF) as u8,
        ((h7 >> 24) & 0xFF) as u8,
    ];
    return h;
}

fn read_file_to_bytes(file_path: &str) -> std::io::Result<Vec<u8>> {
    // Open the file in read-only mode
    let mut file = File::open(file_path)?;

    // Get the file metadata to determine its size
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    // Create a buffer to hold the file contents
    let mut buffer = vec![0; file_size];

    // Read the entire file contents into the buffer
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

fn measure_time<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let start_time = Instant::now();
    let result = f();
    let end_time = Instant::now();
    let elapsed_time = end_time - start_time;
    println!("Elapsed time: {:?}", elapsed_time);
    result
}

// fn main() {
//     // let data = String::from("Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!Hello, world!");
//     // let mut bytes = Vec::<u8>::new();
//     // for c in data.bytes(){bytes.push(c);}
//     let file_path = r"C:\Users\laksh\Downloads\localtonet-win-64.zip"; 
//     match read_file_to_bytes(file_path) {
//         Ok(bytes) => {
//             println!("Successfully read {} bytes from file.", bytes.len());
//             println!("{}", measure_time(|| {
//                 sha256(bytes)
//             }));
//         },
//         Err(e) => {
//             eprintln!("Error reading file: {}", e);
//             // Handle error gracefully
//         }
//     }
// }