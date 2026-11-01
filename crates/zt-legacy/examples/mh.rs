fn main() {
    let mut hex = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut hex).unwrap();
    let bytes = hex::decode(hex.trim()).unwrap();
    let digest = zt_legacy::hashcash::memory_hard_hash(&bytes);
    println!("digest: {}", hex::encode(digest));
    println!("address: {}", hex::encode(&digest[59..64]));
}
