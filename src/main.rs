use std::io::Read;

use std::io::Write;

use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex_literal::hex;
use hex as hex_;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn get_keys() -> ([u8;16], [u8;16]){
    let nid = openssl::nid::Nid::X9_62_PRIME256V1;
    let group = openssl::ec::EcGroup::from_curve_name(nid).expect("Failed to create EC group from the curve name");
    let key = openssl::ec::EcKey::generate(&group).expect("Failed to generate group");
    let mut ctx = openssl::bn::BigNumContext::new().expect("Failed making context");
    let private_key = key.private_key().to_vec();
    let iv = key.private_key().to_vec();
    
    let slice = &private_key[..16];
    let key16: [u8; 16] = slice.try_into().expect("Slice must be 16 bytes");

    let slice_iv = &iv[..16];
    let key16_iv: [u8; 16] = slice_iv.try_into().expect("Slice must be 16 byte");

    (key16, key16_iv)
}

fn main() {
    get_keys();
    let args: Vec<String> = std::env::args().collect();
    let file_path = &args[1];
    // to a byte arr of len 5
    let key = get_keys().0;
    println!("Key: {:?}", key);
    println!("Key encoded: {:?}", hex_::encode(key).len());

    let iv = get_keys().1;
    println!("iv: {:?}", iv);
    println!("iv_encode: {:?}", hex_::encode(iv));
    // let plaintext = std::fs::read_to_string().unwrap();
    let plaintext = match std::fs::File::open(file_path) {
        Ok(mut file) => {
                        let mut contents = Vec::new();
                        if let Err(e) = file.read_to_end(&mut contents) {
                            println!("Error reading file: {}", e);
                            // contents
                        }
                        println!("Read {} byte from file", contents.len());
                        println!("First 16 bytes: {:?}", &contents[..16.min(contents.len())]);
                        contents
            },
    Err(e) => {
        println!("Error opening file: {}", e);
        Vec::new()
    },
    };
    
    println!("the main test before encryption");
    println!("plain text length: {}", plaintext.len());
    

    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

    let ciphertext = cipher.encrypt_vec(&plaintext);
    println!("Encrypted cipher length: {}", ciphertext.len());
    println!("First 16 bytes of ciphertext: {:?}", &ciphertext[..16.min(ciphertext.len())]);

    
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypt_ciphertext = cipher.decrypt_vec(&ciphertext).unwrap();
    
    println!(
        "Decrypted first 16 bytes: {:?}",
        &decrypt_ciphertext[..16.min(decrypt_ciphertext.len())]
    );

    // get the filename
    if let Some(file_name) = std::path::Path::new(file_path).file_name() {
        println!("the file name{:?}", file_name);
        match std::fs::File::create(&file_name) {
                Ok(mut file) => {
                    let _ = file.write_all(&decrypt_ciphertext);
                },
                Err(e) => eprintln!("Error creating file {}: {}", file_name.to_string_lossy(), e)
        }
    };


}


