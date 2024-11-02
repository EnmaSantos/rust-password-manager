use ring::aead::{self, LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad};
use ring::rand::{SystemRandom, SecureRandom};
use std::fs::OpenOptions;
use std::io::{self, Write};

const KEY: &[u8; 32] = b"super_secret_32_byte_encryption_";

fn main() {
    println!("Welcome to the Rust Password Manager!");

    loop {
        println!("Enter a command (add, retrieve, quit):");

        let mut command = String::new();
        io::stdin().read_line(&mut command).expect("Failed to read line");
        let command = command.trim();

        match command {
            "add" => add_password(),
            "retrieve" => retrieve_password(),
            "quit" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Unknown command, please try again."),
        }
    }
}

fn add_password() {
    let mut service = String::new();
    let mut username = String::new();
    let mut password = String::new();

    println!("Enter the service name:");
    io::stdin().read_line(&mut service).expect("Failed to read line");
    let service = service.trim();

    println!("Enter the username:");
    io::stdin().read_line(&mut username).expect("Failed to read line");
    let username = username.trim();

    println!("Enter the password:");
    io::stdin().read_line(&mut password).expect("Failed to read line");
    let password = password.trim();

    let encrypted_password = encrypt_password(password).expect("Encryption failed");

    // Format data and save it to the file
    let data = format!("{}:{}:{}\n", service, username, base64::encode(&encrypted_password));
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("passwords.txt")
        .expect("Failed to open file");
    
    file.write_all(data.as_bytes()).expect("Failed to write data to file");

    println!("Password saved successfully!");
}

fn encrypt_password(password: &str) -> io::Result<Vec<u8>> {
    let key = UnboundKey::new(&AES_256_GCM, KEY).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid key"))?;
    let nonce = generate_nonce()?;
    let mut sealing_key = LessSafeKey::new(key);
    let mut password_bytes = password.as_bytes().to_vec();

    sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut password_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    // Prepend the nonce to the encrypted data for easier decryption
    let mut encrypted_data = nonce.as_ref().to_vec();
    encrypted_data.extend(password_bytes);

    Ok(encrypted_data)
}

fn generate_nonce() -> io::Result<Nonce> {
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to generate nonce"))?;
    Ok(Nonce::assume_unique_for_key(nonce_bytes))
}

fn retrieve_password() {
    let file = File::open("passwords.txt").expect("Failed to open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split(':').collect();

        if parts.len() == 3 {
            let service = parts[0];
            let username = parts[1];
            let encrypted_password = base64::decode(parts[2]).expect("Failed to decode base64");
            let decrypted_password = decrypt_password(&encrypted_password).expect("Decryption failed");

            println!("Service: {}, Username: {}, Password: {}", service, username, decrypted_password);
        }
    }
}

fn decrypt_password(encrypted_data: &[u8]) -> io::Result<String> {
    let key = UnboundKey::new(&AES_256_GCM, KEY).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid key"))?;
    let mut opening_key = LessSafeKey::new(key);

    let nonce = Nonce::try_assume_unique_for_key(&encrypted_data[..12])
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid nonce"))?;
    let mut encrypted_password = encrypted_data[12..].to_vec();

    opening_key.open_in_place(nonce, Aad::empty(), &mut encrypted_password)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decryption failed"))?;

    String::from_utf8(encrypted_password).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid UTF-8"))
}
