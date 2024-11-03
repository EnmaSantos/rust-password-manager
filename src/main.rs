use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad};
use ring::rand::{SystemRandom, SecureRandom};
use std::fs::{OpenOptions, File};
use std::io::{self, Write, BufRead, BufReader};
use base64;

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
    // Create an UnboundKey with the AES-256-GCM algorithm and our encryption key.
    let key = UnboundKey::new(&AES_256_GCM, KEY)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid key"))?;

    // Generate a unique nonce for this encryption.
    let nonce = generate_nonce()?;  // Generate the nonce here

    // Create a sealing key from the unbound key.
    let sealing_key = LessSafeKey::new(key);

    // Convert the nonce to a vector and store it in encrypted_data.
    let mut encrypted_data = nonce.as_ref().to_vec();

    // Convert the password string into a byte vector.
    let mut password_bytes = password.as_bytes().to_vec();

    // Encrypt the password in-place, appending an authentication tag.
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut password_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    // Append the encrypted password bytes to encrypted_data.
    encrypted_data.extend(password_bytes);

    // Return the encrypted data, with the nonce at the beginning.
    Ok(encrypted_data)
}

fn generate_nonce() -> io::Result<Nonce> {
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to generate nonce"))?;
    Ok(Nonce::assume_unique_for_key(nonce_bytes))
}

fn retrieve_password() {
    let file = match File::open("passwords.txt") {
        Ok(file) => file,
        Err(_) => {
            println!("No saved passwords found.");
            return;
        }
    };

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
    // Ensure that encrypted_data is at least 12 bytes for the nonce
    if encrypted_data.len() < 12 {
        return Err(io::Error::new(io::ErrorKind::Other, "Invalid encrypted data: too short"));
    }

    let key = UnboundKey::new(&AES_256_GCM, KEY).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid key"))?;
    let opening_key = LessSafeKey::new(key);

    // Extract the nonce from the first 12 bytes of encrypted_data
    let nonce = Nonce::try_assume_unique_for_key(&encrypted_data[..12])
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid nonce"))?;

    // The rest of encrypted_data after the nonce is the actual encrypted password
    let mut encrypted_password = encrypted_data[12..].to_vec();

    // Perform decryption
    opening_key.open_in_place(nonce, Aad::empty(), &mut encrypted_password)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Decryption failed"))?;

    // Convert decrypted bytes to UTF-8 string
    String::from_utf8(encrypted_password).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid UTF-8"))
}
