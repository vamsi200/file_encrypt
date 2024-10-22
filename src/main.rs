#![allow(unused_imports)]
#![allow(dead_code)]
use std::fs::{self, File};
use hex;
use ring::pbkdf2;
use std::io::Read;
use std::io::{self, Write};
use sysinfo::System;
use rand::Rng;
use std::env;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use rand::RngCore;
use std::io::{BufRead, BufReader};
use std::error::Error;
use pico_args::Arguments;
use std::path::{Path, PathBuf};
use std::num::NonZeroU32;
use aes_gcm::{
    aead::{Aead, AeadCore, AeadInPlace, KeyInit, },
    Aes256Gcm, Nonce, 
};
const SALT_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_SIZE: usize = 12;

struct FileValidator {
    target_file: String,
    target_directory: String,
}

impl FileValidator {
    fn validate_file_exists(&self) -> Result<bool, std::io::Error> {
        let complete_path = format!("{}/{}", self.target_directory, self.target_file);
        let directory_status = fs::metadata(&self.target_directory);
            if directory_status.is_err() {
             return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "[Error] Directory not found"));
            }
       
        match std::fs::metadata(complete_path) {
            Ok(_) => Ok(true),
            Err(e) => if e.kind() == std::io::ErrorKind::NotFound {
                eprintln!("[Error]: {e}");
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}

struct ApplicationDirectoryManager;

impl ApplicationDirectoryManager {
    fn validate_app_directory() -> Result<bool, io::Error> {
        let app_directory = Self::get_application_directory();
        Ok(app_directory.exists())
    }

    fn validate_master_password_file() -> Result<bool, io::Error> {
        let app_directory = Self::get_application_directory();
        let master_password_path = app_directory.join("master_password");

        Ok(master_password_path.exists())
    }

    fn get_application_directory() -> PathBuf {
        let home_directory = env::var("HOME").expect("[Error] Failed to get Home dir");
        PathBuf::from(home_directory).join("encrypt_app")
    }
}

fn calculate_available_threads() -> usize {
    let mut system_info = System::new_all();
    system_info.refresh_all();
    let total_threads = system_info.cpus().len();
    return total_threads / 2
}

fn validate_master_password(password_input: &str) -> Result<bool, std::io::Error> {
    let home_directory = env::var("HOME").expect("[Error] Failed to get Home dir");
    let mut password_file_path = PathBuf::from(home_directory);
    password_file_path.push("encrypt_app");
    password_file_path.push("master_password");        

    let password_file = File::open(password_file_path)?;
    let file_reader = BufReader::new(password_file);

    let mut stored_hash = String::new(); 
    for line in file_reader.lines() {
        let line = line?; 
        stored_hash = line.trim().to_string(); 
    }

    let parsed_hash = PasswordHash::new(&stored_hash).map_err(|e| {
        eprintln!("[Error] Invalid hash: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, "[Error] Invalid password hash")
    })?;

    match Argon2::default().verify_password(password_input.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true), 
        Err(e) => {
            eprintln!("[Error] Incorrect password provided: {}", e);
            Ok(false) 
        }
    }
}

fn generate_password_hash() -> Result<String, std::io::Error> {
    println!("> Enter the Master Password: ");
    io::stdout().flush()?;
    let mut master_password_input = String::new();
    io::stdin()
        .read_line(&mut master_password_input)?;
    
    let master_password_input = master_password_input.trim();

    let mut secure_rng = OsRng;
    let password_salt = SaltString::generate(&mut secure_rng);
    let password_hasher = Argon2::default();
    
    match password_hasher.hash_password(master_password_input.as_bytes(), &password_salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => {
            eprintln!("[Error] Couldn't hash the password: {}", e);
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Password hashing failed"))
        }
    }
}

fn initialize_application_directory(hashed_master_password: &[u8]) -> io::Result<()> {
    let home_directory = env::var("HOME").expect("[Error] Failed to get Home dir");
    let app_directory_path = PathBuf::from(home_directory).join("encrypt_app");
    
    if ApplicationDirectoryManager::validate_app_directory()? {
        println!("Directory already exists at: {:?}", app_directory_path);
 
    } else {
                match fs::create_dir(&app_directory_path) {
                Ok(_) => println!("[*] Successfully created dir:{:?}", app_directory_path),
                
                Err(e) => println!("[Error] Failed to create dir:{:?}, {}", app_directory_path, e),
        }
    }
    
    let master_password_path = PathBuf::from(app_directory_path).join("master_password");
    
    if ApplicationDirectoryManager::validate_master_password_file()? {
        println!("[*] File already exists at: {:?}", master_password_path);
    }
     else {
            match File::create(&master_password_path) {
                Ok(mut password_file) => { 
                    println!("[*] Successfully created file with MasterPassword:{:?}", master_password_path);
                    password_file.write_all(hashed_master_password)?;
                }

                Err(e) => println!("[Error] Failed to create file:{:?}, {}", master_password_path, e),
        }
    }

Ok(())
}

fn generate_encryption_key(master_password: &str, password_salt: &[u8]) -> [u8; 32] {
    let mut encryption_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        password_salt,
        master_password.as_bytes(),
        &mut encryption_key,
    );
    encryption_key
}

fn decrypt_encrypted_file(encrypted_file: &str, output_path: &str, master_password: &str) -> Result<(), std::io::Error> {
    let mut input_file = File::open(encrypted_file)?;
    
    let mut password_salt = [0u8; 16];
    input_file.read_exact(&mut password_salt)?;
    
    let mut encryption_nonce = [0u8; NONCE_SIZE];
    input_file.read_exact(&mut encryption_nonce)?;
    
    let mut encrypted_content = Vec::new();
    input_file.read_to_end(&mut encrypted_content)?;
    
    let encryption_key = generate_encryption_key(master_password, &password_salt);
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    
    let decrypted_content = cipher.decrypt(&encryption_nonce.into(), encrypted_content.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
   
    let decrypted_filename = encrypted_file.trim_end_matches(".enc");
    let output_file_path = format!("{}/{}", output_path, decrypted_filename);
    let mut output_file = File::create(output_file_path)?;
    output_file.write_all(&decrypted_content)?;
    
    println!("[*] Decrypted file created: {}", decrypted_filename);

    Ok(())
}

fn encrypt_target_file(target_file: &str, output_path: &str, master_password: &str) -> Result<(), std::io::Error> {
    let file_validator = FileValidator {
        target_file: target_file.to_string(),
        target_directory: output_path.to_string(),
    };

    match file_validator.validate_file_exists() {
        Ok(true) => {
            println!("[*] Starting encryption for file: {}", target_file);
            let encryption_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let mut password_salt = [0u8; 16];
            OsRng.fill_bytes(&mut password_salt);

            let encryption_key = generate_encryption_key(master_password, &password_salt);
            let cipher = Aes256Gcm::new_from_slice(&encryption_key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let input_file_path = format!("{}/{}", output_path, target_file);
            let mut input_file = File::open(&input_file_path)?;
            let mut file_content = Vec::new();
            input_file.read_to_end(&mut file_content)?;

            let encrypted_content = cipher.encrypt(&encryption_nonce, file_content.as_ref())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let encrypted_file_path = format!("{}/{}.enc", output_path, target_file);
            let mut encrypted_file = File::create(&encrypted_file_path)?;

            encrypted_file.write_all(&password_salt)?;
            encrypted_file.write_all(&encryption_nonce)?;
            encrypted_file.write_all(&encrypted_content)?;

            println!("[*] Encrypted file created at: {}", encrypted_file_path);
                        
        }
        Ok(false) => {
            eprintln!("[Error] File does not exist.");
        }
        Err(e) => {
            eprintln!("[Error]: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

fn validate_directory_access(directory_path: &PathBuf) -> bool {
    let restricted_directories = [
        "/root",
        "/etc",
        "/bin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/usr",
    ];
    
    let path_string = match directory_path.to_str() {
        Some(path) => path,
        None => {
            eprintln!("[Error] Invalid directory path");
            return false;
        }
    }; 
    
    if path_string == "/" {
        println!("Access denied: root directory!");
        return true;
    }

    let is_restricted = restricted_directories.iter().any(|restricted_path| {
        if path_string == *restricted_path {
            return true;
        }
        
        if path_string.starts_with(restricted_path) {
            let path_remainder = &path_string[restricted_path.len()..];
            if path_remainder.starts_with('/') {
                return true;
            }
        }
        
        false
    });

    if is_restricted {
        println!("Access denied: restricted directory!");
    } else {
        println!("Access granted: {}", path_string);
    }
    
    is_restricted
}

fn display_usage_instructions() {
    println!("Usage:");
    println!("  -f <file>           : Specify a file");
    println!("  -d <dir>            : Specify a directory (default is the current directory)");
    println!("  --encrypt           : Encrypt the file or directory");
    println!("  --decrypt           : Decrypt the file or directory");
    println!("-h or --help          : print this");
    println!();
    println!("Examples:");
    println!("  ./need_to_change -f file.txt file2.txt --encrypt      # Encrypt a file");
    println!("  ./need_to_change -f file.txt file2.txt --decrypt      # decrypt multiple files");
    println!("  ./neeed_to_change -d /path/to/dir --encrypt # encrypt a directory");
    println!("  ./neeed_to_change -d /path/to/dir --decrypt  # Decrypt a directory");
}



fn main() -> Result<(), Box<dyn Error>> {
    let mut cli_parser = Arguments::from_env();
    let target_directory: Option<String> = cli_parser.opt_value_from_str("-d").unwrap_or(None);
    let perform_encryption = cli_parser.contains("--encrypt");
    let perform_decryption = cli_parser.contains("--decrypt");
    let display_help = cli_parser.contains("-h") || cli_parser.contains("--help");

    let cli_args: Vec<String> = env::args().collect();
    let mut input_files: Vec<String> = Vec::new();
    let mut is_file_input = false;

    for arg in cli_args.iter().skip(1) {
        if arg == "-f" {
            is_file_input = true;
        } else if is_file_input {
            if arg.starts_with('-') {
                break;
            }
            input_files.push(arg.clone());
        }
    }

    if cli_args.len() == 1 {
        eprintln!("[Error] No arguments provided.");
        display_usage_instructions();
        return Ok(());
    }

    let working_directory = env::current_dir()?;
    let resolved_directory = target_directory.unwrap_or_else(|| working_directory.display().to_string());
    let normalized_path = resolved_directory.trim();
    let directory_path = PathBuf::from(normalized_path);

    if validate_directory_access(&directory_path) {
        eprintln!("[Error] Directory validation failed: Access to the directory is restricted.");
        return Ok(()); // Return early if directory access is denied
    }

    if !perform_decryption && !perform_encryption && display_help {
        display_usage_instructions();
        return Ok(());
    }

    if is_file_input && input_files.is_empty() {
        eprintln!("[Error] No files provided for encryption or decryption.");
        return Ok(());
    }
    
  if perform_decryption {
        println!("> Enter your master password: ");
        io::stdout().flush()?;

        let master_password: String = rpassword::read_password().expect("Error reading password");

        if ApplicationDirectoryManager::validate_app_directory()? {
            if ApplicationDirectoryManager::validate_master_password_file()? {
                match validate_master_password(&master_password) {
                    Ok(is_valid) => {
                        if is_valid {
                            for file_path in &input_files {
                                let result = decrypt_encrypted_file(file_path, directory_path.to_str().unwrap(), &master_password);
                                if let Err(e) = result {
                                    eprintln!("[Error] Failed to decrypt file '{}': {}", file_path, e);
                                }
                            }
                        } else {
                            eprintln!("[Error] Incorrect password, decryption aborted.");
                        }
                    }
                    Err(e) => {
                        eprintln!("[Error] Password validation failed: {}", e);
                    }
                }
            } else {
                eprintln!("[Error] Master password file not found.");
            }
        } else {
            eprintln!("[Error] Application directory not found.");
        }
    }

    if perform_encryption {
        println!("> Enter your master password: ");
        io::stdout().flush()?;
        let master_password = rpassword::read_password().expect("Error reading password");

        if ApplicationDirectoryManager::validate_app_directory()? {
            if ApplicationDirectoryManager::validate_master_password_file()? {
                match validate_master_password(&master_password) {
                    Ok(true) => {
                        for file_path in &input_files {
                            match encrypt_target_file(file_path, directory_path.to_str().unwrap(), &master_password) {
                                Ok(_) => {
                                    println!("Successfully encrypted '{}'", file_path);
                                }
                                Err(e) => {
                                    eprintln!("[Error] Failed to encrypt '{}': {}", file_path, e);
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        eprintln!("[Error] Incorrect master password. Encryption aborted.");
                    }
                    Err(e) => {
                        eprintln!("[Error] Failed to validate master password: {}", e);
                    }
                }
            } else {
                eprintln!("[Error] Master password file not found. Encryption aborted.");
            }
        } else {
            eprintln!("[Error] Application directory is invalid or missing. Encryption aborted.");
        }
    }

    Ok(())
}
