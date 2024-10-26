//#![allow(unused_imports)]
#![allow(dead_code)]
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use pico_args::Arguments;
use rand::RngCore;
use ring::pbkdf2;
use std::error::Error;
use std::fs::{self, File};
use std::io::Read;
use std::io::{self, Write};
use std::io::{BufRead, BufReader};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::{env, process};
use sysinfo::System;
const SALT_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_SIZE: usize = 12;
const RESTRICTED_DIRECTORIES: [&str; 9] = [
    "/root", "/etc", "/bin", "/boot", "/dev", "/proc", "/sys", "/var", "/usr",
];

struct FileValidator {
    target_file: String,
    target_directory: String,
}

impl FileValidator {
    fn validate_dir_exists(&self) -> Result<bool, std::io::Error> {
        fs::metadata(&self.target_directory)?
            .is_dir()
            .then_some(true)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "[Error] Not a directory")
            })
    }

    fn validate_file_exists(&self) -> Result<bool, std::io::Error> {
        let complete_path = format!("{}/{}", self.target_directory, self.target_file);
        fs::metadata(complete_path)?
            .is_file()
            .then_some(true)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "[Error] File Not Found")
            })
    }
}

struct ApplicationDirectoryManager;

impl ApplicationDirectoryManager {
    fn validate_app_directory() -> bool {
        let (app_path, _) = Self::get_application_directory();
        app_path.exists()
    }

    fn validate_master_password_file() -> Result<bool, io::Error> {
        let (_, password_path) = Self::get_application_directory();
        match File::open(password_path.clone()) {
            Ok(_) => Ok(password_path.exists()),
            Err(_) => Ok(false),
        }
    }

    fn get_application_directory() -> (PathBuf, PathBuf) {
        let home_directory =
            PathBuf::from(env::var("HOME").expect("[Error] Failed to get Home dir"));

        let mut encrypt_app_path = home_directory.clone();
        encrypt_app_path.push("encrypt_app");

        let mut master_password_path = encrypt_app_path.clone();
        master_password_path.push("master_password");

        (encrypt_app_path, master_password_path)
    }
}

fn calculate_available_threads() -> usize {
    let mut system_info = System::new_all();
    system_info.refresh_all();
    let total_threads = system_info.cpus().len();
    total_threads / 2
}

fn validate_master_password(password_input: &str) -> Result<bool, io::Error> {
    match ApplicationDirectoryManager::validate_master_password_file() {
        Ok(_) => {
            let (_, password_file_path) = ApplicationDirectoryManager::get_application_directory();

            let file = File::open(password_file_path)?;
            let file_reader = BufReader::new(file);

            let mut stored_hash = String::new();
            for line in file_reader.lines() {
                let line = line?;
                stored_hash = line.trim().to_string();
            }

            let parsed_hash = PasswordHash::new(&stored_hash).map_err(|e| {
                eprintln!("[Error] Invalid hash: {}", e);
                io::Error::new(io::ErrorKind::InvalidData, "[Error] Invalid password hash")
            })?;

            match Argon2::default().verify_password(password_input.as_bytes(), &parsed_hash) {
                Ok(_) => Ok(true), // Password is correct
                Err(e) => {
                    eprintln!("[Error] Incorrect password: {}", e);
                    Ok(false) // Password is incorrect
                }
            }
        }
        Err(e) => {
            eprintln!("[Error] Can't validate master password file: {e}");
            Err(e)
        }
    }
}

fn generate_password_hash() -> Result<String, std::io::Error> {
    print!("> Enter the Master Password: ");
    io::stdout().flush()?;
    //io::stdin().read_line(&mut master_password_input)?;
    let master_password_input = rpassword::read_password().expect("Error reading password");

    let master_password_input = master_password_input.trim();

    let mut secure_rng = OsRng;
    let password_salt = SaltString::generate(&mut secure_rng);
    let password_hasher = Argon2::default();

    match password_hasher.hash_password(master_password_input.as_bytes(), &password_salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => {
            eprintln!("[Error] Couldn't hash the password: {}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Password hashing failed",
            ))
        }
    }
}

fn initialize_application_directory(hashed_master_password: &[u8]) -> io::Result<()> {
    let (_, master_password_path) = ApplicationDirectoryManager::get_application_directory();
    let (app_directory_path, _) = ApplicationDirectoryManager::get_application_directory();

    if ApplicationDirectoryManager::validate_app_directory() {
        println!("Directory already exists at: {:?}", app_directory_path);
    } else {
        match fs::create_dir(&app_directory_path) {
            Ok(_) => println!("[*] Successfully created dir:{:?}", app_directory_path),

            Err(e) => println!(
                "[Error] Failed to create dir:{:?}, {}",
                app_directory_path, e
            ),
        }
    }

    if ApplicationDirectoryManager::validate_master_password_file()? {
        println!("[*] File already exists at: {:?}", master_password_path);
    } else {
        match File::create(&master_password_path) {
            Ok(mut password_file) => {
                println!(
                    "[*] Successfully created file with MasterPassword:{:?}",
                    master_password_path
                );
                password_file.write_all(hashed_master_password)?;
            }

            Err(e) => println!(
                "[Error] Failed to create file:{:?}, {}",
                master_password_path, e
            ),
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

fn decrypt_encrypted_file(
    target_file: &str,
    output_path: &str,
    master_password: &str,
) -> Result<(), std::io::Error> {
    let file_validator = FileValidator {
        target_file: target_file.to_string(),
        target_directory: output_path.to_string(),
    };

    match file_validator.validate_dir_exists() {
        Ok(true) => match file_validator.validate_file_exists() {
            Ok(true) => {
                println!("[*] Starting decryption for file: {}", target_file);

                let input_file_path = format!("{}/{}", output_path, target_file);
                let mut input_file = File::open(&input_file_path)?;

                let mut password_salt = [0u8; 16];
                input_file.read_exact(&mut password_salt)?;
                let mut encryption_nonce = [0u8; NONCE_SIZE];
                input_file.read_exact(&mut encryption_nonce)?;

                let mut encrypted_content = Vec::new();
                input_file.read_to_end(&mut encrypted_content)?;

                let encryption_key = generate_encryption_key(master_password, &password_salt);
                let cipher = Aes256Gcm::new_from_slice(&encryption_key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

                let decrypted_content = cipher
                    .decrypt(&encryption_nonce.into(), encrypted_content.as_ref())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

                // Create output path consistently with the encrypt function
                let decrypted_filename = target_file.trim_end_matches(".enc");
                let output_file_path;
                let mut output_file;
                if output_path.ends_with("/") {
                    output_file_path = format!("{}{}", output_path, decrypted_filename);
                    output_file = File::create(&output_file_path)?;
                } else {
                    output_file_path = format!("{}/{}", output_path, decrypted_filename);
                    output_file = File::create(&output_file_path)?;
                }
                output_file.write_all(&decrypted_content)?;

                println!("[*] Decrypted file created at: {}", output_file_path);
            }
            Ok(false) => {
                eprintln!("[Error] File does not exist");
            }
            Err(e) => {
                eprintln!("[ERROR]:file {}", e);
                return Err(e);
            }
        },
        Ok(false) => {
            eprintln!("[Error] Directory does not exist.");
        }
        Err(e) => {
            eprintln!("[ERROR]: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

fn encrypt_target_file(
    target_file: &str,
    output_path: &str,
    master_password: &str,
) -> Result<(), std::io::Error> {
    let file_validator = FileValidator {
        target_file: target_file.to_string(),
        target_directory: output_path.to_string(),
    };

    match file_validator.validate_dir_exists() {
        Ok(true) => match file_validator.validate_file_exists() {
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

                let encrypted_content = cipher
                    .encrypt(&encryption_nonce, file_content.as_ref())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

                let encrypted_file_path = format!("{}/{}.enc", output_path, target_file);
                let mut encrypted_file = File::create(&encrypted_file_path)?;

                encrypted_file.write_all(&password_salt)?;
                encrypted_file.write_all(&encryption_nonce)?;
                encrypted_file.write_all(&encrypted_content)?;

                println!("[*] Encrypted file created at: {}", encrypted_file_path);
            }
            Ok(false) => {
                eprintln!("[Error] File does not exist");
            }

            Err(e) => {
                eprintln!("[ERROR]:file {}", e);
                return Err(e);
            }
        },
        Ok(false) => {
            eprintln!("[Error] Directory does not exist.");
        }
        Err(e) => {
            eprintln!("[ERROR]: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

fn validate_directory_access(directory_path: &Path) -> bool {
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

    let is_restricted = RESTRICTED_DIRECTORIES.iter().any(|restricted_path| {
        if path_string == *restricted_path {
            return true;
        }

        if path_string.starts_with(restricted_path) {
            if let Some(path_remainder) = path_string.strip_prefix(restricted_path) {
                if path_remainder.starts_with('/') {
                    return true;
                }
            }
        }

        false
    });

    is_restricted
}

fn display_usage_instructions() {
    println!("Usage:");
    println!("  -f <file>           : Specify a file");
    println!("  -d <dir>            : Specify a directory (default is the current directory)");
    println!("  --encrypt           : Encrypt the file or directory");
    println!("  --decrypt           : Decrypt the file or directory");
    println!("-h or --help          : To print help");
    println!();
    println!("Examples:");
    println!("  ./need_to_change -f file.txt file2.txt --encrypt      # Encrypt a file");
    println!("  ./need_to_change -f file.txt file2.txt --decrypt      # decrypt multiple files");
    println!("  ./neeed_to_change -d /path/to/dir --encrypt # encrypt a directory");
    println!("  ./neeed_to_change -d /path/to/dir --decrypt  # Decrypt a directory");
}

fn validate_and_exec<T>(
    input_files: &[String],
    directory_path: &Path,
    opp: T,
) -> Result<(), Box<dyn Error>>
where
    T: Fn(&str, &str, &str) -> Result<(), std::io::Error>,
{
    print!("> Enter your master password: ");
    io::stdout().flush()?;
    let master_password = rpassword::read_password().expect("Error reading password");

    if ApplicationDirectoryManager::validate_app_directory() {
        if ApplicationDirectoryManager::validate_master_password_file()? {
            match validate_master_password(&master_password) {
                Ok(is_valid) => {
                    if is_valid {
                        for file_path in input_files {
                            let result = opp(
                                file_path,
                                directory_path.to_str().unwrap(),
                                &master_password,
                            );
                            if let Err(e) = result {
                                eprintln!("[Error] Failed to process file '{}': {}", file_path, e);
                            }
                        }
                    } else {
                        eprintln!("[Error] Incorrect password. Operation aborted.");
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

    Ok(())
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

    if let Some(ref dir) = target_directory {
        println!("[INFO] Target Directory: {:?}", dir);
        let t_dir = fs::read_dir(dir)?
            .map(|res| res.map(|err| err.path()))
            .collect::<Result<Vec<_>, io::Error>>()?;

        for file in t_dir.iter() {
            let file_name = file.file_name();
            input_files.push(file_name.unwrap().to_string_lossy().into_owned());
        }
    }

    if cli_args.len() == 1 {
        eprintln!("[Error] No arguments provided.");
        display_usage_instructions();
        return Ok(());
    }

    let working_directory = env::current_dir()?;
    let resolved_directory =
        target_directory.unwrap_or_else(|| working_directory.display().to_string());
    let normalized_path = resolved_directory.trim();
    let directory_path = PathBuf::from(normalized_path);

    if !perform_decryption && !perform_encryption && display_help {
        display_usage_instructions();
        return Ok(());
    }

    match ApplicationDirectoryManager::validate_master_password_file() {
        Ok(true) => {
            println!("[INFO] Password File exists.. Continuing..");
        }
        Ok(false) => {
            println!("[INFO] Password File doesn't exist, Please set a Master Password to start");

            match generate_password_hash() {
                Ok(hash) => {
                    let hashed_password_bytes = hash.as_bytes();
                    if let Err(e) = initialize_application_directory(hashed_password_bytes) {
                        eprintln!("[ERROR] Couldn't Save Master Password: {}", e);
                    } else {
                        println!("[INFO] Successfully created & saved Master Password");
                    }
                }
                Err(e) => eprintln!("[ERROR] Couldn't hash password: {}", e),
            }
        }
        Err(e) => eprintln!("[ERROR] Couldn't verify password file: {}", e),
    }

    if validate_directory_access(&directory_path) {
        eprintln!(
            "[ERROR] Below dir's cannot be encrypted/decrypted: \n{:?}",
            RESTRICTED_DIRECTORIES
        );
        return Ok(());
    }

    if is_file_input && input_files.is_empty() {
        eprintln!("[Error] No files provided for encryption/decryption.");
        return Ok(());
    }

    if perform_encryption {
        let files_to_encrypt: Vec<String> = input_files
            .iter()
            .filter(|file| !file.ends_with(".enc"))
            .cloned()
            .collect();

        if files_to_encrypt.is_empty() {
            println!("[ERROR] No files found for encryption");
            process::exit(0);
        } else {
            println!("[INFO] Encrypting files: {:?}", files_to_encrypt);
            print!("> Do you want to continue with the operation? (y/n): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();
            if input == "y" {
                validate_and_exec(&files_to_encrypt, &directory_path, encrypt_target_file)?;
            }
        }
    } else if perform_decryption {
        let files_to_decrypt: Vec<String> = input_files
            .iter()
            .filter(|file| file.ends_with(".enc"))
            .cloned()
            .collect();

        if files_to_decrypt.is_empty() {
            println!("[ERROR] No encrypted files found");
            process::exit(0);
        } else {
            println!("[INFO] Decrypting files: {:?}", files_to_decrypt);
            let mut input = String::new();
            print!("> Do you want to continue with the operation? (y/n): ");
            io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();
            if input.to_lowercase() == "y" {
                validate_and_exec(&files_to_decrypt, &directory_path, decrypt_encrypted_file)?;
            }
        }
    }

    Ok(())
}
