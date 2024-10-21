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

struct FileCheck {
    file_name: String,
    dir_path: String,
}

impl FileCheck{
    fn check_file(&self) -> Result<bool, std::io::Error>{
        let file_path = format!("{}/{}", self.dir_path, self.file_name);
        let check_dir = fs::metadata(&self.dir_path);
            if check_dir.is_err(){
             return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "[Error] Directory not found"));
            }
       
        match std::fs::metadata(file_path) {
            Ok(_) => Ok(true),
            Err(e) => if e.kind() == std::io::ErrorKind::NotFound{
                eprintln!("[Error]: {e}");
                Ok(false)
            }else{
                Ok(true)
            }
        }
                
    }
}


fn get_cpu_threads() -> usize{
    let mut sys = System::new_all();
    sys.refresh_all();
    let cpu_threads = sys.cpus().len();
    return cpu_threads / 2
}

// Used for verifying master password
fn verify_master_password(password: &str) -> Result<bool, std::io::Error> {
    let home_dir = env::var("HOME").expect("[Error] Failed to get Home dir");
    let mut file_path = PathBuf::from(home_dir);
    file_path.push("encrypt_app");
    file_path.push("master_password");        

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut hashed_password = String::new(); 
    for line in reader.lines() {
        let line = line?; 
        hashed_password = line.trim().to_string(); 
    }

    let parsed_hash = PasswordHash::new(&hashed_password).map_err(|e| {
        eprintln!("[Error] Invalid hash: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, "[Error] Invalid password hash")
    })?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true), 
        Err(e) => {
            eprintln!("[Error] Incorrect password provided: {}", e);
            Ok(false) 
        }
    }
}


fn hash_password() -> Result<String, std::io::Error> {
    println!("> Enter the Master Password: ");
    io::stdout().flush()?;
    let mut master_password = String::new();
    io::stdin()
        .read_line(&mut master_password)?;
    
    let master_password = master_password.trim();

    let mut os_rng = OsRng;
    let salt = SaltString::generate(&mut os_rng);
    let argon2 = Argon2::default();
    
    match argon2.hash_password(master_password.as_bytes(), &salt) {
        Ok(hash) => Ok(hash.to_string()), // returns a hashed password
        Err(e) => {
            eprintln!("[Error] Couldn't hash the password: {}", e);
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Password hashing failed"))
        }
    }
}

//takes the hashed password and saves it in a file
fn create_app_dir(hashedpassword: &[u8]) -> io::Result<()> {
    let home_dir = env::var("HOME").expect("[Error] Failed to get Home dir");
    let create_app_dir = PathBuf::from(home_dir).join("encrypt_app");
    
    if create_app_dir.exists() {
            println!("Directory already exists at: {:?}", create_app_dir);
        } else {
            match fs::create_dir(&create_app_dir){
                Ok(_) => println!("[*] Successfully created dir:{:?}", create_app_dir),
                
                Err(e) => println!("[Error] Failed to create dir:{:?}, {}", create_app_dir, e),
        }
    }
    
    let file_path = PathBuf::from(create_app_dir).join("master_password");

    if file_path.exists() {
            println!("[*] File already exists at: {:?}", file_path);
        } else {
            match File::create(&file_path){
                Ok(mut file) => { 
                    println!("[*] Successfully created file with MasterPassword:{:?}", file_path);
                    file.write_all(hashedpassword)?;
                }

                
                Err(e) => println!("[Error] Failed to create file:{:?}, {}", file_path, e),
        }
    }

Ok(())
}

fn derive_key_from_master_password(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        master_password.as_bytes(),
        &mut key,
    );
    key
}

fn decrypt_file(file_name: &str, path: &str, master_password: &str) -> Result<(), std::io::Error>{
    let mut file = File::open(file_name)?;
    
    let mut salt = [0u8; 16];
    file.read_exact(&mut salt)?;
    
    let mut nonce = [0u8; NONCE_SIZE];
    file.read_exact(&mut nonce)?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;
    
    let key = derive_key_from_master_password(master_password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    
    let decrypted_data = cipher.decrypt(&nonce.into(), encrypted_data.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
   
    let output_file_name = file_name.trim_end_matches(".enc");
    let dec_file_path = format!("{}/{}", path, output_file_name);
    let mut dec_file = File::create(dec_file_path)?;
    dec_file.write_all(&decrypted_data)?;
    
    println!("[*] Decrypted file created: {}", output_file_name);

    Ok(())
}

fn encrypt_file(file_name: &str, path: &str, master_password: &str) -> Result<(), std::io::Error> {
    let file_to_encrypt = FileCheck {
        file_name: file_name.to_string(),
        dir_path: path.to_string(),
    };

    match file_to_encrypt.check_file() {
        Ok(true) => {
            println!("[*] Starting encryption for file: {}", file_name);
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            //let key = Aes256Gcm::generate_key(&mut OsRng);
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);

            let key =  derive_key_from_master_password(master_password, &salt);
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let file_path = format!("{}/{}", path, file_name);
            let mut file = File::open(&file_path)?;
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;

            let encrypted_data = cipher.encrypt(&nonce, file_data.as_ref())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let enc_file_path = format!("{}/{}.enc", path, file_name);
            let mut enc_file = File::create(&enc_file_path)?;

            enc_file.write_all(&salt)?;
            enc_file.write_all(&nonce)?;
            enc_file.write_all(&encrypted_data)?;

            println!("[*] Encrypted file created at: {}", enc_file_path);
            //println!("[*] Nonce and ciphertext have been stored in the file.");
                        
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



fn restrict_dir(input_path: &PathBuf) -> bool {
    let restrict_dir_path = [
        "/root",
        "/etc",  // Configuration files
        "/bin",  // Essential binaries
        "/boot", // Boot files
        "/dev",  // Device files
        "/proc", // Kernel and process information
        "/sys",  // System files
        "/var",  // Variable data files (logs, databases)
        "/usr",  // User programs and utilities
    ];
    let path = input_path.to_str().unwrap_or("");
    
    if path == "/" {
        println!("Access denied: root directory!");
        return true;
    }

    let is_restricted = restrict_dir_path.iter().any(|restrict| {
        if path == *restrict {
            return true;
        }
        
        if path.starts_with(restrict) {
            let remaining = &path[restrict.len()..];
            if remaining.starts_with('/') {
                return true;
            }
        }
        
        false
    });

    if is_restricted {
        println!("Access denied: restricted directory!");
    } else {
        println!("Access granted: {}", path);
    }
    
    is_restricted
}

fn print_usage() {
    println!("Usage:");
    println!("  -f <file>           : Specify a file");
    println!("  -d <dir>            : Specify a directory (default is the current directory)");
    println!("  --encrypt           : Encrypt the file or directory");
    println!("  --decrypt           : Decrypt the file or directory");
    println!("-h or --help         : print this");
    println!();
    println!("Examples:");
    println!("  ./need_to_change -f file.txt file2.txt --encrypt      # Encrypt a file");
    println!("  ./need_to_change -f file.txt file2.txt --decrypt      # decrypt multiple files");
    println!("  ./neeed_to_change -d /path/to/dir --decrypt  # Decrypt a directory");
}


fn main() {
    let mut pargs = pico_args::Arguments::from_env();
    let dir: Option<String> = pargs.opt_value_from_str("-d").unwrap();
    let encrypt = pargs.contains("--encrypt"); 
    let decrypt = pargs.contains("--decrypt");
    let help = pargs.contains("-h") || pargs.contains("--help");
    let args: Vec<String> = env::args().collect();

    let mut files: Vec<String> = Vec::new();
    let mut is_flag = false;

    for arg in args.iter().skip(1) { 
        if arg == "-f" {
            is_flag = true; 
        } else if is_flag {
            if arg.starts_with('-') {
                break;
            }
            files.push(arg.clone());
        }
    }


    if env::args().len() == 1 {  
        eprintln!("[Error] No arguments provided.");
        print_usage();  
        return;
    }

    let current_dir = match env::current_dir() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error retrieving current directory: {}", e);
            return;
        }
    };


    if !decrypt && !encrypt && help{
        print_usage();  
        return;
    }
    if decrypt { 
        // todo take master_password input
        for file in &files{
            let _ = decrypt_file(&file, "/home/vamsi/scripts/file_encrypt/src", "master_password");
        }

    }
    if encrypt {
       //todo take master_password input 
        for file in &files{
            let _  =  encrypt_file(&file, "/home/vamsi/scripts/file_encrypt/src", "master_password");
        }
    }

        let dir = dir.unwrap_or_else(|| current_dir.display().to_string());
        let dir = dir.trim();
        let buf = PathBuf::from(dir);
        let _ = restrict_dir(&buf);
    
}
