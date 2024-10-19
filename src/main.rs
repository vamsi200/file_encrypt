#![allow(unused_imports)]
#![allow(dead_code)]
use std::fs::{self, File};
use hex;
use std::io::{self, Write};
use sysinfo::System;
use rand::Rng;
use aes_gcm::AeadCore;
use std::env;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use std::io::{BufRead, BufReader};
use std::error::Error;
use pico_args::Arguments;
use std::path::{Path, PathBuf};
const SALT_LENGTH: usize = 16;

struct FileCheck {
    file_name: String,
    dir_path: String,
}

impl FileCheck{
    fn check_file(&self) -> Result<bool, std::io::Error>{
        let full_path = format!("{}/{}", self.dir_path, self.file_name);
        let check_dir = fs::metadata(&self.dir_path);
            if check_dir.is_err(){
             return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "[Error] Directory not found"));
            }
       
        match std::fs::metadata(full_path) {
            Ok(_) => Ok(true),
            Err(e) => if e.kind() == std::io::ErrorKind::NotFound{
                eprintln!("[Error] File not found: {e}");
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

fn set_master_password() -> Result<String, Box<dyn Error>> {
    println!("> Enter the Master Password: ");
    io::stdout().flush()?;

    let mut master_password = String::new();
    io::stdin()
        .read_line(&mut master_password)?;
    
    let master_password = master_password.trim();
   
    Ok (master_password.to_string())
   
}


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
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid password hash")
    })?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true), 
        Err(e) => {
            eprintln!("[Error] Incorrect password provided: {}", e);
            Ok(false) 
        }
    }
}


fn hash_password(password: &String) -> Result<String, String>{
    let mut os_rng = OsRng;
    let salt = SaltString::generate(&mut os_rng);
    let argon2 = Argon2::default();
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => Ok(hash.to_string()),
        Err(e) => Err(format!("[Error] Couldn't hash the password:{}", e)),
    }
}


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

//fn restrict_dir(path: &str) -> bool{
//   let restrict_dir_path = vec![
//    "/",                // Root directory
//    "/etc/",           // Configuration files
//    "/bin/",           // Essential binaries
//    "/boot/",          // Boot files
//    "/dev/",           // Device files
//    "/proc/",          // Kernel and process information
//    "/sys/",           // System files
//    "/var/",           // Variable data files (logs, databases)
//    "/usr/",           // User programs and utilities
//];
//
//}

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
        todo!();
    }
    if encrypt {
        todo!();
    }

    let dir = dir.unwrap_or_else(|| current_dir.display().to_string());

   //if restrict_dir(&dir) {
   //    println!("Cant encrypt: {}", dir);
   //}
    
}
