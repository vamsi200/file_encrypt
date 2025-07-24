use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use indicatif::{ProgressBar, ProgressStyle};
use pico_args::Arguments;
use rand::RngCore;
use std::fs::{self, File};
use std::io::BufWriter;
use std::io::Read;
use std::io::{self, Write};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::{env, process};
use std::{error::Error, time};
use walkdir::WalkDir;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 4096;
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
                    eprintln!("[Error] {}", e);
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
        println!(
            "[INFO] Directory already exists at: {:?}",
            app_directory_path
        );
    } else {
        match fs::create_dir(&app_directory_path) {
            Ok(_) => println!("[INFO] Successfully created dir:{:?}", app_directory_path),

            Err(e) => println!(
                "[Error] Failed to create dir:{:?}, {}",
                app_directory_path, e
            ),
        }
    }

    if ApplicationDirectoryManager::validate_master_password_file()? {
        println!("[INFO] File already exists at: {:?}", master_password_path);
    } else {
        match File::create(&master_password_path) {
            Ok(mut password_file) => {
                println!(
                    "[INFO] Successfully created file with MasterPassword:{:?}",
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
    let mut key = [0u8; 32];
    let params = Params::new(512 * 1024, 10, 4, Some(32)).unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(master_password.as_bytes(), password_salt, &mut key)
        .unwrap();

    key
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

    if !file_validator.validate_dir_exists()? {
        eprintln!("[Error] Directory does not exist.");
        return Ok(());
    }

    if !file_validator.validate_file_exists()? {
        eprintln!("[Error] File does not exist");
        return Ok(());
    }

    let input_file_path = format!("{}/{}", output_path, target_file);
    let input_file = BufReader::new(File::open(&input_file_path)?);

    let mut reader = input_file;

    let mut password_salt = [0u8; SALT_SIZE];
    reader.read_exact(&mut password_salt)?;

    let encryption_key = generate_encryption_key(master_password, &password_salt);
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let decrypted_filename = target_file.trim_end_matches(".enc");
    let output_file_path = if output_path.ends_with("/") {
        format!("{}{}", output_path, decrypted_filename)
    } else {
        format!("{}/{}", output_path, decrypted_filename)
    };
    let mut output_file = BufWriter::new(File::create(&output_file_path)?);

    loop {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        match reader.read_exact(&mut nonce_bytes) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let chunk_len = u32::from_be_bytes(len_buf) as usize;

        let mut encrypted_chunk = vec![0u8; chunk_len];
        reader.read_exact(&mut encrypted_chunk)?;

        let decrypted_chunk = cipher
            .decrypt(nonce, encrypted_chunk.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        output_file.write_all(&decrypted_chunk)?;
    }

    output_file.flush()?;
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

    if !file_validator.validate_dir_exists()? {
        eprintln!("[Error] Directory does not exist.");
        return Ok(());
    }

    if !file_validator.validate_file_exists()? {
        eprintln!("[Error] File does not exist");
        return Ok(());
    }

    let mut password_salt = [0u8; 16];
    OsRng.fill_bytes(&mut password_salt);
    let encryption_key = generate_encryption_key(master_password, &password_salt);
    let cipher = Aes256Gcm::new_from_slice(&encryption_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let input_file_path = format!("{}/{}", output_path, target_file);
    let encrypted_file_path = format!("{}/{}.enc", output_path, target_file);

    let input_file = BufReader::new(File::open(&input_file_path)?);
    let mut encrypted_file = BufWriter::new(File::create(&encrypted_file_path)?);

    encrypted_file.write_all(&password_salt)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    let mut reader = input_file;
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        let chunk = &buffer[..bytes_read];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted_chunk = cipher
            .encrypt(nonce, chunk)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        encrypted_file.write_all(&nonce_bytes)?;
        let chunk_len = (encrypted_chunk.len() as u32).to_be_bytes();
        encrypted_file.write_all(&chunk_len)?;
        encrypted_file.write_all(&encrypted_chunk)?;
    }

    encrypted_file.flush()?;
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
    println!("  --depth <level>     : Depth of encryption/decryption");
    println!("  -h or --help        : To print help");
    println!();
    println!("Examples:");
    println!("  ./file_encrypt -f file.txt             --encrypt     # Encrypt a file");
    println!("  ./file_encrypt -f file.txt file2.txt   --decrypt     # decrypt multiple files");
    println!("  ./file_encrypt -d /path/to/dir         --encrypt     # encrypt a directory");
    println!("  ./file_encrypt -d /path/to/dir         --decrypt     # Decrypt a directory");
    println!(
        "  ./file_encrypt -d /path/to/dir --depth 1 --encrypt   # encrypt a directory with depth 1"
    );
    println!(
        "  ./file_encrypt -d /path/to/dir --depth 1 --decrypt   # decrypt a directory with depth 1"
    );
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

    if !ApplicationDirectoryManager::validate_app_directory() {
        eprintln!("[Error] Application directory not found.");
        return Ok(());
    }

    if !ApplicationDirectoryManager::validate_master_password_file()? {
        eprintln!("[Error] Master password file not found.");
        return Ok(());
    }

    if validate_master_password(&master_password)? {
        for (index, file_path) in input_files.iter().enumerate() {
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::with_template("{spinner} [{elapsed_precise}] {msg}").unwrap(),
            );
            spinner.set_message(format!("Processing - '{}'", file_path.clone()));
            spinner.enable_steady_tick(time::Duration::from_millis(100));

            let result = opp(
                file_path,
                directory_path.to_str().unwrap(),
                &master_password,
            );

            spinner.finish_and_clear();

            match result {
                Ok(_) => {
                    println!(
                        "[{}/{}] Successfully processed - '{}'",
                        index + 1,
                        input_files.len(),
                        file_path
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[{}/{}] Failed to process - '{}': {}",
                        index + 1,
                        input_files.len(),
                        file_path,
                        e
                    );
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut cli_parser = Arguments::from_env();
    let target_directory: Option<String> = cli_parser.opt_value_from_str("-d").unwrap_or(None);
    let perform_encryption = cli_parser.contains("--encrypt");
    let perform_decryption = cli_parser.contains("--decrypt");
    let display_help = cli_parser.contains("--help");
    let depth_limit: Option<usize> = cli_parser.opt_value_from_str("--depth").unwrap_or(None);

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

            let path = Path::new(arg);
            let metadata = fs::symlink_metadata(path)?;
            if path.is_dir() {
                println!("[INFO] Skipping directory - {}", arg);
                continue;
            }
            if metadata.is_dir() {
                println!("[INFO] Skipping directory - {}", arg);
                continue;
            }

            input_files.push(arg.clone());
        }
    }

    if cli_args.len() == 1 {
        eprintln!("[Error] No arguments provided.");
        display_usage_instructions();
        return Ok(());
    }

    if !perform_decryption && !perform_encryption {
        display_usage_instructions();
        return Ok(());
    }

    if display_help {
        display_usage_instructions();
        return Ok(());
    }

    if is_file_input && input_files.is_empty() {
        eprintln!("[Error] No files provided for encryption/decryption.");
        return Ok(());
    }

    if let Some(ref dir) = target_directory {
        println!("[INFO] Target Directory: {}", dir);

        for entry in WalkDir::new(dir)
            .max_depth(depth_limit.unwrap_or(usize::MAX))
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let relative_path = path.strip_prefix(dir).unwrap();
            input_files.push(relative_path.display().to_string());
        }
    }

    let working_directory = env::current_dir()?;
    let resolved_directory =
        target_directory.unwrap_or_else(|| working_directory.display().to_string());
    let normalized_path = resolved_directory.trim();
    let directory_path = PathBuf::from(normalized_path);

    match ApplicationDirectoryManager::validate_master_password_file() {
        Ok(true) => {
            println!("[INFO] Master Password File exists, Continuing..");
        }
        Ok(false) => {
            println!("[WARN] Password File doesn't exist, Please set a Master Password to start");

            match generate_password_hash() {
                Ok(hash) => {
                    let hashed_password_bytes = hash.as_bytes();
                    if let Err(e) = initialize_application_directory(hashed_password_bytes) {
                        eprintln!("[ERROR] Couldn't Save Master Password: {}", e);
                    } else {
                        println!("[SUCCESS] Successfully created & saved Master Password");
                    }
                }
                Err(e) => eprintln!("[ERROR] Couldn't hash password: {}", e),
            }
        }
        Err(e) => eprintln!("[ERROR] Couldn't verify password file: {}", e),
    }

    if validate_directory_access(&directory_path) {
        eprintln!("[ERROR] Below dir's cannot be encrypted/decrypted:",);
        for dir in RESTRICTED_DIRECTORIES {
            println!("- {}", dir);
        }
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
            println!("Encrypting files:");
            for file in &files_to_encrypt {
                println!("- {}", file);
            }
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
            println!("Decrypting files:");
            for file in &files_to_decrypt {
                println!("- {}", file);
            }
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
