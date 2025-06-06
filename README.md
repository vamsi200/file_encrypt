# File Encryption

A robust command-line utility written in Rust for secure file encryption and decryption using AES-256-GCM.

## Security Features

- **Password Protection**: Argon2id hashing ensures secure password storage with resistance to brute-force and GPU attacks.
- **Modern Encryption**: AES-256-GCM provides authenticated encryption to prevent tampering and ensure data integrity.
- **Hardened Key Derivation**: Keys are derived using Argon2id with the following parameters:
  - Memory cost: `512 KB`
  - Iterations: `10`
  - Parallelism: `4 threads`
  - Output length: `32 bytes` (256-bit key)
- **Salted Password Hashing**: Master passwords are hashed with Argon2id using:
  - Algorithm: `Argon2id`
  - Random per-user salt
  - Default Argon2id parameters

## Important Notes

- **Master Password is Critical**
  - The tool stores a Master Password file in your `$HOME` directory.
  - There is **no password recovery mechanism**.
  - If the Master Password file is deleted, the tool will prompt you to create a new one.
  - However, files encrypted with the original password can **still be decrypted** if you remember that password.

- **Always Keep Backups**
  - Before encrypting important files, ensure you maintain backups.
  - This prevents accidental data loss due to forgotten passwords or corruption.


## Getting Started

### Prerequisites

- Rust (latest stable version)
- Terminal or command prompt
- Git (for cloning the repository)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vamsi200/file_encrypt.git
   cd file_encrypt
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. The binary will be available in `target/release/`.

## Usage

### Command Reference

```
Usage:
  -f <file>           : Specify one or more files
  -d <dir>            : Specify a directory (default is current)
  --encrypt           : Encrypt the file or directory
  --decrypt           : Decrypt the file or directory
  --depth <n>         : Encrypt/Decrypt the directory with depth 'n'
  -h or --help        : Display help information
```

### Examples

```bash
# Encrypt single or multiple files
./file_encrypt -f file.txt file2.txt --encrypt

# Decrypt multiple files
./file_encrypt -f file.txt file2.txt --decrypt

# Encrypt a directory
./file_encrypt -d /path/to/dir --encrypt

# Decrypt a directory
./file_encrypt -d /path/to/dir --decrypt

# encrypt a directory with depth 1
./file_encrypt -d /path/to/dir --depth 1 --encrypt

# decrypt a directory with depth 1
./file_encrypt -d /path/to/dir --depth 1 --decrypt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

