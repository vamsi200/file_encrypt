# File Encryption

A robust command-line utility written in Rust for secure file encryption and decryption using AES-256-GCM.

## Features

- **Master Password Management**: Secure password handling with Argon2 hashing
- **Strong Encryption**: AES-256-GCM encryption with authenticated encryption
- **User-Friendly CLI**: Simple command-line interface for all operations

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

## Security Features

- **Password Protection**: Argon2 hashing ensures secure password storage
- **Modern Encryption**: AES-256-GCM provides authenticated encryption
- **Secure Parameters**: Cryptographic salts and nonces are automatically managed

## Important Notes

- **Backup Your Password**: There is no password recovery mechanism. Lost passwords mean permanently inaccessible files.
- **Keep Backups**: Always maintain backups of important files before encryption.
- **Secure Storage**: Store your master password securely - it's critical for decryption.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

