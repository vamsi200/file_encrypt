# File Encryption

A robust command-line utility written in Rust for secure file encryption and decryption using AES-256-GCM. This tool combines industrial-strength security with user-friendly operation, featuring Argon2 for password hashing and PBKDF2 for key derivation.

## Features

- **Master Password Management**: Secure password handling with Argon2 hashing
- **Strong Encryption**: AES-256-GCM encryption with authenticated encryption
- **Path Validation**: Comprehensive file and directory path verification
- **Automatic Metadata**: Integrated handling of cryptographic parameters
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

3. The compiled binary will be available in `target/release/`.

## Usage

### Encrypting Files

```bash
./file_encrypt --encrypt /path/to/your/file
```
The encrypted file will be created with a `.enc` extension.

### Decrypting Files

```bash
./file_encrypt --decrypt /path/to/your/file.enc
```
The file will be restored to its original form.

### Command Reference

```
Usage:
  -f <file>           : Specify a file
  -d <dir>            : Specify a directory (default is current)
  --encrypt           : Encrypt the file or directory
  --decrypt           : Decrypt the file or directory
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
```

## Security Features

- **Password Protection**: Argon2 hashing ensures secure password storage
- **Modern Encryption**: AES-256-GCM provides authenticated encryption
- **Secure Parameters**: Cryptographic salts and nonces are automatically managed
- **Data Integrity**: Built-in authentication prevents tampering

## Important Notes

- **Backup Your Password**: There is no password recovery mechanism. Lost passwords mean permanently inaccessible files.
- **Keep Backups**: Always maintain backups of important files before encryption.
- **Secure Storage**: Store your master password securely - it's critical for decryption.

## Security Considerations

This tool implements several security best practices:
- Secure password hashing with Argon2
- Strong encryption using AES-256-GCM
- Proper handling of cryptographic parameters
- Secure memory handling for sensitive data

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

