File Encryption

A Rust-based command-line utility for securely encrypting and decrypting files using AES-256-GCM encryption. This tool is designed for robust security, leveraging Argon2 for password hashing and PBKDF2 for key derivation.

Features

Master Password Management: Securely hash and validate the master password using Argon2.

AES-256-GCM Encryption: Provides strong encryption for files with embedded metadata for decryption.

File and Directory Validation: Ensures proper paths and file existence before performing operations.

Metadata Storage: Automatically handles salts and nonces within encrypted files.


Requirements

Rust (latest stable version) installed on your system. You can install Rust via rustup.

A terminal or command prompt to execute the tool.

Installation

Clone the Repository:

git clone https://github.com/vamsi200/file_encrypt.git

cd file_encrypt

Build the Project:

cargo build --release

The compiled binary will be located in the target/release directory.

Run the Tool:

./target/release/file_encrypt

Usage 
Encrypt a File

To encrypt a file:

./file_encrypt --encrypt /path/to/your/file

The encrypted file will have a .enc extension.

Decrypt a File

To decrypt a file:

./file_encrypt --decrypt /path/to/your/file.enc

The decrypted file will be restored to its original form.

View Help Menu

For a full list of available commands:

./file_encrypt --help

Usage:
  -f <file>           : Specify a file
  -d <dir>            : Specify a directory (default is the current directory)
  --encrypt           : Encrypt the file or directory
  --decrypt           : Decrypt the file or directory
  -h or --help        : To print help

Examples:
  ./need_to_change  -f file.txt file2.txt --encrypt      # Encrypt a file
  ./need_to_change  -f file.txt file2.txt --decrypt      # decrypt multiple files
  ./neeed_to_change -d /path/to/dir       --encrypt      # encrypt a directory
  ./neeed_to_change -d /path/to/dir       --decrypt      # Decrypt a directory



Security Considerations

Password Security: The master password is securely hashed using Argon2.

Encryption Strength: AES-256-GCM is used to ensure data confidentiality and integrity.

Metadata Management: Salt and nonce are embedded within encrypted files for proper decryption.

Warning

Make sure to securely back up your master password. If it is lost, encrypted files cannot be decrypted.


License

This project is licensed under the MIT License. See the LICENSE file for more details.


