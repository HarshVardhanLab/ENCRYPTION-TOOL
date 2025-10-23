# 🔐 Advanced AES Encryption Tool

A secure command-line tool for encrypting and managing sensitive data using AES encryption. Features a vault system for password-protected files and direct encryption capabilities.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)

## ✨ Features

- 🗄️ **Secure Vault System**
  - Password-protected file encryption
  - Organized storage in encrypted vault
  - File management (list, delete, export)

- 🔑 **Key Management**
  - Generate secure encryption keys
  - Save and load keys safely
  - Password-derived key support (PBKDF2)

- 📝 **Text & File Operations**
  - Encrypt/decrypt text directly
  - Encrypt/decrypt files
  - Clipboard support

- 🛡️ **Security Features**
  - AES encryption (Fernet)
  - Secure password handling
  - Protected key storage
  - Operation history logging

## 🚀 Quick Start

### Prerequisites

```bash
# Install required packages
pip install cryptography pyperclip
```

### Running the Tool

```bash
python main.py
```

## 📖 Usage Guide

### 1. Password-Protected Vault

Store text securely in the vault:
```bash
1. Select option [1] "Encrypt Text with Password"
2. Enter a strong password
3. Type your text (end with 'END' on a new line)
4. Optionally provide a custom filename
```

Retrieve vault contents:
```bash
1. Select option [2] "Decrypt Text with Password"
2. Choose a vault file
3. Enter the password
```

### 2. Direct Encryption

Encrypt text or files directly with a key:
```bash
# Generate a new key:
1. Select option [10]
2. Save the key securely

# Encrypt text:
1. Select option [6]
2. Choose key input method
3. Enter text to encrypt
```

### 3. File Operations

```bash
# Encrypt a file:
1. Select option [8]
2. Choose/generate a key
3. Provide input file path
4. Optionally specify output path

# Decrypt a file:
1. Select option [9]
2. Provide the correct key
3. Select encrypted file
4. Choose output location
```

## 🔒 Security Notes

- **Passwords**: Use strong, unique passwords for vault files
- **Keys**: Store encryption keys securely, never in plain text
- **Backups**: Keep secure backups of your encryption keys
- **Vault**: Files in the vault are encrypted individually
- **Memory**: Sensitive data is cleared from memory when possible

## 📁 Directory Structure

```
.
├── main.py              # Main encryption tool
├── app.py              # Clipboard support
├── encryption_history.json  # Operation logs
├── encrypted_vault/    # Encrypted files storage
└── README.md          # This documentation
```

## ⚙️ Configuration

- Vault location: `./encrypted_vault/`
- History file: `encryption_history.json`
- Default key file: `encryption.key`

## 🛟 Troubleshooting

1. **Wrong Password**: Double-check password; no recovery possible
2. **Invalid Key**: Ensure key format is correct
3. **File Access**: Check permissions on vault directory
4. **Memory Errors**: Free up system memory

## 🔍 Features in Detail

### Vault System
- `.vault` extension enforced
- Secure file permissions
- Metadata storage
- Created timestamp tracking

### Key Management
- Base64 encoded keys
- Password-derived keys (PBKDF2)
- Key validation
- Flexible key input methods

### Security
- AES-128 in CBC mode with HMAC
- Secure random number generation
- Protected file permissions
- Operation logging

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [Python Cryptography](https://cryptography.io/)
- Secure clipboard handling with [Pyperclip](https://pypi.org/project/pyperclip/)

---

Created by HarshVardhanLab - Secure your data with confidence! 🔐