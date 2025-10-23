try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except Exception:
    # Allow module import even if cryptography is not installed; functional calls will fail later.
    Fernet = None
    hashes = None
    PBKDF2HMAC = None
    HAS_CRYPTO = False

import os
import base64
import json
from pathlib import Path
from datetime import datetime
import getpass
import sys

class EncryptionTool:
    def __init__(self):
        self.history_file = Path("encryption_history.json")
        self.vault_dir = Path("encrypted_vault")
        self.vault_dir.mkdir(exist_ok=True)
        
    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def generate_key(self):
        """Generate a key for AES encryption"""
        return Fernet.generate_key()
    
    def encrypt_message(self, key, message):
        """Encrypt a message using the provided key"""
        try:
            f = Fernet(key)
            encrypted = f.encrypt(message.encode())
            return encrypted
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    def decrypt_message(self, key, encrypted_message):
        """Decrypt a message using the provided key"""
        try:
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_message).decode()
            return decrypted
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def save_encrypted_text_file(self, password, text, filename=None):
        """Save encrypted text to a password-protected file"""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"encrypted_text_{timestamp}.vault"
            else:
                # enforce .vault extension for vault files
                if not filename.endswith('.vault'):
                    filename = f"{filename}.vault"
            
            filepath = self.vault_dir / filename
            
            # Derive key from password
            key, salt = self.derive_key_from_password(password)
            
            # Encrypt the text
            encrypted_text = self.encrypt_message(key, text)
            
            # Create vault structure
            vault_data = {
                'salt': base64.b64encode(salt).decode(),
                'encrypted_data': encrypted_text.decode(),
                'created_at': datetime.now().isoformat(),
                'type': 'text'
            }
            
            # Save to file
            with open(filepath, 'w') as f:
                json.dump(vault_data, f, indent=2)

            # Restrict permissions to owner only where supported
            try:
                os.chmod(filepath, 0o600)
            except Exception:
                pass

            return str(filepath)
        except Exception as e:
            raise ValueError(f"Failed to save encrypted file: {str(e)}")
    
    def load_encrypted_text_file(self, password, filename):
        """Load and decrypt text from a password-protected file"""
        try:
            filepath = self.vault_dir / filename if not Path(filename).is_absolute() else Path(filename)
            
            # Load vault data
            with open(filepath, 'r') as f:
                vault_data = json.load(f)
            
            # Retrieve salt and encrypted data
            salt = base64.b64decode(vault_data['salt'])
            encrypted_data = vault_data['encrypted_data'].encode()
            
            # Derive key from password
            key, _ = self.derive_key_from_password(password, salt)
            
            # Decrypt the text
            decrypted_text = self.decrypt_message(key, encrypted_data)
            
            return decrypted_text, vault_data.get('created_at', 'Unknown')
        except json.JSONDecodeError:
            raise ValueError("Invalid vault file format!")
        except FileNotFoundError:
            raise ValueError(f"File '{filename}' not found!")
        except Exception as e:
            raise ValueError(f"Failed to decrypt file. Wrong password or corrupted file: {str(e)}")
    
    def list_vault_files(self):
        """List all encrypted files in the vault"""
        try:
            files = list(self.vault_dir.glob("*.vault"))
            return sorted([f.name for f in files])
        except Exception:
            return []
    
    def delete_vault_file(self, filename):
        """Delete an encrypted file from the vault"""
        try:
            filepath = self.vault_dir / filename
            if filepath.exists():
                filepath.unlink()
                return True
            return False
        except Exception as e:
            raise ValueError(f"Failed to delete file: {str(e)}")
    
    def export_vault_file(self, filename, destination):
        """Export a vault file to another location"""
        try:
            source = self.vault_dir / filename
            dest = Path(destination)

            # If destination is a directory, preserve the filename
            if dest.exists() and dest.is_dir():
                dest = dest / source.name

            # Ensure parent directory exists
            dest.parent.mkdir(parents=True, exist_ok=True)

            with open(source, 'rb') as src, open(dest, 'wb') as dst:
                dst.write(src.read())

            return str(dest)
        except Exception as e:
            raise ValueError(f"Failed to export file: {str(e)}")
    
    def encrypt_file(self, key, input_file, output_file=None):
        """Encrypt a file"""
        try:
            with open(input_file, 'rb') as f:
                file_data = f.read()
            
            f = Fernet(key)
            encrypted_data = f.encrypt(file_data)
            
            if not output_file:
                output_file = f"{input_file}.encrypted"
            
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            return output_file
        except Exception as e:
            raise ValueError(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, key, input_file, output_file=None):
        """Decrypt a file"""
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            
            if not output_file:
                output_file = input_file.replace('.encrypted', '.decrypted')
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            return output_file
        except Exception as e:
            raise ValueError(f"File decryption failed: {str(e)}")
    
    def save_key_to_file(self, key, filename="encryption.key"):
        """Save encryption key to a file"""
        try:
            path = Path(filename).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'wb') as key_file:
                key_file.write(key)

            # Restrict permissions to owner only where supported
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass

            return str(path)
        except Exception as e:
            raise ValueError(f"Failed to save key: {str(e)}")
    
    def load_key_from_file(self, filename="encryption.key"):
        """Load encryption key from a file"""
        try:
            path = Path(filename).expanduser()
            with open(path, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            raise ValueError(f"Key file '{filename}' not found!")
        except Exception as e:
            raise ValueError(f"Failed to load key: {str(e)}")
    
    def validate_key(self, key):
        """Validate if a key is properly formatted"""
        try:
            Fernet(key)
            return True
        except Exception:
            return False
    
    def save_to_history(self, operation, details):
        """Save operation to history file"""
        try:
            history = []
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            
            history.append({
                'timestamp': datetime.now().isoformat(),
                'operation': operation,
                'details': details
            })
            
            with open(self.history_file, 'w') as f:
                json.dump(history[-50:], f, indent=2)  # Keep last 50 entries
        except Exception:
            pass  # Silently fail if history can't be saved

def print_header():
    """Print a stylized header"""
    # Colorful header when run in a TTY
    GREEN = ansi_color('32')
    CYAN = ansi_color('36')
    RESET = ansi_color('0')

    print("\n" + "="*60)
    title = f"🔐  ADVANCED AES ENCRYPTION/DECRYPTION TOOL  🔐"
    print(f"{CYAN}{title.center(60)}{RESET}")
    print("="*60 + "\n")

def print_menu():
    """Display the main menu"""
    GREEN = ansi_color('32')
    RED = ansi_color('31')
    BLUE = ansi_color('34')
    YELLOW = ansi_color('33')
    RESET = ansi_color('0')

    print(f"\n{GREEN}📋 MAIN MENU:{RESET}")
    def m(n, text, color=BLUE):
        print(f"  {YELLOW}[{n}]{RESET} {color}{text}{RESET}")

    m('1', 'Encrypt Text with Password (Save to Vault)')
    m('2', 'Decrypt Text with Password (Load from Vault)')
    m('3', 'List All Vault Files')
    m('4', 'Delete Vault File')
    m('5', 'Export Vault File')
    m('6', 'Encrypt Text (Direct)')
    m('7', 'Decrypt Text (Direct)')
    m('8', 'Encrypt File')
    m('9', 'Decrypt File')
    m('10', 'Generate New Key')
    m('11', 'Save Key to File')
    m('12', 'Load Key from File')
    m('13', 'Validate Key')
    m('0', 'Exit', color=RED)
    print("-" * 60)


def ansi_color(code: str) -> str:
    """Return ANSI escape sequence for a color code, or empty if not a TTY."""
    if not sys.stdout.isatty():
        return ''
    return f"\033[{code}m"

def get_password(confirm=False):
    """Get password from user securely"""
    password = getpass.getpass("Enter password: ")
    if confirm:
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("❌ Passwords don't match!")
            return None
    return password

def get_key_input(tool, allow_empty=False, operation="encryption"):
    """Get key from user with multiple options"""
    print(f"\n🔑 KEY OPTIONS for {operation}:")
    print("  [1] Enter key manually")
    print("  [2] Load key from file")
    if allow_empty:
        print("  [3] Generate new key")
    
    choice = input("Choose option: ").strip()
    
    if choice == '1':
        key_str = input("Enter your key: ").strip()
        if not key_str:
            print("❌ Key cannot be empty!")
            return None
        # sanitize common copy/paste artifacts and ensure bytes
        key_str = key_str.strip().strip('"').strip("'")
        key = key_str.encode() if isinstance(key_str, str) else key_str
    elif choice == '2':
        filename = input("Enter key filename (default: encryption.key): ").strip()
        filename = filename if filename else "encryption.key"
        try:
            key = tool.load_key_from_file(filename)
            print(f"✅ Key loaded from '{filename}'")
        except Exception as e:
            print(f"❌ {str(e)}")
            return None
    elif choice == '3' and allow_empty:
        key = tool.generate_key()
        print(f"✅ Generated Key: {key.decode()}")
        save = input("Save this key to file? (y/n): ").lower()
        if save == 'y':
            filename = input("Filename (default: encryption.key): ").strip()
            filename = filename if filename else "encryption.key"
            tool.save_key_to_file(key, filename)
            print(f"✅ Key saved to '{filename}'")
    else:
        print("❌ Invalid option!")
        return None
    
    # Validate key
    if not tool.validate_key(key):
        print("❌ Invalid key format!")
        return None
    
    return key

def main():
    tool = EncryptionTool()
    print_header()
    print(f"📁 Vault Location: {tool.vault_dir.absolute()}")
    
    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        
        try:
            if choice == '1':  # Encrypt Text with Password (Vault)
                print("\n🔒 PASSWORD-PROTECTED TEXT ENCRYPTION")
                print("⚠️  Remember your password! It cannot be recovered.")
                
                password = get_password(confirm=True)
                if not password:
                    continue
                
                print("\nEnter your text (type 'END' on a new line to finish):")
                lines = []
                while True:
                    line = input()
                    if line == 'END':
                        break
                    lines.append(line)
                text = '\n'.join(lines)
                
                if not text.strip():
                    print("❌ Text cannot be empty!")
                    continue
                
                filename = input("Enter filename (leave blank for auto): ").strip()
                filename = filename if filename else None
                
                filepath = tool.save_encrypted_text_file(password, text, filename)
                print(f"\n✅ Text encrypted and saved to: {filepath}")
                tool.save_to_history('encrypt_vault', {'file': filepath})
                
            elif choice == '2':  # Decrypt Text with Password (Vault)
                print("\n🔓 PASSWORD-PROTECTED TEXT DECRYPTION")
                
                files = tool.list_vault_files()
                if not files:
                    print("❌ No vault files found!")
                    continue
                
                print("\n📄 Available vault files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                
                file_choice = input("\nEnter file number or filename: ").strip()
                
                if file_choice.isdigit() and 1 <= int(file_choice) <= len(files):
                    filename = files[int(file_choice) - 1]
                else:
                    filename = file_choice
                
                password = get_password()
                if not password:
                    continue
                
                decrypted_text, created_at = tool.load_encrypted_text_file(password, filename)
                print(f"\n✅ DECRYPTED TEXT (Created: {created_at}):")
                print("-" * 60)
                print(decrypted_text)
                print("-" * 60)
                tool.save_to_history('decrypt_vault', {'file': filename})
                
            elif choice == '3':  # List Vault Files
                print("\n📂 VAULT FILES:")
                files = tool.list_vault_files()
                if not files:
                    print("  No files found in vault.")
                else:
                    for i, f in enumerate(files, 1):
                        print(f"  [{i}] {f}")
                
            elif choice == '4':  # Delete Vault File
                print("\n🗑️  DELETE VAULT FILE")
                files = tool.list_vault_files()
                if not files:
                    print("❌ No vault files found!")
                    continue
                
                print("\n📄 Available vault files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                
                file_choice = input("\nEnter file number or filename to delete: ").strip()
                
                if file_choice.isdigit() and 1 <= int(file_choice) <= len(files):
                    filename = files[int(file_choice) - 1]
                else:
                    filename = file_choice
                
                confirm = input(f"⚠️  Delete '{filename}'? (yes/no): ").lower()
                if confirm == 'yes':
                    if tool.delete_vault_file(filename):
                        print(f"✅ File '{filename}' deleted successfully!")
                    else:
                        print(f"❌ File '{filename}' not found!")
                else:
                    print("Deletion cancelled.")
                
            elif choice == '5':  # Export Vault File
                print("\n📤 EXPORT VAULT FILE")
                files = tool.list_vault_files()
                if not files:
                    print("❌ No vault files found!")
                    continue
                
                print("\n📄 Available vault files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                
                file_choice = input("\nEnter file number or filename: ").strip()
                
                if file_choice.isdigit() and 1 <= int(file_choice) <= len(files):
                    filename = files[int(file_choice) - 1]
                else:
                    filename = file_choice
                
                destination = input("Enter destination path: ").strip()
                result = tool.export_vault_file(filename, destination)
                print(f"✅ File exported to: {result}")
                
            elif choice == '6':  # Encrypt Text (Direct)
                print("\n📝 TEXT ENCRYPTION (DIRECT)")
                key = get_key_input(tool, allow_empty=True, operation="encryption")
                if not key:
                    continue
                
                text = input("Enter text to encrypt: ")
                encrypted = tool.encrypt_message(key, text)
                print(f"\n✅ Encrypted Text:\n{encrypted.decode()}")
                tool.save_to_history('encrypt_text', {'length': len(text)})
                
            elif choice == '7':  # Decrypt Text (Direct)
                print("\n🔓 TEXT DECRYPTION (DIRECT)")
                key = get_key_input(tool, allow_empty=False, operation="decryption")
                if not key:
                    continue
                
                encrypted_text = input("Enter encrypted text: ").encode()
                decrypted = tool.decrypt_message(key, encrypted_text)
                print(f"\n✅ Decrypted Text:\n{decrypted}")
                tool.save_to_history('decrypt_text', {'length': len(decrypted)})
                
            elif choice == '8':  # Encrypt File
                print("\n📁 FILE ENCRYPTION")
                key = get_key_input(tool, allow_empty=True, operation="file encryption")
                if not key:
                    continue
                
                input_file = input("Enter input file path: ").strip()
                output_file = input("Enter output file path (leave blank for auto): ").strip()
                output_file = output_file if output_file else None
                
                result = tool.encrypt_file(key, input_file, output_file)
                print(f"✅ File encrypted successfully: {result}")
                tool.save_to_history('encrypt_file', {'file': input_file})
                
            elif choice == '9':  # Decrypt File
                print("\n📂 FILE DECRYPTION")
                key = get_key_input(tool, allow_empty=False, operation="file decryption")
                if not key:
                    continue
                
                input_file = input("Enter encrypted file path: ").strip()
                output_file = input("Enter output file path (leave blank for auto): ").strip()
                output_file = output_file if output_file else None
                
                result = tool.decrypt_file(key, input_file, output_file)
                print(f"✅ File decrypted successfully: {result}")
                tool.save_to_history('decrypt_file', {'file': input_file})
                
            elif choice == '10':  # Generate New Key
                print("\n🔑 KEY GENERATION")
                key = tool.generate_key()
                print(f"✅ Generated Key:\n{key.decode()}")
                print("\n⚠️  IMPORTANT: Save this key securely! You'll need it for decryption.")
                
                save = input("\nSave to file? (y/n): ").lower()
                if save == 'y':
                    filename = input("Filename (default: encryption.key): ").strip()
                    filename = filename if filename else "encryption.key"
                    tool.save_key_to_file(key, filename)
                    print(f"✅ Key saved to '{filename}'")
                
            elif choice == '11':  # Save Key to File
                print("\n💾 SAVE KEY TO FILE")
                key_str = input("Enter your key: ").strip()
                key = key_str.encode()
                
                if not tool.validate_key(key):
                    print("❌ Invalid key format!")
                    continue
                
                filename = input("Filename (default: encryption.key): ").strip()
                filename = filename if filename else "encryption.key"
                tool.save_key_to_file(key, filename)
                print(f"✅ Key saved to '{filename}'")
                
            elif choice == '12':  # Load Key from File
                print("\n📥 LOAD KEY FROM FILE")
                filename = input("Filename (default: encryption.key): ").strip()
                filename = filename if filename else "encryption.key"
                key = tool.load_key_from_file(filename)
                print(f"✅ Key loaded:\n{key.decode()}")
                
            elif choice == '13':  # Validate Key
                print("\n✓ KEY VALIDATION")
                key_str = input("Enter key to validate: ").strip()
                key = key_str.encode()
                
                if tool.validate_key(key):
                    print("✅ Key is valid!")
                else:
                    print("❌ Key is invalid!")
                
            elif choice == '0':  # Exit
                print("\n👋 Thanks for using the Encryption Tool. Stay secure!")
                break
                
            else:
                print("❌ Invalid choice! Please try again.")
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Operation cancelled by user.")
            continue
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            continue
        
        input("\n Press Enter to continue...")

if __name__ == "__main__":
    main()