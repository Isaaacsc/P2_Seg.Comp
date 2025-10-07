import base64
from key_generator import generate_prime
from rsa_keypair import rsa_key
from signature import sign_file, verify_signature, export_key, load_key_file
from rsa_oaep import rsa_encrypt_oaep, rsa_decrypt_oaep

def main():
    public_key = None
    private_key = None

    while True:
        print("\n=====-===== RSA Signature Generator/Verifier =====-=====")
        print(">>> 1. Generate RSA keys")
        print(">>> 2. Encrypt file")
        print(">>> 3. Decrypt file") 
        print(">>> 4. Sign file")
        print(">>> 5. Verify signature")
        print(">>> 0. Exit")
        
        choice = input("Choose an option: ")

        if choice == '1':
            print("Generating primes p and q (1024 bits)...")
            p = generate_prime(1024)
            q = generate_prime(1024)
            while p == q:
                q = generate_prime(1024)
            
            public_key, private_key = rsa_key(p, q)  #Public key (n, e), private key (d, p, q)
            export_key(public_key, 'public_key.txt', 'public')
            export_key(private_key, 'private_key.txt', 'private')
            print("Keys generated and saved successfully!")
            
        elif choice == '2': #Encrypt with OAEP + RSA
            if not public_key and not load_keys():
                continue
            
            filename = input("File to encrypt (e.g teste.txt): ")
            try:
                with open(filename, 'rb') as f:
                    plaintext = f.read()
                
                ciphertext = rsa_encrypt_oaep(plaintext, public_key)
                n, e = public_key
                ciphertext_bytes = ciphertext.to_bytes((n.bit_length() + 7) // 8, 'big')
                ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('ascii')
                
                output_file = filename + '.encrypted'
                with open(output_file, 'w') as f:
                    f.write(ciphertext_b64)
                
                print(f"Encrypted file: {output_file}")
                
            except FileNotFoundError:
                print("File not found!")
            except Exception as e:
                print(f"Encryption error: {e}")
                
        elif choice == '3': #Decrypt
            if not private_key and not load_keys():
                continue
            
            filename = input("Encrypted file (e.g test.txt.encrypted): ")
            try:
                with open(filename, 'r') as f:
                    ciphertext_b64 = f.read().strip()
                
                ciphertext_bytes = base64.b64decode(ciphertext_b64)
                ciphertext = int.from_bytes(ciphertext_bytes, 'big')
                plaintext = rsa_decrypt_oaep(ciphertext, private_key)
                
                output_file = filename.replace('.encrypted', '_decrypted')
                if output_file == filename:
                    output_file = filename + '_decrypted'
                
                with open(output_file, 'wb') as f:
                    f.write(plaintext)
                
                print(f"Decrypted file: {output_file}")
                
            except FileNotFoundError:
                print("File not found!")
            except Exception as e:
                print(f"Decryption error: {e}")
                
        elif choice == '4': #Sign
            if not private_key and not load_keys():
                continue
            
            filename = input("File to sign (e.g document.txt): ")
            try:
                signature = sign_file(filename, private_key)
                signature_file = filename + '.sig'
                with open(signature_file, 'w') as f:
                    f.write(signature)
                print(f"Signature saved: {signature_file}")
                
            except FileNotFoundError:
                print("File not found!")
            except Exception as e:
                print(f"Signing error: {e}")
                
        elif choice == '5': #Verification
            if not public_key and not load_keys():
                continue
            
            filename = input("Original file (e.g document.txt): ")
            signature_file = input("Signature file (e.g document.txt.sig): ")
            
            try:
                with open(signature_file, 'r') as f:
                    signature_b64 = f.read().strip()
                
                is_valid = verify_signature(filename, signature_b64, public_key)
                print("Signature VALID!" if is_valid else "Signature INVALID!")
                    
            except FileNotFoundError:
                print("File not found!")
            except Exception as e:
                print(f"Verification error: {e}")
                
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid option!")

def load_keys():
    global public_key, private_key
    try:
        public_key = load_key_file('public_key.txt', 'public')
        private_key = load_key_file('private_key.txt', 'private')
        print("Keys loaded from files.")
        return True
    except:
        print("Error: Generate keys first (Option 1)")
        return False

if __name__ == "__main__":
    main()