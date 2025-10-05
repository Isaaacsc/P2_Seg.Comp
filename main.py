import base64
import key_generator
import rsa_keypair
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

p, q = 0, 0
while p == q:
    p = key_generator.generate_prime()
    q = key_generator.generate_prime()

public_key, private_key = rsa_keypair.rsa_key(p, q)

# Constrói chaves RSA no formato da lib pycryptodome
pub_rsa = RSA.construct((public_key[0], public_key[1]))   # (n, e)
priv_rsa = RSA.construct((public_key[0], private_key[0], private_key[1]))  # (n, d, e)

# Cria cifradores OAEP com SHA-256
encryptor = PKCS1_OAEP.new(pub_rsa, hashAlgo=SHA256)
decryptor = PKCS1_OAEP.new(priv_rsa, hashAlgo=SHA256)

def process_file(input_filename: str, action: str) -> None:
    if action == 'encrypt':
        output_filename = input_filename.rsplit('.', 1)[0] + '_encrypt.txt'
        with open(input_filename, 'rb') as infile, open(output_filename, 'w', encoding='ascii') as outfile:
            plaintext = infile.read()
            
            # Tamanho máximo de bloco para OAEP com SHA-256
            key_size_bytes = pub_rsa.size_in_bytes()
            hLen = SHA256.digest_size
            max_block_size = key_size_bytes - 2 * hLen - 2
            
            for i in range(0, len(plaintext), max_block_size):
                block = plaintext[i:i+max_block_size]
                encrypted_block = encryptor.encrypt(block)
                b64_block = base64.b64encode(encrypted_block).decode('ascii')
                outfile.write(b64_block + "\n")

    else:  # decrypt
        output_filename = input_filename.rsplit('.', 1)[0] + '_decrypt.txt'
        with open(input_filename, 'r', encoding='ascii') as infile, open(output_filename, 'wb') as outfile:
            for line in infile:
                if line.strip():
                    encrypted_block = base64.b64decode(line.strip())
                    decrypted_block = decryptor.decrypt(encrypted_block)
                    outfile.write(decrypted_block)

process_file('document.txt', 'encrypt')
process_file('document_encrypt.txt', 'decrypt')
