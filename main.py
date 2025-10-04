import key_generator
import rsa_keypair


p, q = 0
while p == q:
    p = key_generator.generate_prime()
    q = key_generator.generate_prime()

def process_file(input_filename: str, action: str, x) -> None:
    if action == 'encrypt':
        output_filename = input_filename.rsplit('.', 1)[0] + 'encrypt.txt'
        with open(input_filename, 'r', encoding='ascii') as infile, open(output_filename, 'w', encoding='ascii') as outfile:
            for char in infile.read():
                asc_num = ord(char)
                new_num = x(asc_num)
                outfile.write(str(new_num) + ' ')  # Add space as delimiter
    else:
        output_filename = input_filename.rsplit('.', 1)[0] + 'decrypt.txt'
        with open(input_filename, 'r', encoding='ascii') as infile, open(output_filename, 'w', encoding='ascii') as outfile:
            encrypted_data = infile.read().split()  # Split by space
            for num_str in encrypted_data:
                if num_str:  # skip empty strings
                    decrypted_char = x(int(num_str))
                    outfile.write(chr(decrypted_char))

public_key, privete_key = rsa_keypair.rsa_key(p, q)
process_file('document.txt', 'encrypt', lambda m: rsa_keypair.rsa_encrypt(m, public_key))
process_file('encrypt.txt', 'decrypt', lambda c: rsa_keypair.rsa_decrypt(c, privete_key))
