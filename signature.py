import base64
import hashlib  
from rsa_oaep import oaep_encode, oaep_decode

def sign_file(filename: str, private_key: tuple) -> str:
    hash_obj = hashlib.sha3_256()
    with open(filename, 'rb') as f:
        while chunk := f.read(4096):
            hash_obj.update(chunk)
    file_hash = hash_obj.digest()
    
    d, p, q = private_key
    n = p * q
    
    hash_encoded = oaep_encode(file_hash, n)
    signature_int = pow(hash_encoded, d, n)
    
    byte_length = (n.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(byte_length, 'big')
    signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
    
    return signature_b64

def verify_signature(filename: str, signature_b64: str, public_key: tuple) -> bool:
    try:
        signature_bytes = base64.b64decode(signature_b64)
        signature_int = int.from_bytes(signature_bytes, 'big')
        
        n, e = public_key
        decrypted_encoded = pow(signature_int, e, n)
        decrypted_hash = oaep_decode(decrypted_encoded, n)
        
        hash_obj = hashlib.sha3_256()
        with open(filename, 'rb') as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        current_hash = hash_obj.digest()
        
        return decrypted_hash == current_hash
        
    except Exception as e:
        print(f"Verification error: {e}")
        return False

def export_key(key: tuple, filename: str, key_type: str):
    with open(filename, 'w') as f:
        if key_type == 'public':
            n, e = key
            f.write(f"n={n}\n")
            f.write(f"e={e}\n")
        else: 
            d, p, q = key
            f.write(f"d={d}\n")
            f.write(f"p={p}\n")
            f.write(f"q={q}\n")

def load_key_file(filename: str, key_type: str) -> tuple:
    key_data = {}
    with open(filename, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=')
                key_data[key] = int(value)
    
    if key_type == 'public':
        return (key_data['n'], key_data['e'])
    else: 
        return (key_data['d'], key_data['p'], key_data['q'])