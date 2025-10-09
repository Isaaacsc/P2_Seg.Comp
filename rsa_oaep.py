import secrets
import hashlib 
from rsa_keypair import rsa_encrypt, rsa_decrypt

class SHA3_256:
    digest_size = 32
    
    @staticmethod
    def new(data=b""):
        return hashlib.sha3_256(data)

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha3_256) -> bytes:
    hash_len = hash_func().digest_size
    if length > (hash_len << 32):
        raise ValueError("mask too long")
    
    T = b""
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4, 'big')
        T += hash_func(seed + C).digest()
        counter += 1
    
    return T[:length]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def oaep_encode(message: bytes, n: int, hash_func=hashlib.sha3_256) -> int:
    k = (n.bit_length() + 7) // 8  # module size in bytes
    hash_len = hash_func().digest_size
    message_len = len(message)
    
    if message_len > k - 2 * hash_len - 2:
        raise ValueError("message too long")
    
    # Padding generation
    label_hash = hash_func(b"").digest()  # empty hash label
    PS = b"\x00" * (k - message_len - 2 * hash_len - 2)
    DB = label_hash + PS + b"\x01" + message
    
    seed = secrets.token_bytes(hash_len)
    dbMask = mgf1(seed, k - hash_len - 1)
    maskedDB = xor_bytes(DB, dbMask)
    seedMask = mgf1(maskedDB, hash_len)
    maskedSeed = xor_bytes(seed, seedMask)
    
    EM = b"\x00" + maskedSeed + maskedDB
    return int.from_bytes(EM, 'big')

def oaep_decode(em: int, n: int, hash_func=hashlib.sha3_256) -> bytes:
    k = (n.bit_length() + 7) // 8  # block size in bytes
    hash_len = hash_func().digest_size  # hash size in bytes
    EM = em.to_bytes(k, 'big')

    if EM[0] != 0:
        raise ValueError("Corrupted message - invalid first byte")
    
    # Separate the two main parts of the message, the seed (maskedSeed) and the data (maskedDB) that was masked to unmask
    maskedSeed = EM[1:1 + hash_len]  
    maskedDB = EM[1 + hash_len:]     
    seedMask = mgf1(maskedDB, hash_len)
    seed = xor_bytes(maskedSeed, seedMask)
    dbMask = mgf1(seed, k - hash_len - 1)
    DB = xor_bytes(maskedDB, dbMask)
    
    lHash = hash_func(b"").digest()
    if DB[:hash_len] != lHash:
        raise ValueError("Message altered. Label hash doesn't match")

    i = hash_len
    while i < len(DB) and DB[i] == 0:
        i += 1
    
    if i >= len(DB) or DB[i] != 1:
        raise ValueError("Unable to locate the start of the real message")
    
    original_message = DB[i + 1:]
    
    return original_message

def rsa_encrypt_oaep(message: bytes, public_key: tuple) -> int:
    n, e = public_key
    em = oaep_encode(message, n)
    return rsa_encrypt(em, public_key)

def rsa_decrypt_oaep(ciphertext: int, private_key: tuple) -> bytes:
    # private_key = (d, p, q) or (d, n)
    if len(private_key) > 2:
        n = private_key[1] * private_key[2]
    else:
        n = private_key[1] if len(private_key) > 1 else private_key[0]
    em = rsa_decrypt(ciphertext, private_key)
    return oaep_decode(em, n)
