import math

def rsa_key(p: int, q: int, e: int = 65537) -> tuple:
    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        raise ValueError("e must be coprime to φ(n)")

    d = pow(e, -1, phi)
    
    return (n, e), (d, p, q)

def rsa_encrypt(m: int, public_key: tuple) -> int:
    n, e = public_key
    return pow(m, e, n)

def rsa_decrypt(c: int, private_key: tuple) -> int:
    d, p, q = private_key
    n = p * q
    return pow(c, d, n)  

