import math

def rsa_key(p: int, q: int, e: int = 65537) -> tuple:
    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        raise ValueError("e must be coprime to φ(n)")

    d = pow(e, -1, phi)

    return (n, e), (p, q, d)

def rsa_encrypt(m: int, public_key: tuple) -> int:
    n, e = public_key

    return pow(m, e, n)

def rsa_decrypt(c: int, private_key: tuple) -> int:
    p, q, d = private_key

    dp = d % (p - 1)
    dq = d % (q - 1)
    
    mp = pow(c % p, dp, p)
    mq = pow(c % q, dq, q)

    q_inv = pow(q, -1, p)
    h = (q_inv * (mp - mq)) % p
    m = (mq + h * q) % (p * q)
    return m