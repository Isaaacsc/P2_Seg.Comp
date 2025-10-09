# 🔐 RSA Digital Signature Generator and Verifier

This project implements a complete **RSA-based digital signature system** using **OAEP padding** and **SHA3-256 hashing**, fully written in **Python 3** and **without external cryptography libraries**.  
It includes both a **command-line interface** and a **Tkinter GUI**, designed for educational and academic use.

---

## 🧠 Overview

The system can:
- Generate RSA key pairs (2048 bits);
- Encrypt and decrypt files using OAEP and SHA3-256;
- Digitally sign and verify text or binary files;
- Operate through GUI or terminal menu;
- Optimize decryption using the **Chinese Remainder Theorem (CRT)**.

---

## ⚙️ Project Structure

├── key_generator.py # Prime generation (Miller-Rabin + trial division)
├── rsa_keypair.py # RSA key generation and CRT optimization
├── rsa_oaep.py # OAEP padding and RSA operations
├── signature.py # Digital signature and verification
├── interface.py # Graphical interface (Tkinter)
├── main.py # Command-line interface
└── README.md

---

## 💻 Requirements

- **OS:** Linux (Ubuntu 20.04+ recommended)  
- **Python:** Version 3.10 or newer  
- **Standard libraries used:** `hashlib`, `math`, `secrets`, `base64`, `tkinter`  

> No external libraries are required.

---

## 🚀 How to Run

### 1. Clone the repository
bash
git clone https://github.com/youruser/rsa-signature-tool.git
cd rsa-signature-tool
2. Run with graphical interface
bash
python3 interface.py
  3. Or use the command-line menu
bash
  python3 main.py
🔧 Features
Key Generation: 2048-bit RSA with Miller–Rabin primality test

OAEP Padding: Secure against chosen-ciphertext attacks

SHA3-256 Hashing: Ensures strong message integrity

CRT Optimization: ~75% faster RSA decryption

Error Handling: Detects invalid keys, corrupted or tampered files

🧪 Example Usage
  Generate keys:
  
  bash
    python3 main.py
  → Select option 1 to create public_key.txt and private_key.txt.
  
  Sign a file:
  
  bash
    python3 main.py
  → Choose option 4 and enter the file name (e.g., document.txt).
  
  Verify signature:
  
  bash
    python3 main.py
  → Choose option 5 to confirm authenticity.

🧩 Performance
Method	Avg. Time (ms)	Reduction
Standard Decryption	125.4	–
CRT Decryption	31.2	75% faster

👥 Authors
Name	ID	Role
Isaac Silva - Isaaacsc
Gabriela Costa

📚 References
RFC 8017 — PKCS #1: RSA Cryptography Specifications (v2.2)

Python Docs — hashlib module

Wikipedia — RSA cryptosystem, OAEP, Miller–Rabin test

🧾 License
Developed for the course CIC0201 – Computer Security.
Free for academic and research purposes.
