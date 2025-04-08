# Phoenix[CIA S\V] - CIA Triad Secure File Vault

> "Because Confidentiality, Integrity, and Availability should never be boring."

![Phoenix Banner](./assets/banner.txt)

## 🔐 Introduction
Welcome to **Phoenix[CIA S\V]**, your own secure vault built on the core principles of the **CIA Triad**:
- **Confidentiality** via strong AES encryption.
- **Integrity** through HMAC verification.
- **Availability** with automated backups.

Built using Python and tested on **Kali Linux**, this project helps you encrypt files, verify their integrity, decrypt them safely, and back them up — all through a clean CLI interface with style.

---

## 🚀 Getting Started

### 📥 Clone the Repository
```bash
git clone https://github.com/yourusername/cia_secure_vault.git
cd cia_secure_vault
```

### 🔧 Install Requirements
Make sure you have Python 3 installed. Then run:
```bash
pip install -r requirements.txt
```

### ✅ Requirements File (`requirements.txt`)
```
pycryptodome
```

---

## 📚 How to Use
After installing, run the main script:
```bash
python3 main.py
```
You'll be greeted with an awesome banner and a menu like:
```
Welcome to Phoenix[CIA S\V]
1. Add File
2. Retrieve File
3. Verify File
4. Backup File
5. Help & Docs
6. Exit
```

### 🔐 Add File
```bash
python3 main.py add -i /path/to/yourfile.txt
```
Encrypts the file, creates HMAC, and backs up everything.

### 🔓 Retrieve File
```bash
python3 main.py retrieve -f yourfile.txt -o decrypted.txt
```
Decrypts and checks integrity before saving.

### 🧪 Verify Integrity
```bash
python3 main.py verify -f yourfile.txt
```
Verifies if the file has been tampered with using HMAC.

### 🗂 Backup File
```bash
python3 main.py backup -f yourfile.txt
```
Manually backs up your encrypted file.

---

## 🧠 Learning Outcome
This project strengthens your practical understanding of:
- AES encryption & decryption.
- HMAC and cryptographic integrity.
- Secure file handling.
- CLI automation using Python's argparse.

Perfect for beginners and intermediate cybersecurity enthusiasts.

---

## 📁 Project Structure
```
cia_secure_vault/
├── assets/               # ASCII banners and future UI art
├── vault/                # Encrypted files storage
├── backup/               # Backup directory
├── main.py               # Main CLI driver
├── crypto_utils.py       # AES encryption/decryption
├── integrity.py          # HMAC functions
├── backup.py             # Backup helper
├── requirements.txt      # Python dependencies
├── README.md             # This file
└── LICENSE
```

---

## 📜 License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## 🌟 Fun Fact
Did you know? The CIA Triad isn’t a secret agency — it’s the foundation of everything in cybersecurity! 😉

Built with ❤️ in the world of Kali.

---

## 🤝 Contributing
Feel free to fork and PR! Let’s make security tools more awesome and accessible.

---

## 🧭 What's Next?
Check back soon or follow me — we’re building a full GitHub portfolio of:
- Cybersecurity Tools 🛠
- CLI-Based Learning Games 🎮
- Real-World Security Simulations 💣

Stay tuned, and stay secure!

