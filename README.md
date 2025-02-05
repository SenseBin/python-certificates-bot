# Python-Certificates-Bot
- [English](README.md)
- [简体中文](README.zh.md)
## Abstract

Python-Certificates-Bot is a Python tool designed to automate the process of obtaining SSL/TLS certificates from Let's Encrypt using the ACME protocol. This bot handles account registration, order creation, HTTP-01 challenge validation, and certificate issuance, making it easy to secure your web server with HTTPS.

## Features
- Generate and manage ACME accounts
- Create and finalize orders for SSL/TLS certificates
- Handle HTTP-01 challenge validation
- Automatically save certificates, private keys, and certificate chains
- Compatible with Let's Encrypt and other ACME-based certificate authorities

## Installation
Clone the repository and install the required dependencies:

```bash
git clone https://github.com/SenseBin/python-certificates-bot .git
cd python-certificates-bot 
pip install requests cryptography
```

## Usage
1. Modify `account_emails` in the main function to your own email address.
2. Change `domain_name` in the main function to the domain name for which you want to generate a certificate.
3. Set `challenge_base_dir` to your server's `$webroot/.well-known/acme-challenge`

Run the script:
```bash
python python-certificates-bot.py
```
The output files will be generated in the `cert_output` directory.

## Contributing
Contributions are welcome! Please submit pull requests or open issues for any bugs or feature requests.
