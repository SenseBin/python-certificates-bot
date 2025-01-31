# Python-Certificates-Bot

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
