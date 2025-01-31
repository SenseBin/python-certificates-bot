import os
import hashlib
import requests
import json
import base64
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


# Generate a new account private key
def generate_account_key():
    account_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    return account_key


# Get ACME Nonce
def get_nonce(acme_directory):
    response = requests.head(acme_directory["newNonce"])
    return response.headers["Replay-Nonce"]


# Base64 URL-safe encoding
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


# Register account
def register_account(account_emails, acme_directory, account_key):
    protected = {
        "alg": "RS256",
        "nonce": get_nonce(acme_directory),
        "url": acme_directory["newAccount"],
        "jwk": {
            "kty": "RSA",
            "n": base64url_encode(account_key.public_key().public_numbers().n.to_bytes(512, 'big')),
            "e": base64url_encode(account_key.public_key().public_numbers().e.to_bytes(3, 'big')),
        },
    }

    payload = {
        "termsOfServiceAgreed": True,
        "contact": ['mailto:' + i for i in account_emails]
    }

    protected_b64 = base64url_encode(json.dumps(protected).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signature = account_key.sign(
        f"{protected_b64}.{payload_b64}".encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    response = requests.post(
        acme_directory["newAccount"],
        json={
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": base64url_encode(signature)
        },
        headers={
            'Content-Type': 'application/jose+json'
        }
    )
    if response.status_code == 201:
        return {
            'kid': response.headers.get('Location', ''),
            'account_info': response.json()
        }
    raise Exception('ACME account creation error')


# Generate CSR
def generate_csr(domain_name, domain_key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
    ])).sign(domain_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.DER)


# Create order
def create_order(acme_directory, account_kid, account_key, domain_name):
    protected = {
        "alg": "RS256",
        "nonce": get_nonce(acme_directory),
        "url": acme_directory["newOrder"],
        "kid": account_kid,
    }

    payload = {
        "identifiers": [{"type": "dns", "value": domain_name}]
    }

    protected_b64 = base64url_encode(json.dumps(protected).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signature = account_key.sign(
        f"{protected_b64}.{payload_b64}".encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    response = requests.post(
        acme_directory["newOrder"],
        json={
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": base64url_encode(signature)
        },
        headers={
            'Content-Type': 'application/jose+json'
        }
    )
    return response.json()


# Execute HTTP-01 challenge
def http_01_challenge(authz, acme_directory, account_key, account_kid, write_challenge_file_callback):
    print("Handling HTTP challenge...")

    # Get validation details
    auth_response = requests.get(authz)
    auth_data = auth_response.json()

    print(f'challenge auth_data={auth_data}')

    # Find HTTP-01 type challenge
    challenge = next(c for c in auth_data['challenges'] if c['type'] == 'http-01')
    token = challenge['token']

    def _big_number_to_byte(n: int) -> bytes:
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, byteorder="big")

    # Get JWK thumbprint
    jwk = {
        "kty": "RSA",
        "n": base64url_encode(_big_number_to_byte(account_key.public_key().public_numbers().n)),
        "e": base64url_encode(_big_number_to_byte(account_key.public_key().public_numbers().e))
    }
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    jwk_thumbprint = base64url_encode(hashlib.sha256(jwk_json.encode('utf-8')).digest())

    # Calculate validation content
    key_authorization = f"{token}.{jwk_thumbprint}"

    # Write validation file
    write_challenge_file_callback(token, key_authorization)

    # Notify ACME server to start validation
    protected = {
        "alg": "RS256",
        "nonce": get_nonce(acme_directory),
        "url": challenge['url'],
        "kid": account_kid,
    }

    payload = {}  # Empty payload is valid

    protected_b64 = base64url_encode(json.dumps(protected).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signature = account_key.sign(
        f"{protected_b64}.{payload_b64}".encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    response = requests.post(
        challenge['url'],
        json={
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": base64url_encode(signature)
        },
        headers={'Content-Type': 'application/jose+json'}
    )

    # Wait for validation to complete (max 60 seconds)
    max_attempts = 30  # 30 attempts, 2 seconds each
    attempts = 0
    while attempts < max_attempts:
        auth_response = requests.get(authz)
        auth_status = auth_response.json()['status']
        if auth_status == 'valid':
            break
        elif auth_status == 'invalid':
            print(f'Challenge validation status: {auth_status}')
        time.sleep(2)
        attempts += 1
    else:
        raise Exception("Challenge validation timeout after 60 seconds")

    print("Challenge completed successfully")


def write_challenge_file(base_dir, token, content):
    challenge_path = os.path.join(base_dir, token)
    save_file(challenge_path, content)


# Save file
def save_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)


# Main function
def main():
    account_emails = ['example@example.com']
    domain_name = "example.com"
    challenge_base_dir = 'web/.well-known/acme-challenge'
    output_dir = 'cert_output'
    acme_directory = {
        "newNonce": "https://acme-v02.api.letsencrypt.org/acme/new-nonce",
        "newAccount": "https://acme-v02.api.letsencrypt.org/acme/new-acct",
        "newOrder": "https://acme-v02.api.letsencrypt.org/acme/new-order"
    }

    # Generate account private key
    account_key = generate_account_key()

    # Register account
    register_account_reply = register_account(account_emails, acme_directory, account_key)
    account_kid = register_account_reply['kid']
    account_info = register_account_reply['account_info']
    print(f"Registered kid={account_kid}, account: {account_info}")

    # Generate domain private key and CSR
    domain_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    save_file(
        os.path.join(output_dir, 'private.key'),
        domain_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    )

    csr = generate_csr(domain_name, domain_key)

    # Create order
    order = create_order(acme_directory, account_kid, account_key, domain_name)
    print(f"Order created: {order}")

    # Execute HTTP-01 validation
    authz = order['authorizations'][0]
    http_01_challenge(
        authz,
        acme_directory,
        account_key,
        account_kid,
        lambda file_name, file_content: write_challenge_file(challenge_base_dir, file_name, file_content)
    )

    # Poll order status and get certificate
    order_finalize_url = order['finalize']
    protected = {
        "alg": "RS256",
        "nonce": get_nonce(acme_directory),
        "url": order_finalize_url,
        "kid": account_kid,
    }

    payload = {
        "csr": base64url_encode(csr)
    }

    protected_b64 = base64url_encode(json.dumps(protected).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signature = account_key.sign(
        f"{protected_b64}.{payload_b64}".encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    response = requests.post(
        order_finalize_url,
        json={
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": base64url_encode(signature)
        },
        headers={'Content-Type': 'application/jose+json'},
    )

    finalize_response = response.json()
    print(f'finalize_response={finalize_response}')
    print("Order finalized, waiting for certificate issuance...")

    # Retrieve the certificate
    while True:
        response = requests.get(finalize_response['certificate'])
        if response.status_code == 200:
            break
        time.sleep(2)

    certificate = response.text
    print(f"Certificate:\n{certificate}")

    # Save the certificate
    save_file(
        os.path.join(output_dir, 'certificate.crt'), 
        certificate
    )

    print("Certificate issuance completed")


if __name__ == "__main__":
    main()
