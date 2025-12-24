from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Generate private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Generate public key
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Get the directory where THIS script is located
current_dir = os.path.dirname(os.path.abspath(__file__))

private_path = os.path.join(current_dir, "private_key.pem")
public_path = os.path.join(current_dir, "public_key.pem")

with open(private_path, "wb") as f: 
    f.write(private_pem)

with open(public_path, "wb") as f: 
    f.write(public_pem)

print(f"Keys saved to: {current_dir}")