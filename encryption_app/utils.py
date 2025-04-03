from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64
import os
from django.conf import settings

def load_rsa_keys():
    """Load RSA keys from filesystem"""
    key_dir = settings.KEY_DIR
    
    private_key_path = os.path.join(key_dir, 'private_key.pem')
    public_key_path = os.path.join(key_dir, 'public_key.pem')
    
    private_key = None
    public_key = None
    
    # Load keys if they exist
    if os.path.exists(private_key_path):
        with open(private_key_path, 'rb') as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None
            )
            
    if os.path.exists(public_key_path):
        with open(public_key_path, 'rb') as key_file:
            public_key = load_pem_public_key(
                key_file.read()
            )
            
    return private_key, public_key

def rsa_encrypt(public_key_pem, plaintext):
    """
    Encrypt data using RSA public key
    
    Args:
        public_key_pem (str): PEM-encoded public key
        plaintext (str): Text to encrypt
    
    Returns:
        str: Base64-encoded encrypted data
    """
    try:
        # Load the public key
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        
        # Encrypt the data
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded ciphertext
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        raise Exception(f"RSA encryption failed: {str(e)}")

def rsa_decrypt(private_key_pem, ciphertext):
    """
    Decrypt data using RSA private key
    
    Args:
        private_key_pem (str): PEM-encoded private key
        ciphertext (str): Base64-encoded encrypted data
    
    Returns:
        str: Decrypted text
    """
    try:
        # Load the private key
        private_key = load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Decode the base64 ciphertext
        decoded_ciphertext = base64.b64decode(ciphertext)
        
        # Decrypt the data
        plaintext = private_key.decrypt(
            decoded_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return the decrypted text
        return plaintext.decode('utf-8')
    except Exception as e:
        raise Exception(f"RSA decryption failed: {str(e)}")