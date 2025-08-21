from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import logging
from typing import Tuple, Union
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass

class RSAKeyManager:
    """RSA Key Management with enhanced security features"""

    DEFAULT_KEY_SIZE = 2048
    MIN_KEY_SIZE = 2048
    MAX_KEY_SIZE = 4096

    @staticmethod
    def generate_rsa_keypair(key_size: int = DEFAULT_KEY_SIZE) -> Tuple[str, str]:
        """
        Generate a new RSA keypair with specified key size

        Args:
            key_size (int): RSA key size (default: 2048, min: 2048, max: 4096)

        Returns:
            Tuple[str, str]: (public_key_pem, private_key_pem)

        Raises:
            EncryptionError: If keypair generation fails
            ValueError: If key_size is invalid
        """
        if not RSAKeyManager.MIN_KEY_SIZE <= key_size <= RSAKeyManager.MAX_KEY_SIZE:
            raise ValueError(f"Key size must be between {RSAKeyManager.MIN_KEY_SIZE} and {RSAKeyManager.MAX_KEY_SIZE}")

        if key_size % 256 != 0:
            raise ValueError("Key size must be a multiple of 256")

        try:
            # Generate private key with secure random number generator
            private_key = rsa.generate_private_key(
                public_exponent=65537,  # Standard RSA exponent
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Serialize private key
            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # For demo; in production, use password
            ).decode('utf-8')

            # Serialize public key
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            logger.info(f"RSA keypair generated successfully (key_size: {key_size})")
            return pub_pem, priv_pem

        except Exception as e:
            logger.error(f"RSA keypair generation failed: {e}")
            raise EncryptionError(f"Failed to generate RSA keypair: {e}")

    @staticmethod
    def load_public_key(public_key_pem: str):
        """Load and validate public key from PEM format"""
        try:
            return serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), 
                backend=default_backend()
            )
        except Exception as e:
            raise EncryptionError(f"Invalid public key format: {e}")

    @staticmethod
    def load_private_key(private_key_pem: str, password: bytes = None):
        """Load and validate private key from PEM format"""
        try:
            return serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=password,
                backend=default_backend()
            )
        except Exception as e:
            raise EncryptionError(f"Invalid private key format: {e}")

def encrypt_data(public_key_pem: str, data: Union[str, bytes]) -> str:
    """
    Encrypt data using RSA-OAEP with SHA-256

    Args:
        public_key_pem (str): Public key in PEM format
        data (Union[str, bytes]): Data to encrypt

    Returns:
        str: Base64-encoded encrypted data

    Raises:
        EncryptionError: If encryption fails
        ValueError: If inputs are invalid
    """
    if not public_key_pem or not data:
        raise ValueError("Public key and data cannot be empty")

    # Convert string data to bytes
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data

    # Check data size limitations (RSA can encrypt limited data size)
    max_size = 190  # For 2048-bit key with OAEP padding
    if len(data_bytes) > max_size:
        raise ValueError(f"Data too large for RSA encryption (max {max_size} bytes)")

    try:
        public_key = RSAKeyManager.load_public_key(public_key_pem)

        # Encrypt using OAEP padding with SHA-256
        encrypted = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encode as base64 for safe transport/storage
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        logger.info(f"Data encrypted successfully ({len(data_bytes)} bytes)")
        return encrypted_b64

    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise EncryptionError(f"Failed to encrypt data: {e}")

def decrypt_data(private_key_pem: str, encrypted_data: str, password: bytes = None) -> str:
    """
    Decrypt RSA-OAEP encrypted data

    Args:
        private_key_pem (str): Private key in PEM format
        encrypted_data (str): Base64-encoded encrypted data
        password (bytes): Password for encrypted private key (if applicable)

    Returns:
        str: Decrypted data as string

    Raises:
        EncryptionError: If decryption fails
        ValueError: If inputs are invalid
    """
    if not private_key_pem or not encrypted_data:
        raise ValueError("Private key and encrypted data cannot be empty")

    try:
        private_key = RSAKeyManager.load_private_key(private_key_pem, password)

        # Decode base64 encrypted data
        encrypted_bytes = base64.b64decode(encrypted_data)

        # Decrypt using OAEP padding
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_str = decrypted.decode('utf-8')
        logger.info("Data decrypted successfully")
        return decrypted_str

    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise EncryptionError(f"Failed to decrypt data: {e}")

def encrypt_large_data(public_key_pem: str, data: Union[str, bytes]) -> str:
    """
    Encrypt large data using hybrid encryption (AES + RSA)
    For future enhancement when dealing with larger datasets

    Args:
        public_key_pem (str): Public key in PEM format
        data (Union[str, bytes]): Data to encrypt

    Returns:
        str: JSON string containing encrypted AES key and encrypted data
    """
    # Implementation placeholder for hybrid encryption
    # This would use AES for data encryption and RSA for key encryption
    pass

def get_key_info(key_pem: str, is_private: bool = True) -> dict:
    """
    Get information about an RSA key

    Args:
        key_pem (str): Key in PEM format
        is_private (bool): Whether the key is a private key

    Returns:
        dict: Key information including size and type
    """
    try:
        if is_private:
            key = RSAKeyManager.load_private_key(key_pem)
            key_type = "Private Key"
        else:
            key = RSAKeyManager.load_public_key(key_pem)
            key_type = "Public Key"

        key_size = key.key_size

        return {
            'type': key_type,
            'size': key_size,
            'algorithm': 'RSA',
            'padding': 'OAEP with SHA-256'
        }
    except Exception as e:
        raise EncryptionError(f"Failed to get key info: {e}")

# Legacy function names for backward compatibility
generate_rsa_keypair = RSAKeyManager.generate_rsa_keypair