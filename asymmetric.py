from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class AsymmetricCipher:
    """
    Handles RSA encryption, decryption, and digital signatures.
    """

    def generate_keys(self):
        """Generate RSA-4096 private and public keys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, public_key, message: bytes) -> bytes:
        """Encrypt message using RSA public key."""
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, private_key, ciphertext: bytes) -> bytes:
        """Decrypt message using RSA private key."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign(self, private_key, message: bytes) -> bytes:
        """Create digital signature using RSA private key."""
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        """Verify RSA digital signature."""
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
