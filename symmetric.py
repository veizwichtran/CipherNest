from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class SymmetricCipher:
    """
    Handles AES-256 encryption and decryption using AES-GCM.
    """

    def generate_key(self) -> bytes:
        """Generate a secure 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, key: bytes, data: bytes) -> tuple:
        """
        Encrypt data using AES-GCM.
        Returns nonce and ciphertext.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt AES-GCM encrypted data.
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
