from argon2 import PasswordHasher


class SecureHasher:
    """
    Provides secure password hashing using Argon2.
    """

    def __init__(self):
        self.ph = PasswordHasher()

    def hash_password(self, password: str) -> str:
        """Hash a password securely."""
        return self.ph.hash(password)

    def verify_password(self, hashed: str, password: str) -> bool:
        """Verify a password against its hash."""
        try:
            return self.ph.verify(hashed, password)
        except Exception:
            return False
