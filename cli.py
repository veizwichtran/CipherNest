import click
from .symmetric import SymmetricCipher
from .hashing import SecureHasher


@click.group()
def cli():
    """CipherNest CLI entry point."""
    pass


@cli.command()
@click.argument("message")
def encrypt(message):
    """Encrypt a message using AES."""
    cipher = SymmetricCipher()
    key = cipher.generate_key()
    nonce, ciphertext = cipher.encrypt(key, message.encode())

    click.echo(f"Key: {key.hex()}")
    click.echo(f"Nonce: {nonce.hex()}")
    click.echo(f"Ciphertext: {ciphertext.hex()}")


@cli.command()
@click.argument("password")
def hash(password):
    """Hash a password securely."""
    hasher = SecureHasher()
    hashed = hasher.hash_password(password)
    click.echo(f"Hashed Password: {hashed}")
