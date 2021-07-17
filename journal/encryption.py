import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from journal.config import DEFAULT_ITERATIONS
from typing import Union


def get_key(pwd: bytes, salt: bytes, iterations: int) -> bytes:
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=iterations,
  )
  return base64.urlsafe_b64encode(kdf.derive(pwd))


def encrypt_from_password(msg: Union[str, bytes], pwd: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
  if isinstance(msg, str):
    msg = msg.encode('utf-8')

  salt = secrets.token_bytes(32)
  key = get_key(pwd.encode('utf-8'), salt, iterations)
  # Creates a base64 encoded token in format of salt + iterations + encrypted message. Storing salt/iterations with message allows messages to be decrypted independently
  return base64.urlsafe_b64encode(
      b'%b%b%b' % (
          salt,
          iterations.to_bytes(4, 'big'),  # 4 bytes w/ most significant first
          # Decode encrypted message from base64 since we are re-encoding it
          base64.urlsafe_b64decode(Fernet(key).encrypt(msg)),
      )
  )


def decrypt_from_password(token: bytes, pwd: str) -> str:
  decoded = base64.urlsafe_b64decode(token)

  salt = decoded[:32]
  iterations = int.from_bytes(decoded[32:36], 'big')
  # Fernet expects msg in base64 so it must be re-encoded
  encrypted_msg = base64.urlsafe_b64encode(decoded[36:])
  key = get_key(pwd.encode('utf-8'), salt, iterations)
  try:
    decrypted_txt = Fernet(key).decrypt(encrypted_msg).decode('utf-8')
    return decrypted_txt
  except:
    return None
