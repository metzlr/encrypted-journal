import os
import base64
import secrets
import datetime
import sys
import fnmatch
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_ITERATIONS = 100000
ENTRIES_PATH = './entries/'


def get_key(pwd: bytes, salt: bytes, iterations: int) -> bytes:
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=iterations,
  )
  return base64.urlsafe_b64encode(kdf.derive(pwd))


def encrypt_message(msg: str, pwd: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
  salt = secrets.token_bytes(16)
  key = get_key(pwd.encode('utf-8'), salt, iterations)
  # Creates a base64 encoded token in format of salt + iterations + encrypted message. Storing salt/iterations with message allows messages to be decrypted independently
  return base64.urlsafe_b64encode(
      b'%b%b%b' % (
          salt,
          iterations.to_bytes(4, 'big'),  # 4 bytes w/ most significant first
          # Decode encrypted message from base64 since we are re-encoding it
          base64.urlsafe_b64decode(Fernet(key).encrypt(msg.encode('utf-8'))),
      )
  )


def decrypt_message(token: bytes, pwd: str) -> str:
  decoded = base64.urlsafe_b64decode(token)

  salt = decoded[:16]
  iterations = int.from_bytes(decoded[16:20], 'big')
  # Fernet expects msg in base64 so it must be re-encoded
  encrypted_msg = base64.urlsafe_b64encode(decoded[20:])

  key = get_key(pwd.encode('utf-8'), salt, iterations)
  return Fernet(key).decrypt(encrypted_msg).decode('utf-8')


def get_num_entries():
  return len(fnmatch.filter(os.listdir(ENTRIES_PATH), '*.entry'))


def create_entry():
  pwd = input("Enter your password: ")

  # Create entries directory if it doesn't exist
  if (not os.path.exists(ENTRIES_PATH)):
    os.mkdir(ENTRIES_PATH)

  # Get entry message
  entry_path = input(
      "Create a .txt file containing the entry. Enter the path to that file: ")
  try:
    entry_msg = open(entry_path, "r").read()
  except:
    print("ERROR unable to open file at path:", entry_path)
    return

  entry_number = get_num_entries() + 1
  now = datetime.datetime.now()
  entry_name = str(entry_number) + '___' + str(now.date()) + '_' + \
      str(now.time()).replace(':', '-')

  encrypted = encrypt_message(entry_msg, pwd, DEFAULT_ITERATIONS)
  open(ENTRIES_PATH+entry_name, 'wb').write(encrypted)


def main():

  create_entry()


if __name__ == "__main__":
  main()
