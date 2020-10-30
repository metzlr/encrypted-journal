import os
import base64
import secrets
import datetime
import sys
import fnmatch
import getpass
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


def create_entry(pwd):

  # Create entries directory if it doesn't exist
  if (not os.path.exists(ENTRIES_PATH)):
    os.mkdir(ENTRIES_PATH)

  # Get entry message
  entry_path = input(
      "Create a .txt file containing the entry. Enter the path to that file: ")
  try:
    entry_msg = open(entry_path, "r").read()
  except:
    print("ERROR Unable to open file at path:", entry_path)
    return False

  entry_number = get_num_entries() + 1
  now = datetime.datetime.now()
  entry_name = str(entry_number) + '___' + str(now.date()) + '_' + \
      str(now.time()).replace(':', '-').replace('.', '-') + '.entry'

  encrypted = encrypt_message(entry_msg, pwd, DEFAULT_ITERATIONS)
  open(ENTRIES_PATH+entry_name, 'wb').write(encrypted)
  return True


def read_entry(pwd):
  entries = list_entries()
  i = int(input("Input the entry ID: "))
  try:
    entry_bytes = open(os.path.join(ENTRIES_PATH, entries[i]), "rb").read()
  except:
    print("ERROR Unable to open entry. Something might be wrong with the file")

  msg = decrypt_message(entry_bytes, pwd)
  print("\nMESSAGE:\n")
  print(msg+"\n")


def list_entries():
  entries = [f for f in os.listdir(ENTRIES_PATH) if os.path.isfile(
      os.path.join(ENTRIES_PATH, f)) and os.path.splitext(f)[-1].lower() == '.entry']
  print("\nID\tNAME")
  for i in range(len(entries)):
    print("{num}\t{file_name}".format(num=i, file_name=entries[i]))
  print()
  return entries


def main():
  pwd = getpass.getpass(prompt='Enter password: ')

  while (True):
    cmd = input("journal: ")
    if (cmd == "help"):
      print("\nCommands:")
      print("help\t\t List available commands")
      print("create\t\t Create a new entry")
      print("read\t\t Read an entry")
      print("list\t\t Lists available entries")
      print("quit\t\t Quit")
      print()
    elif (cmd == "write"):
      success = create_entry(pwd)
      if (success):
        print("\nSuccessfully created new entry!\n")
      else:
        print("Failed to create entry")
    elif (cmd == "read"):
      read_entry(pwd)

    elif (cmd == "list"):
      list_entries()
    elif (cmd == "quit"):
      break


if __name__ == "__main__":
  main()
