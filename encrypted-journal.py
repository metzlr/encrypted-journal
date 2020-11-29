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
DATA_PATH = 'data/'
ENTRIES_PATH = os.path.join(DATA_PATH, 'entries/')
VERIFY_PWD_FILENAME = 'password.key'
VERIFY_PWD_PATH = os.path.join(DATA_PATH, VERIFY_PWD_FILENAME)
VERIFY_PWD_MSG = "This message will be encoded by the chosen password and used to verify that the correct password is being used."


def get_key(pwd: bytes, salt: bytes, iterations: int) -> bytes:
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=iterations,
  )
  return base64.urlsafe_b64encode(kdf.derive(pwd))


def encrypt_message(msg: str, pwd: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
  salt = secrets.token_bytes(32)
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


def get_num_entries():
  return len(fnmatch.filter(os.listdir(ENTRIES_PATH), '*.entry'))


def create_entry(pwd):

  # Create entries directory if it doesn't exist
  if (not os.path.exists(ENTRIES_PATH)):
    os.mkdir(ENTRIES_PATH)

  # Get entry message
  entry_text_path = input(
      "Create a .txt file containing the entry. Enter the path to that file: ")
  try:
    entry_msg = open(entry_text_path, "r").read()
  except:
    print("ERROR Unable to open file at path:", entry_text_path)
    return False

  entry_number = get_num_entries() + 1
  now = datetime.datetime.now()
  entry_name = str(entry_number) + '___' + str(now.date()) + '_' + \
      str(now.time()).replace(':', '-').replace('.', '-') + '.entry'

  encrypted = encrypt_message(entry_msg, pwd, DEFAULT_ITERATIONS)
  open(os.path.join(ENTRIES_PATH, entry_name), 'wb').write(encrypted)
  return True


def read_entry(pwd):
  entries = list_entries()
  i = int(input("Input the entry ID: "))
  try:
    entry_bytes = open(os.path.join(ENTRIES_PATH, entries[i]), "rb").read()
  except:
    print("ERROR Unable to open entry. Something might be wrong with the file")
    return

  try:
    msg = decrypt_message(entry_bytes, pwd)
  except:
    print("ERROR Failed to decrypt entry file. Make sure you entered the correct password")
    return
  print("\nMESSAGE:\n")
  print(msg+"\n")


# Lists all files with '.entry' extension in ENTRIES_PATH
def list_entries():
  entries = [f for f in os.listdir(ENTRIES_PATH) if os.path.isfile(
      os.path.join(ENTRIES_PATH, f)) and os.path.splitext(f)[-1].lower() == '.entry']
  print("\nID\tNAME")
  for i in range(len(entries)):
    print("{num}\t{file_name}".format(num=i, file_name=entries[i]))
  print()
  return entries


# Checks given pwd string against stored password token
def validate_password(pwd):
  pwd_token = open(VERIFY_PWD_PATH, 'rb').read()
  verify_msg = decrypt_message(pwd_token, pwd)
  return verify_msg == VERIFY_PWD_MSG


def main():
  if (os.path.exists(VERIFY_PWD_PATH)):
    pwd = getpass.getpass(prompt="Enter password: ")
    if (not validate_password(pwd)):
      print("Whoops. That password does not match the original.")
      return
  else:
    while (True):
      pwd = getpass.getpass(prompt="Enter a new password: ")
      confirmation = getpass.getpass(prompt="Confirm new password: ")
      if (confirmation == pwd):
        break
      print("The passwords did not match. Try again.")

    # Create data directory if it doesn't already exist
    os.makedirs(DATA_PATH, exist_ok=True)

    encrypted_verify_msg = encrypt_message(
        VERIFY_PWD_MSG, pwd, DEFAULT_ITERATIONS)
    open(VERIFY_PWD_PATH, 'wb').write(encrypted_verify_msg)
    print(
        f"Created an encrypted password file in '{VERIFY_PWD_PATH}'. It will be used to verify your password in the future. So don't delete it.")

  while (True):
    cmd = input("journal: ")
    if (cmd == "help"):
      print("\nCommands:")
      print("help\t\t List available commands")
      print("create\t\t Create a new entry")
      print("read\t\t Read an entry")
      print("list\t\t List saved entries")
      print("quit\t\t Quit")
      print()
    elif (cmd == "create"):
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
    else:
      print("Unknown command. Type 'help' for list of commands.")


if __name__ == "__main__":
  main()
