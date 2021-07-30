import click
import datetime
from functools import update_wrapper
from journal import encryption
from journal.global_config import PWD_ITERATIONS, VERIFY_PASSWORD_MESSAGE, DATA_PATH, PWD_ITERATIONS, PWD_MIN_LENGTH, ENTRIES_PATH, PASSWORD_KEY_PATH


def require_password(f):
  @click.pass_context
  def get_pwd(ctx, *args, **kwargs):
    pwd = None
    if PASSWORD_KEY_PATH.exists():
      while True:
        pwd_input = click.prompt("Password", type=str, hide_input=True)
        if validate_password(pwd_input, PASSWORD_KEY_PATH):
          click.echo("Correct!\n")
          pwd = pwd_input
          break
        else:
          click.echo("Incorrect")

    else:
      click.echo("No existing password found.")
      while True:
        pwd_input = click.prompt(
            "Create a new password", type=str, hide_input=True, confirmation_prompt=True)
        if len(pwd_input) < PWD_MIN_LENGTH:
          click.echo(
              f"Whoops. The password must be at least {PWD_MIN_LENGTH} {'characters' if PWD_MIN_LENGTH > 1 else 'character'} long.")
        else:
          pwd = pwd_input
          break
      encrypted_verify_msg = encryption.encrypt_from_password(
          VERIFY_PASSWORD_MESSAGE, pwd, PWD_ITERATIONS)
      PASSWORD_KEY_PATH.write_bytes(encrypted_verify_msg)
      click.echo(
          f"Password saved. Don't forget it.\n")

    return ctx.invoke(f, pwd, *args, **kwargs)

  return update_wrapper(get_pwd, f)


def validate_password(test_pwd, pwd_path):
  """
  Checks given pwd string against stored password token
  """
  pwd_token = pwd_path.read_bytes()
  verify_msg = encryption.decrypt_from_password(pwd_token, test_pwd)
  return verify_msg == VERIFY_PASSWORD_MESSAGE


def get_num_entries(path):
  return len(list(path.glob("*.entry")))


def list_entries(path, numbered=False):
  """
  List all entries in the data directory
  """
  if not path.exists():
    click.echo("No entries found.")
    return

  entries = sorted([f for f in path.glob("*.entry") if f.is_file()])

  if numbered:
    click.echo("ID\tENTRY NAME")
    click.echo("--------------------------------------------")
    for i in range(len(entries)):
      click.echo("{num}\t{file_name}".format(
          num=i+1, file_name=entries[i].name))
  else:
    click.echo("ENTRY NAME")
    click.echo("--------------------------------------------")
    for i in range(len(entries)):
      click.echo(f"{entries[i].name}")

  return entries


@click.group()
def cli():
  """
  Encrypted Journal CLI
  """
  # Create data directory if it doesn't already exist
  if not DATA_PATH.exists():
    DATA_PATH.mkdir()


@cli.command()
def entries():
  """
  List all journal entries
  """
  list_entries(ENTRIES_PATH, False)


@cli.command()
@require_password
def create(pwd):
  """
  Create a new encrypted journal entry
  """
  # Create entries directory if it doesn't exist
  if not ENTRIES_PATH.exists():
    ENTRIES_PATH.mkdir()

  # Open text editor for user to enter entry contents
  # Enabling require_save option will cause edit to return None if the user
  # quits without saving
  entry = click.edit(require_save=True)
  if entry is None:
    click.echo("Aborted entry creation")
    return

  entry = entry.encode("utf-8")

  entry_number = get_num_entries(ENTRIES_PATH) + 1
  now = datetime.datetime.utcnow()
  entry_name = str(entry_number) + '_' + str(now.date()) + '_' + \
      str(now.time()).replace(':', '-').replace('.', '-') + '.entry'
  new_entry_path = ENTRIES_PATH.joinpath(entry_name)

  click.echo(
      f"New encrypted entry successfully created at:\n{new_entry_path}")

  # Encrypt text and save to file
  encrypted = encryption.encrypt_from_password(entry, pwd)
  new_entry_path.write_bytes(encrypted)

  return True


@cli.command()
@require_password
def read(pwd):
  """
  Decrypt and read a journal entry
  """
  entries = list_entries(ENTRIES_PATH, True)

  i = int(input("Input the entry ID: ")) - 1
  try:
    entry_bytes = entries[i].read_bytes()
  except:
    click.echo(
        "ERROR Unable to open entry. Something might be wrong with the file")
    return

  try:
    msg = encryption.decrypt_from_password(entry_bytes, pwd)
  except:
    click.echo(
        "ERROR Failed to decrypt entry file. Make sure you entered the correct password")
    return

  click.edit(text="NOTE: Modifying this file will NOT affect the actual entry. This file will be deleted once you exit the editor.\n---------------------------------------\n\n" + msg)
