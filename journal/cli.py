import os
import click
import editor
import fnmatch
import datetime
from click.decorators import pass_context
from functools import update_wrapper
from dotenv import load_dotenv
from journal import encryption
from journal.config import PWD_ITERATIONS, VERIFY_PWD_FILENAME, VERIFY_PWD_MSG, PROD_DATA_PATH, DEV_DATA_PATH, PWD_ITERATIONS, PWD_MIN_LENGTH, ENTRIES_PATH

load_dotenv()

def require_password(f):
  @click.pass_context
  def get_pwd(ctx, *args, **kwargs):
    data_path = ctx.obj["DATA_PATH"]
    pwd_path = os.path.join(data_path, VERIFY_PWD_FILENAME)
    pwd = None
    if (os.path.exists(pwd_path)):
      while True:
        pwd_input = click.prompt("Password", type=str, hide_input=True)
        if (validate_password(pwd_input, pwd_path)):
          click.echo("Correct!\n")
          pwd = pwd_input
          break
        else:
          click.echo("Incorrect")

    else:
      click.echo("No existing password found.")
      while True:
        pwd_input = click.prompt("Create a new password", type=str, hide_input=True, confirmation_prompt=True)
        if len(pwd_input) < PWD_MIN_LENGTH:
          click.echo(f"Whoops. The password must be at least {PWD_MIN_LENGTH} {'characters' if PWD_MIN_LENGTH > 1 else 'character'} long.")
        else:
          break
      encrypted_verify_msg = encryption.encrypt_message(
          VERIFY_PWD_MSG, pwd_input, PWD_ITERATIONS)
      open(pwd_path, 'wb').write(encrypted_verify_msg)
      click.echo(
          f"Password saved. Don't forget it.")

    return ctx.invoke(f, pwd, *args, **kwargs)

  return update_wrapper(get_pwd, f)


def validate_password(test_pwd, pwd_path):
  """
  Checks given pwd string against stored password token
  """
  pwd_token = open(pwd_path, 'rb').read()
  verify_msg = encryption.decrypt_message(pwd_token, test_pwd)
  return verify_msg == VERIFY_PWD_MSG


def get_num_entries(path):
  return len(fnmatch.filter(os.listdir(path), '*.entry'))


def list_entries(path, numbered=False):
  """
  List all entries in the data directory
  """

  if not os.path.isdir(path):
    click.echo("No entries found.")
    return

  entries = [f for f in os.listdir(path) if os.path.isfile(
      os.path.join(path, f)) and os.path.splitext(f)[-1].lower() == '.entry']
  
  if numbered:
    click.echo("\nID\tENTRY NAME")
    click.echo("--------------------------------------------")
    for i in range(len(entries)):
      click.echo("{num}\t{file_name}".format(num=i, file_name=entries[i]))
  else:
    click.echo("\nENTRY NAME")
    click.echo("--------------------------------------------")
    for i in range(len(entries)):
      click.echo(f"{entries[i]}")

  return entries
  

@click.group()
@click.pass_context
def cli(ctx):
  """
  Encrypted Journal CLI
  """
  
  # ensure that ctx.obj exists and is a dict
  ctx.ensure_object(dict)

  dev = os.getenv("DEV", "False").lower() == 'true'
  if dev:
    ctx.obj["DATA_PATH"] = DEV_DATA_PATH
  else:
    ctx.obj["DATA_PATH"] = PROD_DATA_PATH

  # Create data directory if it doesn't already exist
  os.makedirs(ctx.obj["DATA_PATH"], exist_ok=True)


@cli.command()
@pass_context
def entries(ctx):
  """
  List all journal entries
  """
  entries_path = os.path.join(ctx.obj["DATA_PATH"], ENTRIES_PATH)
  list_entries(entries_path, False)


@cli.command()
@require_password
@pass_context
def create(ctx, pwd):
  """
  Create a new encrypted journal entry
  """
  entries_path = os.path.join(ctx.obj["DATA_PATH"], ENTRIES_PATH)

  # Create entries directory if it doesn't exist
  if (not os.path.exists(entries_path)):
    os.mkdir(entries_path)

  entry_number = get_num_entries(entries_path) + 1
  now = datetime.datetime.utcnow()
  entry_name = str(entry_number) + '_' + str(now.date()) + '_' + \
      str(now.time()).replace(':', '-').replace('.', '-') + '.entry'

  # Open text editor for user to enter entry contents
  new_entry_path = os.path.join(entries_path, entry_name)
  entry_bytes = editor.edit(filename=new_entry_path, contents="New journal entry")

  click.echo(f"New encrypted entry successfully created at: {new_entry_path}")

  # Encrypt text and save to file
  encrypted = encryption.encrypt_message(entry_bytes, pwd)
  open(new_entry_path, 'wb').write(encrypted)

  return True

@cli.command()
@require_password
@pass_context
def read(ctx, pwd):
  """
  Decrypt and read a journal entry
  """

  entries_path = os.path.join(ctx.obj["DATA_PATH"], ENTRIES_PATH)
  entries = list_entries(entries_path, True)

  i = int(input("Input the entry ID: "))
  try:
    entry_bytes = open(os.path.join(entries_path, entries[i]), "rb").read()
  except:
    click.echo("ERROR Unable to open entry. Something might be wrong with the file")
    return

  try:
    msg = encryption.decrypt_message(entry_bytes, pwd)
  except:
    click.echo("ERROR Failed to decrypt entry file. Make sure you entered the correct password")
    return

  click.echo("\ENTRY:\n")
  click.echo(msg+"\n")