from select import select
import click
import datetime
from functools import update_wrapper
from journal import encryption
from journal.global_config import PWD_ITERATIONS, VERIFY_PASSWORD_MESSAGE, DATA_PATH, PWD_ITERATIONS, PWD_MIN_LENGTH, ENTRIES_PATH, PASSWORD_KEY_PATH
from pathlib import Path

EXIT_COMMANDS = ['quit', 'exit', 'q']
ENTRY_NAME_FORMAT = "%Y-%m-%d_%H-%M-%S"


def format_timedelta(td):
  minutes, _ = divmod(td.seconds, 60)
  hours, minutes = divmod(minutes, 60)
  return f"{td.days}d {hours:02d}h {minutes:02d}m"


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


def get_entries_at(path):
  return sorted(path.glob("*.entry"))


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


def select_entry():
  """
  Displays a list of all entries and prompts user to select one. If the user inputs an exit command, None is returned.
  """
  while True:
    entries = list_entries(ENTRIES_PATH, True)
    user_input = input(
        "Input the ID number of an entry or enter 'q' to exit: ").lower()
    if user_input in EXIT_COMMANDS:
      break

    entry_id = None
    try:
      entry_id = int(user_input) - 1
    except:
      click.echo("Invalid ID!\n")
      continue
    if entry_id < 0 or entry_id >= len(entries):
      click.echo("Invalid ID!\n")
      continue

    return entries[entry_id]


@click.group()
def cli():
  """
  Encrypted Journal
  """
  # Create data directory if it doesn't already exist
  if not DATA_PATH.exists():
    DATA_PATH.mkdir()


@cli.command(name="info")
def info_cmd():
  """
  Print info about the current ejournal
  """
  entries = get_entries_at(ENTRIES_PATH)
  deltas = []
  for i in range(len(entries)-1):
    e0 = entries[i]
    e1 = entries[i+1]
    d = datetime.datetime.strptime(e1.stem, ENTRY_NAME_FORMAT) - \
        datetime.datetime.strptime(e0.stem, ENTRY_NAME_FORMAT)
    deltas.append(d.total_seconds())
  d_avg = None if len(deltas) == 0 else datetime.timedelta(seconds=sum(deltas) / len(deltas))

  click.echo(f"Password set: {PASSWORD_KEY_PATH.exists()}")
  click.echo(f"Entries path: {ENTRIES_PATH.resolve()}")
  click.echo(f"Number of entries: {len(entries)}")
  click.echo(f"Avg time between entries: {'NA' if d_avg is None else format_timedelta(d_avg)}")
  # TODO: Show avg time for last week, month, year as well


@cli.command(name="list")
def list_cmd():
  """
  List all journal entries
  """
  list_entries(ENTRIES_PATH, False)


@cli.command(name="create")
@require_password
def create_cmd(pwd):
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

  # Entry file will be of format YYYY-MM-DD_HH-MM-SS.entry
  now = datetime.datetime.utcnow().strftime(ENTRY_NAME_FORMAT)
  entry_name = str(now).replace(':', '-')
  new_entry_path = ENTRIES_PATH.joinpath(entry_name + '.entry')

  if new_entry_path.is_file():
    click.echo(
        f"Unable to save entry. There's already an entry with the name '{entry_name}' in {ENTRIES_PATH}")
    return

  # Encrypt text and save to file
  encrypted = encryption.encrypt_from_password(entry, pwd)
  new_entry_path.write_bytes(encrypted)

  click.echo(
      f"New encrypted entry successfully created at:\n{new_entry_path}")


@cli.command(name="edit")
@require_password
def edit_cmd(pwd):
  """
  Edit an existing journal entry. Overwrites data in original entry.
  """
  click.echo("Pick an entry to edit:\n")
  entry_path = select_entry()
  if entry_path is None:
    return

  try:
    entry_bytes = entry_path.read_bytes()
  except:
    click.echo(
        "ERROR Unable to open entry. Something might be wrong with the file\n")
    return
  try:
    orig_contents = encryption.decrypt_from_password(entry_bytes, pwd)
  except:
    click.echo(
        "ERROR Failed to decrypt entry file. Make sure you entered the correct password\n")
    return

  updated_contents = click.edit(text=orig_contents, require_save=True)
  if updated_contents is None:
    # File was not edited
    click.echo(f"\nNo changes were made to entry '{entry_path.name}'")
    return

  # Encrypt new text and overwrite original
  encrypted = encryption.encrypt_from_password(updated_contents, pwd)
  entry_path.write_bytes(encrypted)

  click.echo(f"\nChanges to entry '{entry_path.name} saved successfully!")


@cli.command(name="read")
@require_password
def read_cmd(pwd):
  """
  Decrypt and read a journal entry
  """
  while True:
    click.echo("Pick an entry to read:\n")
    entry_path = select_entry()
    if entry_path is None:
      break

    try:
      entry_bytes = entry_path.read_bytes()
    except:
      click.echo(
          "ERROR Unable to open entry. Something might be wrong with the file\n")
      continue

    try:
      contents = encryption.decrypt_from_password(entry_bytes, pwd)
    except:
      click.echo(
          "ERROR Failed to decrypt entry file. Make sure you entered the correct password\n")
      continue

    click.edit(
        text="NOTE: Modifying this file will NOT affect the actual entry. This file will be deleted once you exit the editor."
        + "\n------------------------------------\n\n" + contents)
