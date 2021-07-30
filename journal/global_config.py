from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

DEFAULT_ITERATIONS = 100000
PWD_ITERATIONS = 500000
PWD_MIN_LENGTH = 8

PROD_DATA_PATH = Path.home().joinpath(".ejournal")
DEV_DATA_PATH = Path("dev-data")

DATA_PATH = None
if os.getenv("DEV", "False").lower() == "true":
  DATA_PATH = DEV_DATA_PATH
else:
  DATA_PATH = PROD_DATA_PATH

ENTRIES_PATH = DATA_PATH.joinpath("entries")
PASSWORD_KEY_PATH = DATA_PATH.joinpath("password.key")
PASSWORD_KEY_PATH.suffix
VERIFY_PASSWORD_MESSAGE = "This message will be encoded by the chosen password and used to verify that the correct password is being used."
