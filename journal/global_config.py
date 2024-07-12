import os
from dotenv import load_dotenv
from pathlib import Path
from configparser import ConfigParser

load_dotenv()


PROD_DATA_PATH = Path.home().joinpath(".ejournal")
DEV_DATA_PATH = Path("dev-data")

DATA_PATH = None
if os.getenv("DEV", "False").lower() == "true":
  DATA_PATH = DEV_DATA_PATH
else:
  DATA_PATH = PROD_DATA_PATH

DATA_PATH.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = DATA_PATH.joinpath("config.ini")
config = ConfigParser()
# Create config file and populate it with default values if it doesn't exist
if not CONFIG_PATH.exists():
  config["DEFAULT"] = {
      "entries_path": DATA_PATH.joinpath("entries")
  }
  config["custom"] = {}
  config.write(CONFIG_PATH.open("w+"))
else:
  config.read(CONFIG_PATH)

ENTRIES_PATH = Path(config.get("custom", "entries_path"))

PASSWORD_KEY_PATH = DATA_PATH.joinpath("password.key")
PASSWORD_KEY_PATH.suffix
VERIFY_PASSWORD_MESSAGE = "This message will be encoded by the chosen password and used to verify that the correct password is being used."

DEFAULT_ITERATIONS = 100000
PWD_ITERATIONS = 500000
PWD_MIN_LENGTH = 8
