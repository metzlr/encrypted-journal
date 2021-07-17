import os
from pathlib import Path

DEFAULT_ITERATIONS = 100000
PWD_ITERATIONS = 500000
PWD_MIN_LENGTH = 8
PROD_DATA_PATH = Path.home().joinpath('.ejournal', 'data')
DEV_DATA_PATH = 'dev-data'
VERIFY_PWD_FILENAME = 'password.key'
VERIFY_PWD_MSG = "This message will be encoded by the chosen password and used to verify that the correct password is being used."
ENTRIES_PATH = 'entries'
