# encrypted-journal

A CLI tool I made to learn more about cryptography. Allows you to create/read entries that are encrypted using a password.

## Install Instructions
1. Clone repository
2. Run `pip install --user .` from the repository root
3. Run `ejournal` to verify installation was successful

#### MacOS
If after installing, the `ejournal` command isn't working, ensure that you have `~/.local/bin` added your `PATH`

## Development
### Setup
1. Clone repository
2. Create and activate virtualenv
3. Navigate to the repository root
4. Run `pip install -r requirements.txt`
5. Run `pip install -e .` (with virtualenv activated)
6. Run `echo 'DEV=True' > .env`

### Running Unit Tests
Run `python -m unittest` from the repository root.

