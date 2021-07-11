import unittest
import secrets
import journal.encryption as encryption

class TestEncryption(unittest.TestCase):

  def setup(self):
    pass

  def test_get_key(self):
    # Ensure keys are consistent
    salt = secrets.token_bytes(32)
    key1 = encryption.get_key("Somepassword".encode("utf-8"), salt, 100000)
    key2 = encryption.get_key("Somepassword".encode("utf-8"), salt, 100000)
    self.assertEqual(key1, key2)

    key2 = encryption.get_key("Somepassword".encode("utf-8"), salt, 10)
    self.assertNotEqual(key1, key2)

    key2 = encryption.get_key("Somepassword2".encode("utf-8"), salt, 100000)
    self.assertNotEqual(key1, key2)

  def test_encrypt_and_decrypt(self):
    message = "This is a message"
    encrypted = encryption.encrypt_string(message, "somepassword")
    decrypted = encryption.decrypt_bytes(encrypted, "somepassword")
    self.assertEqual(message, decrypted)