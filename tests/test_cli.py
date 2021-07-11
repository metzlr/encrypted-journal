import unittest
import journal.encryption as encryption
from io import StringIO
from journal import cli
from unittest.mock import patch, Mock

class TestEncryption(unittest.TestCase):

  ctx = None
  
  @classmethod
  def setUpClass(cls):
    cls.ctx.obj = {}
    cls.ctx.obj["DATA_PATH"] = "./data/"
  
  @classmethod
  def tearDownClass(cls):
    cls.ctx = None

  @patch("journal.cli.os.listdir")
  @patch("journal.cli.os.path.isfile")
  @patch("journal.cli.os.path.isdir")
  @patch("sys.stdout", new_callable = StringIO)
  def test_list_entries(self, mock_stdout, isdir_mock, isfile_mock, listdir_mock):
    path = "./entries/"
    listdir_mock.return_value = ['entry1.entry', 'entry3.txt.entry']
    isfile_mock.return_value = True
    isdir_mock.return_value = True

    list_entries = cli.list_entries(path, False)
    expected_out = "\nENTRY NAME" + \
    "\n--------------------------------------------" + \
    "\nentry1.entry\nentry3.txt.entry\n"

    expected_out += "\nID\tENTRY NAME" + \
    "\n--------------------------------------------" + \
    "\n0\tentry1.entry\n1\tentry3.txt.entry\n"
    list_entries = cli.list_entries(path, True)
    self.assertListEqual(list_entries, ['entry1.entry', 'entry3.txt.entry'])
    actual = mock_stdout.getvalue()
    self.assertEqual(mock_stdout.getvalue(), expected_out, msg=actual)
