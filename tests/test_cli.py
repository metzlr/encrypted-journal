import unittest
from io import StringIO
from journal import cli
from unittest.mock import patch, MagicMock


class FakeContext:
  obj = {}


class TestCli(unittest.TestCase):

  ctx = None

  @classmethod
  def setUpClass(cls):
    cls.ctx = FakeContext()
    cls.ctx.obj["DATA_PATH"] = "./data/"

  @classmethod
  def tearDownClass(cls):
    cls.ctx = None

  @patch("sys.stdout", new_callable=StringIO)
  def test_list_entries(self, mock_stdout):
    file_mock1 = MagicMock()
    file_mock2 = MagicMock()

    file_mock1.__lt__.return_value = True
    file_mock2.__lt__.return_value = False

    file_mock1.is_file.return_value = True
    file_mock2.is_file.return_value = True

    file_mock1.name = "entry1.entry"
    file_mock2.name = "entry2.txt.entry"

    path_mock = MagicMock()
    path_mock.exists.return_value = True
    path_mock.glob.return_value = iter([file_mock1, file_mock2])

    list_entries = cli.list_entries(path_mock, False)
    path_mock.glob.return_value = iter([file_mock2, file_mock1])  # Reset
    list_entries = cli.list_entries(path_mock, True)

    expected_out = "ENTRY NAME" + \
        "\n--------------------------------------------" + \
        "\nentry1.entry\nentry2.txt.entry\n"

    expected_out += "ID\tENTRY NAME" + \
        "\n--------------------------------------------" + \
        "\n1\tentry1.entry\n2\tentry2.txt.entry\n"
    actual = mock_stdout.getvalue()

    self.assertListEqual(list_entries, [file_mock1, file_mock2])
    self.assertEqual(mock_stdout.getvalue(), expected_out, msg=actual)
