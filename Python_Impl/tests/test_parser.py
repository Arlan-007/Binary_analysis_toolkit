import unittest
from src.parser.pe_parser import PEParser

class TestPEParser(unittest.TestCase):
    def setUp(self):
        self.parser = PEParser("samples/hello_world_32.exe")

    def test_magic_bytes(self):
        self.assertEqual(self.parser.get_magic_bytes(), b"MZ")

    def test_entry_point(self):
        expected_entry_point = 0x401000
        self.assertEqual(self.parser.get_entry_point(), expected_entry_point)

    def test_section_headers(self):
        sections = self.parser.get_section_names()
        self.assertIn(".text", sections)
        self.assertIn(".data", sections)
if __name__ == "__main__":
    unittest.main()