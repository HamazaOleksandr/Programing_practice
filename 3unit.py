import unittest
import zipfile
import os

from weak_pw import load_wordlist_from_zip, find_weak_passwords



class TestWeakPasswords(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        #тестовий zip з wordlist
        cls.zip_name = "test_wordlist.zip"
        with zipfile.ZipFile(cls.zip_name, "w") as z:
            z.writestr("wordlist.txt", "123456\npassword\nqwerty\n")

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.zip_name)

    def test_load_wordlist_from_zip(self):
        passwords = load_wordlist_from_zip(self.zip_name)
        self.assertIn("123456", passwords)
        self.assertIn("password", passwords)
        self.assertNotIn("admin", passwords)

    def test_find_weak_passwords(self):
        users = {
            "user1": "123456",
            "user2": "StrongPass",
            "user3": "password"
        }

        weak_passwords = {"123456", "password"}
        result = find_weak_passwords(users, weak_passwords)

        self.assertEqual(len(result), 2)
        self.assertIn(("user1", "123456"), result)
        self.assertIn(("user3", "password"), result)


if __name__ == "__main__":
    unittest.main()
