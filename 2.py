import secrets, string, random

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

def generate_password(length):
    if length < 4:
        raise ValueError("length must be at least 4")
    parts = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SYMBOLS)
    ]
    all_chars = string.ascii_letters + string.digits + SYMBOLS
    parts += [secrets.choice(all_chars) for _ in range(length - 4)]
    random.SystemRandom().shuffle(parts)
    return ''.join(parts)

if __name__ == "__main__":
    print(generate_password(12))

if __name__ == "__main__":
    import unittest

    class TestPasswordGenerator(unittest.TestCase):
        def test_length(self):
            pwd = generate_password(12)
            self.assertEqual(len(pwd), 12)

        def test_contains_upper_lower_digit_symbol(self):
            pwd = generate_password(16)
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(c in SYMBOLS for c in pwd))

        def test_too_short_raises(self):
            with self.assertRaises(ValueError):
                generate_password(3)

    unittest.main()
