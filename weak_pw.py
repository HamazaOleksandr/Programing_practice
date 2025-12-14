import zipfile


def load_wordlist_from_zip(zip_path):
    passwords = set()

    with zipfile.ZipFile(zip_path, "r") as z:
        for name in z.namelist():
            with z.open(name) as f:
                for line in f:
                    passwords.add(line.decode("utf-8").strip())

    return passwords


def find_weak_passwords(users, weak_passwords):
    result = []

    for user, password in users.items():
        if password in weak_passwords:
            result.append((user, password))

    return result


def main():
    users = {
        "user1": "123456",
        "user2": "qwerty",
        "user3": "SaN01_(s123_)",
        "user4": "password"
    }

    weak_passwords = load_wordlist_from_zip("wordlist.zip")
    weak_users = find_weak_passwords(users, weak_passwords)

    if not weak_users:
        print("Слабких паролів не знайдено")
    else:
        print("Слабкі паролі:")
        for user, password in weak_users:
            print(f"{user} - {password}")


if __name__ == "__main__":
    main()
