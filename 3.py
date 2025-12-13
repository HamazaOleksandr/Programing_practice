import math, sys

SYMBOLS = set("!@#$%^&*()-_=+[]{};:,.<>?/|\\")
COMMON_SEQS = ["1234","2345","3456","abcd","qwer","password","1111","0000","1212"]

def load_wordlist(path):
    s = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if w:
                s.add(w)
    return s

def estimate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in SYMBOLS for c in password): pool += len(SYMBOLS)
    if pool == 0: pool = 94
    return len(password) * math.log2(pool)

def contains_common_sequence(pw):
    pl = pw.lower()
    return any(seq in pl for seq in COMMON_SEQS)

def check_password(password, wordlist=None, min_len=8, entropy_thr=50.0):
    reasons = []
    pw = password or ""
    if wordlist and pw.lower() in wordlist:
        reasons.append("in_wordlist")
    if len(pw) < min_len:
        reasons.append("too_short")
    if not any(c.isupper() for c in pw):
        reasons.append("no_upper")
    if not any(c.islower() for c in pw):
        reasons.append("no_lower")
    if not any(c.isdigit() for c in pw):
        reasons.append("no_digit")
    if not any(c in SYMBOLS for c in pw):
        reasons.append("no_symbol")
    if contains_common_sequence(pw):
        reasons.append("common_sequence")
    entropy = estimate_entropy(pw)
    if entropy < entropy_thr:
        reasons.append("low_entropy")
    return (len(reasons) > 0, reasons, round(entropy,2))

def read_users_from_txt(path):
    users = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: 
                continue
            if "," in line:
                parts = line.split(",",1)
            elif ":" in line:
                parts = line.split(":",1)
            else:
                parts = line.split(None,1)
            username = parts[0].strip()
            password = parts[1].strip() if len(parts) > 1 else ""
            users.append({"username": username, "password": password})
    return users

def find_weak_passwords_from_files(users_path="user.txt", wordlist_path=None):
    users = read_users_from_txt(users_path)
    wl = load_wordlist(wordlist_path) if wordlist_path else None
    results = []
    for u in users:
        username = u.get("username","")
        password = u.get("password","")
        is_weak, reasons, entropy = check_password(password, wl)
        results.append({"username": username, "password": password, "is_weak": is_weak, "reasons": reasons, "entropy": entropy})
    return results

if __name__ == "__main__":
    users_path = "user.txt"
    wl_path = None
    if len(sys.argv) > 1:
        users_path = sys.argv[1]
    if len(sys.argv) > 2:
        wl_path = sys.argv[2]
    res = find_weak_passwords_from_files(users_path, wl_path)
    for r in res:
        print(f"{r['username']}\t{r['password']}\t{'WEAK' if r['is_weak'] else 'OK'}\t{','.join(r['reasons'])}\t{r['entropy']}")
