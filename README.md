# QingBruteForce

**QingBruteForce** is a lightweight, offline password search-space analyzer for Kali Linux and other Python 3 environments.

It helps you understand how password length and character variety affect the number of possible combinations and the theoretical time required to search that space.

> **Scope:** This project calculates search spaces and provides local password-strength guidance. It does not attempt logins, connect to websites, generate attack wordlists, or crack account passwords. Use it for learning and defensive password auditing.

## Features

- Supports password lengths from 1 to 20 characters for analysis.
- Character sets: lowercase, uppercase, digits, symbols, letters, alphanumeric, and printable ASCII.
- Custom character-set size calculations.
- Combination count using arbitrary-precision integers.
- Time estimates at a user-supplied hypothetical checking rate.
- Local password strength analysis without transmitting the password.
- No third-party Python dependencies.

## Requirements

- Python 3.9+
- Kali Linux, Debian, Ubuntu, macOS, or Windows

## Install on Kali Linux

```bash
sudo apt update
sudo apt install -y git python3
git clone https://github.com/qingremzy/QingBruteForce.git
cd QingBruteForce
```

## Usage

Show help:

```bash
python3 qingbruteforce.py --help
```

Calculate the search space for 12 characters drawn from lowercase, uppercase, digits, and symbols:

```bash
python3 qingbruteforce.py estimate --length 12 --charset all
```

Estimate a hypothetical search rate of one million checks per second:

```bash
python3 qingbruteforce.py estimate --length 12 --charset all --rate 1000000
```

Use a custom character set size (for example, 20 possible characters):

```bash
python3 qingbruteforce.py estimate --length 8 --charset-size 20
```

Analyze a password locally. Avoid putting a password into a shared terminal or shell history:

```bash
python3 qingbruteforce.py analyze
```

The analyzer prompts for the password without echoing it and does not save it.

## Important notes

- The time estimate is theoretical. Real checking rates vary enormously with the algorithm, hardware, and security controls.
- A large search space does not guarantee a strong password if it is reused, exposed, or predictable.
- Prefer long, unique passphrases generated and stored with a reputable password manager. Enable multi-factor authentication.
- Never test passwords against accounts or systems you do not own or have explicit permission to assess.

## License

MIT. See [LICENSE](LICENSE).
