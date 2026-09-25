# pwman: Secure Password Manager

Semester project for ICS0022 Secure Programming, TalTech.

## Scope

A command-line password manager in C++17 that lets multiple local users store credentials in an encrypted vault. Each user has a master password (stored only as an Argon2id hash) and a separate vault encrypted with XChaCha20-Poly1305. Passwords are never displayed in cleartext and are wiped from memory after use.

See [DESIGN.md](docs/DESIGN.md) for the architecture and threat model.

## Planned commands

Start the program with `./pwman`. Before login:

| Command | Description |
|---|---|
| `register` | Create a new user and master password |
| `login` | Unlock your vault |
| `exit` | Quit |

After login:

| Command | Description |
|---|---|
| `add` | Add a credential (site, username, password, notes) |
| `list` | List stored entries (site and username only) |
| `get <id>` | Copy the password to the clipboard (auto-cleared) |
| `update <id>` | Update an entry |
| `delete <id>` | Delete an entry |
| `logout` | Lock the vault and return to the login prompt |

## Build and run

Requirements: CMake 3.16+, a C++17 compiler, libsodium, nlohmann/json.

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake libsodium-dev nlohmann-json3-dev

git clone <repository-url>
cd pwman
cmake -B build
cmake --build build
./build/pwman
```

## Status

Checkpoint 1: design and repository setup. Implementation starts in the next checkpoint.
