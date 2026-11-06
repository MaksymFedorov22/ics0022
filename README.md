# pwman: Secure Password Manager

Semester project for ICS0022 Secure Programming, TalTech.

## Scope

A command-line password manager in C++17 that lets multiple local users store credentials in an encrypted vault. Each user has a master password (stored only as an Argon2id hash) and a separate vault encrypted with XChaCha20-Poly1305. Passwords are never displayed in cleartext and are wiped from memory after use.

See [DESIGN.md](docs/DESIGN.md) for the architecture and threat model.

## Build and run

Requirements: CMake 3.16+, a C++17 compiler, pkg-config, libsodium, nlohmann/json.

### Reference environment: Windows with WSL2 (Ubuntu 24.04)

The project is developed and tested on Ubuntu 24.04 LTS running in WSL2 on Windows, with these package versions: GCC 13.3, CMake 3.28, libsodium 1.0.18, nlohmann/json 3.11.3. To create the same environment on a Windows machine.

### Build steps (Debian/Ubuntu)

```bash
sudo apt install build-essential cmake pkg-config libsodium-dev nlohmann-json3-dev

git clone https://github.com/MaksymFedorov22/ics0022.git
cd ics0022
cmake -B build
cmake --build build
./build/pwman
```

The program stores its data in `./data/` relative to the directory it is started from (created automatically, mode `0700`):

- `data/users.dat`: one `username:<argon2id hash>` line per user
- `data/vaults/<username>.vault`: the user's encrypted vault

## Usage

Before login:

| Command | Description |
|---|---|
| `register` | Create a new user. Username: 3-32 characters `[A-Za-z0-9_]`; master password: at least 12 characters, typed twice |
| `login` | Unlock your vault with your master password |
| `help` | Show available commands |
| `exit` | Quit |

After login:

| Command | Description |
|---|---|
| `add` | Add a credential (site, username, password, notes). Site and password are required |
| `list` | List stored entries (id, site and username only) |
| `get <id>` | Copy the password to the clipboard |
| `delete <id>` | Delete an entry |
| `logout` | Lock the vault and return to the login prompt |
| `help` | Show available commands |
| `exit` | Lock the vault and quit |

Passwords are typed with terminal echo turned off and are never printed. `get` passes the password on standard input to the first clipboard tool that works: `wl-copy` (Wayland), `xclip` (X11) or `clip.exe` (WSL). If none is available, the password is not shown.

Example session:

```
pwman> register
Username: alice
Master password:
Repeat master password:
User registered. You can now log in.
pwman> login
Username: alice
Master password:
Vault unlocked (0 entries).
alice> add
Site: github.com
Username: alice_gh
Password:
Notes: work
Entry 1 added.
alice> list
1	github.com	alice_gh
alice> get 1
Password for github.com copied to clipboard.
alice> logout
Vault locked.
```

## Source layout

| File | Module |
|---|---|
| `src/main.cpp` | Interface: command loop, input with echo off, clipboard |
| `src/users.cpp` | User management: username rules, register, login |
| `src/crypto.cpp` | Encryption: Argon2id hashing and key derivation, vault encryption and decryption |
| `src/vault.cpp` | Vault entries and their JSON form, load and save |
| `src/storage.cpp` | Storage: data directories, file reads, atomic `0600` writes |

## Status

Checkpoint 2: core functionality implemented (register, login, encrypted vault, add/list/get/delete). See the [progress note](docs/Checkpoint%202%20Progress.md).

Planned for Checkpoint 3: `update`, locked memory for secrets (`sodium_malloc`), disabling core dumps, login delay and lockout, auto-lock, clipboard auto-clear, full input validation, structured logging and tests.
