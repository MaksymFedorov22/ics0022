# Checkpoint 2 progress note

## Implemented

1. **Basic vault storage**
   - One vault file per user: `data/vaults/<username>.vault`
   - Commands: `add`, `list`, `get <id>`, `delete <id>`
   - Atomic saves, files `0600`, directory `0700`
2. **Credentials encrypted at rest**
   - Argon2id key derivation with a per-vault salt
   - XChaCha20-Poly1305 with a new nonce on every save; header authenticated
3. **Master password authentication**
   - Stored only as an Argon2id hash in `data/users.dat`; minimum 12 characters
   - Vault decrypted only after the hash check succeeds; generic "Login failed."
4. **Interface never prints passwords**
   - Password input with echo off
   - `list` shows id, site and username only
   - `get` copies to the clipboard, never prints
5. **Build and run instructions**
   - README covers setup on Ubuntu 24.04 (WSL2) and the build steps
   - Verified on a clean Ubuntu 24.04 environment

## Planned for Checkpoint 3

- `update` command
- Locked memory for secrets, core dumps disabled
- Login lockout, auto-lock, clipboard auto-clear
- Full input validation, structured logging, test suite
