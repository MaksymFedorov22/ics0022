#pragma once

#include <sodium.h>

#include <string>
#include <vector>

// Holds the vault key together with the salt and KDF limits used to derive it; the key is wiped on destruction.
struct VaultKey
{
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned long long opslimit = 0;
    size_t memlimit = 0;

    ~VaultKey()
    {
        sodium_memzero(key, sizeof key);
    }
};

// Takes a string, overwrites its contents with zeros and leaves it empty.
inline void wipe(std::string& s)
{
    sodium_memzero(s.data(), s.size());
    s.clear();
}

// Takes a password and returns its Argon2id hash string, or an empty string on failure.
std::string hash_password(const std::string& password);

// Takes a stored hash and a password and returns true if the password matches the hash.
bool verify_password(const std::string& hash, const std::string& password);

// Takes a password and fills the key using a fresh random salt; returns false on failure.
bool new_vault_key(VaultKey& key, const std::string& password);

// Takes a key and plaintext and returns the encrypted vault file bytes (header followed by ciphertext).
std::vector<unsigned char> seal_vault(const VaultKey& key, const std::string& plaintext);

// Takes a password and vault file bytes, fills the key and the decrypted plaintext; returns false on wrong password or tampering.
bool open_vault(VaultKey& key, const std::string& password, const std::vector<unsigned char>& file, std::string& plaintext);
