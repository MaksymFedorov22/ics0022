#include "crypto.h"

#include <cstdint>
#include <cstring>

namespace
{

// Vault header: magic(4) | version(1) | opslimit(8) | memlimit(8) | salt(16) | nonce(24)
const unsigned char MAGIC[4] = {'P', 'M', 'V', '1'};
constexpr unsigned char VERSION = 1;
constexpr size_t SALT_OFFSET = 4 + 1 + 8 + 8;
constexpr size_t NONCE_OFFSET = SALT_OFFSET + crypto_pwhash_SALTBYTES;
constexpr size_t HEADER_BYTES = NONCE_OFFSET + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr size_t TAG_BYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;

// Takes a 64-bit value and writes it to p as 8 little-endian bytes.
void put_u64(unsigned char* p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        p[i] = static_cast<unsigned char>(v >> (8 * i));
    }
}

// Takes 8 little-endian bytes at p and returns them as a 64-bit value.
uint64_t get_u64(const unsigned char* p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
    {
        v = (v << 8) | p[i];
    }
    return v;
}

// Takes a password and the salt and limits already in k, and fills k.key; returns false on failure.
bool derive_key(VaultKey& k, const std::string& password)
{
    return crypto_pwhash(k.key, sizeof k.key, password.data(), password.size(), k.salt, k.opslimit, k.memlimit, crypto_pwhash_ALG_ARGON2ID13) == 0;
}

}  // namespace

// Takes a password and returns its Argon2id hash string, or an empty string on failure.
std::string hash_password(const std::string& password)
{
    char out[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(out, password.data(), password.size(), crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
        return "";
    }
    return out;
}

// Takes a stored hash and a password and returns true if the password matches the hash.
bool verify_password(const std::string& hash, const std::string& password)
{
    return crypto_pwhash_str_verify(hash.c_str(), password.data(), password.size()) == 0;
}

// Takes a password and fills the key using a fresh random salt; returns false on failure.
bool new_vault_key(VaultKey& k, const std::string& password)
{
    randombytes_buf(k.salt, sizeof k.salt);
    k.opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    k.memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
    return derive_key(k, password);
}

// Takes a key and plaintext and returns the encrypted vault file bytes (header followed by ciphertext).
std::vector<unsigned char> seal_vault(const VaultKey& k, const std::string& plaintext)
{
    std::vector<unsigned char> out(HEADER_BYTES + plaintext.size() + TAG_BYTES);
    unsigned char* p = out.data();
    std::memcpy(p, MAGIC, sizeof MAGIC);
    p[4] = VERSION;
    put_u64(p + 5, k.opslimit);
    put_u64(p + 13, k.memlimit);
    std::memcpy(p + SALT_OFFSET, k.salt, sizeof k.salt);
    randombytes_buf(p + NONCE_OFFSET, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    crypto_aead_xchacha20poly1305_ietf_encrypt(p + HEADER_BYTES, nullptr, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), p, HEADER_BYTES, nullptr, p + NONCE_OFFSET, k.key);
    return out;
}

// Takes a password and vault file bytes, fills the key and the decrypted plaintext; returns false on wrong password or tampering.
bool open_vault(VaultKey& k, const std::string& password, const std::vector<unsigned char>& file, std::string& plaintext)
{
    if (file.size() < HEADER_BYTES + TAG_BYTES)
    {
        return false;
    }
    const unsigned char* p = file.data();
    if (std::memcmp(p, MAGIC, sizeof MAGIC) != 0 || p[4] != VERSION)
    {
        return false;
    }

    // The header is only authenticated after decryption, so bound the KDF
    // parameters first to stop a tampered file from requesting huge resources.
    k.opslimit = get_u64(p + 5);
    k.memlimit = get_u64(p + 13);
    if (k.opslimit < crypto_pwhash_OPSLIMIT_MIN || k.opslimit > crypto_pwhash_OPSLIMIT_SENSITIVE || k.memlimit < crypto_pwhash_MEMLIMIT_MIN || k.memlimit > crypto_pwhash_MEMLIMIT_SENSITIVE)
    {
        return false;
    }
    std::memcpy(k.salt, p + SALT_OFFSET, sizeof k.salt);
    if (!derive_key(k, password))
    {
        return false;
    }

    size_t clen = file.size() - HEADER_BYTES;
    plaintext.assign(clen - TAG_BYTES, '\0');
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*>(plaintext.data()), nullptr, nullptr, p + HEADER_BYTES, clen, p, HEADER_BYTES, p + NONCE_OFFSET, k.key) != 0)
    {
        sodium_memzero(k.key, sizeof k.key);
        plaintext.clear();
        return false;
    }
    return true;
}
