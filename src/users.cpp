#include "users.h"

#include <sstream>

#include "storage.h"

namespace
{

// Takes a username and returns its stored hash from users.dat ("username:hash" lines), or an empty string if unknown.
std::string find_hash(const std::string& username)
{
    std::vector<unsigned char> data;
    if (!read_file(users_path(), data))
    {
        return "";
    }
    std::istringstream in(std::string(data.begin(), data.end()));
    std::string line;
    while (std::getline(in, line))
    {
        size_t sep = line.find(':');
        if (sep != std::string::npos && line.compare(0, sep, username) == 0 && sep == username.size())
        {
            return line.substr(sep + 1);
        }
    }
    return "";
}

}  // namespace

// Takes a username and returns true if it is 3-32 letters, digits or underscores (safe to use as a file name).
bool valid_username(const std::string& username)
{
    if (username.size() < 3 || username.size() > 32)
    {
        return false;
    }
    for (char c : username)
    {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
        {
            return false;
        }
    }
    return true;
}

// Takes a username and returns true if it is registered in users.dat.
bool user_exists(const std::string& username)
{
    return !find_hash(username).empty();
}

// Takes a username and master password, stores the password hash in users.dat and creates an empty vault; returns false on failure.
bool register_user(const std::string& username, const std::string& password)
{
    if (!valid_username(username) || user_exists(username))
    {
        return false;
    }

    std::string hash = hash_password(password);
    VaultKey key;
    if (hash.empty() || !new_vault_key(key, password))
    {
        return false;
    }
    if (!save_vault(username, key, {}))
    {
        return false;
    }

    std::vector<unsigned char> data;
    read_file(users_path(), data);  // missing file just means no users yet
    std::string line = username + ":" + hash + "\n";
    data.insert(data.end(), line.begin(), line.end());
    return write_file_atomic(users_path(), data);
}

// Takes a username and master password, checks the password against the stored hash and then fills the key and entries from the vault; returns false on failure.
bool login_user(const std::string& username, const std::string& password, VaultKey& key, std::vector<Entry>& entries)
{
    std::string hash = find_hash(username);
    if (hash.empty() || !verify_password(hash, password))
    {
        return false;
    }
    return load_vault(username, password, key, entries);
}
