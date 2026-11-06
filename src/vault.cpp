#include "vault.h"

#include <nlohmann/json.hpp>

#include "storage.h"

using json = nlohmann::json;

// Takes an entry and fills j with its JSON object (used by nlohmann/json).
void to_json(json& j, const Entry& e)
{
    j = json{{"id", e.id}, {"site", e.site}, {"username", e.username}, {"password", e.password}, {"notes", e.notes}};
}

// Takes a JSON object and fills the entry from it; throws if a field is missing (used by nlohmann/json).
void from_json(const json& j, Entry& e)
{
    j.at("id").get_to(e.id);
    j.at("site").get_to(e.site);
    j.at("username").get_to(e.username);
    j.at("password").get_to(e.password);
    j.at("notes").get_to(e.notes);
}

// Takes the owner's name, key and entries, and writes them as an encrypted vault file; returns false on failure.
bool save_vault(const std::string& owner, const VaultKey& key, const std::vector<Entry>& entries)
{
    std::string plaintext = json(entries).dump();
    std::vector<unsigned char> file = seal_vault(key, plaintext);
    wipe(plaintext);
    return write_file_atomic(vault_path(owner), file);
}

// Takes the owner's name and password, and fills the key and decrypted entries; returns false on wrong password, tampering or bad data.
bool load_vault(const std::string& owner, const std::string& password, VaultKey& key, std::vector<Entry>& entries)
{
    std::vector<unsigned char> file;
    if (!read_file(vault_path(owner), file))
    {
        return false;
    }

    std::string plaintext;
    if (!open_vault(key, password, file, plaintext))
    {
        return false;
    }

    bool ok = true;
    try
    {
        entries = json::parse(plaintext).get<std::vector<Entry>>();
    }
    catch (const json::exception&)
    {
        ok = false;
    }
    wipe(plaintext);
    return ok;
}

// Takes a list of entries, overwrites all their fields with zeros and empties the list.
void wipe_entries(std::vector<Entry>& entries)
{
    for (Entry& e : entries)
    {
        wipe(e.site);
        wipe(e.username);
        wipe(e.password);
        wipe(e.notes);
    }
    entries.clear();
}
