#pragma once

#include <string>
#include <vector>

#include "crypto.h"

// One stored credential.
struct Entry
{
    int id = 0;
    std::string site;
    std::string username;
    std::string password;
    std::string notes;
};

// Takes the owner's name, key and entries, and writes them as an encrypted vault file; returns false on failure.
bool save_vault(const std::string& owner, const VaultKey& key, const std::vector<Entry>& entries);

// Takes the owner's name and password, and fills the key and decrypted entries; returns false on wrong password, tampering or bad data.
bool load_vault(const std::string& owner, const std::string& password, VaultKey& key, std::vector<Entry>& entries);

// Takes a list of entries, overwrites all their fields with zeros and empties the list.
void wipe_entries(std::vector<Entry>& entries);
