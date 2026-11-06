#pragma once

#include <string>
#include <vector>

#include "crypto.h"
#include "vault.h"

constexpr size_t MIN_MASTER_PASSWORD = 12;

// Takes a username and returns true if it is 3-32 letters, digits or underscores (safe to use as a file name).
bool valid_username(const std::string& username);

// Takes a username and returns true if it is registered in users.dat.
bool user_exists(const std::string& username);

// Takes a username and master password, stores the password hash in users.dat and creates an empty vault; returns false on failure.
bool register_user(const std::string& username, const std::string& password);

// Takes a username and master password, checks the password against the stored hash and then fills the key and entries from the vault; returns false on failure.
bool login_user(const std::string& username, const std::string& password, VaultKey& key, std::vector<Entry>& entries);
