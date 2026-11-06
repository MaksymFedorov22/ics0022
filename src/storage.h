#pragma once

#include <string>
#include <vector>

// Creates the data/ and data/vaults/ directories (mode 0700) if they are missing; returns false on failure.
bool ensure_data_dirs();

// Returns the path of the users.dat file.
std::string users_path();

// Takes a username and returns the path of that user's vault file.
std::string vault_path(const std::string& username);

// Takes a file path and fills out with the file's contents; returns false if the file cannot be read.
bool read_file(const std::string& path, std::vector<unsigned char>& out);

// Takes a file path and data and atomically replaces the file with that data (mode 0600); returns false on failure.
bool write_file_atomic(const std::string& path, const std::vector<unsigned char>& data);
