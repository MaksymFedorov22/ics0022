#include "storage.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iterator>

namespace
{
const std::string DATA_DIR = "data";
}

// Creates the data/ and data/vaults/ directories (mode 0700) if they are missing; returns false on failure.
bool ensure_data_dirs()
{
    for (const std::string& dir : {DATA_DIR, DATA_DIR + "/vaults"})
    {
        if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
        {
            return false;
        }
    }
    return true;
}

// Returns the path of the users.dat file.
std::string users_path()
{
    return DATA_DIR + "/users.dat";
}

// Takes a username and returns the path of that user's vault file.
std::string vault_path(const std::string& username)
{
    return DATA_DIR + "/vaults/" + username + ".vault";
}

// Takes a file path and fills out with the file's contents; returns false if the file cannot be read.
bool read_file(const std::string& path, std::vector<unsigned char>& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), {});
    return !in.bad();
}

// Takes a file path and data and atomically replaces the file with that data (mode 0600); returns false on failure.
bool write_file_atomic(const std::string& path, const std::vector<unsigned char>& data)
{
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        return false;
    }

    size_t done = 0;
    bool ok = true;
    while (ok && done < data.size())
    {
        ssize_t n = write(fd, data.data() + done, data.size() - done);
        if (n > 0)
        {
            done += static_cast<size_t>(n);
        }
        else if (errno != EINTR)
        {
            ok = false;
        }
    }
    ok = ok && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || std::rename(tmp.c_str(), path.c_str()) != 0)
    {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}
