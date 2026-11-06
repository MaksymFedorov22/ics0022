#include <sodium.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <memory>
#include <sstream>

#include "crypto.h"
#include "storage.h"
#include "users.h"
#include "vault.h"

namespace
{

// Holds the logged-in user, the vault key and the decrypted entries; the entries are wiped on destruction.
struct Session
{
    std::string username;
    VaultKey key;
    std::vector<Entry> entries;

    ~Session()
    {
        wipe_entries(entries);
    }
};

// Takes a prompt, shows it and reads one line of input into out; returns false at end of input.
bool read_line(const std::string& prompt, std::string& out)
{
    std::cout << prompt << std::flush;
    return static_cast<bool>(std::getline(std::cin, out));
}

// Takes a prompt, shows it and reads one line with terminal echo turned off into out; returns false at end of input.
bool read_secret(const std::string& prompt, std::string& out)
{
    std::cout << prompt << std::flush;
    termios old{};
    bool tty = tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty)
    {
        termios noecho = old;
        noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);
    }
    bool ok = static_cast<bool>(std::getline(std::cin, out));
    if (tty)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        std::cout << '\n';
    }
    return ok;
}

// Takes text and copies it to the clipboard through the input of wl-copy, xclip or clip.exe; returns false if none of them works.
bool copy_to_clipboard(const std::string& text)
{
    for (const char* cmd : {"wl-copy", "xclip -selection clipboard", "clip.exe"})
    {
        FILE* pipe = popen((std::string(cmd) + " >/dev/null 2>&1").c_str(), "w");
        if (!pipe)
        {
            continue;
        }
        fwrite(text.data(), 1, text.size(), pipe);
        if (pclose(pipe) == 0)
        {
            return true;
        }
    }
    return false;
}

// Takes whether a user is logged in and prints the commands available in that state.
void print_help(bool logged_in)
{
    if (!logged_in)
    {
        std::cout << "Commands: register, login, help, exit\n";
    }
    else
    {
        std::cout << "Commands: add, list, get <id>, delete <id>, logout, help, exit\n";
    }
}

// Asks for a username and master password and registers the new user.
void do_register()
{
    std::string username, password, repeat;
    if (!read_line("Username: ", username))
    {
        return;
    }
    if (!valid_username(username))
    {
        std::cout << "Username must be 3-32 characters: letters, digits or underscore.\n";
        return;
    }
    if (user_exists(username))
    {
        std::cout << "Username is already taken.\n";
        return;
    }
    if (read_secret("Master password: ", password) && read_secret("Repeat master password: ", repeat))
    {
        if (password.size() < MIN_MASTER_PASSWORD)
        {
            std::cout << "Master password must be at least " << MIN_MASTER_PASSWORD << " characters.\n";
        }
        else if (password != repeat)
        {
            std::cout << "Passwords do not match.\n";
        }
        else if (register_user(username, password))
        {
            std::cout << "User registered. You can now log in.\n";
        }
        else
        {
            std::cout << "Registration failed.\n";
        }
    }
    wipe(password);
    wipe(repeat);
}

// Asks for a username and master password and returns an unlocked session, or nullptr if login fails.
std::unique_ptr<Session> do_login()
{
    std::string username, password;
    if (!read_line("Username: ", username))
    {
        return nullptr;
    }
    auto session = std::make_unique<Session>();
    bool ok = read_secret("Master password: ", password) && valid_username(username) && login_user(username, password, session->key, session->entries);
    wipe(password);
    if (!ok)
    {
        std::cout << "Login failed.\n";
        return nullptr;
    }
    session->username = username;
    std::cout << "Vault unlocked (" << session->entries.size() << " entries).\n";
    return session;
}

// Takes the session, asks for the new entry's fields, adds the entry and saves the vault.
void do_add(Session& s)
{
    Entry e;
    if (!read_line("Site: ", e.site) || !read_line("Username: ", e.username) || !read_secret("Password: ", e.password) || !read_line("Notes: ", e.notes))
    {
        return;
    }
    if (e.site.empty() || e.password.empty())
    {
        std::cout << "Site and password are required.\n";
        wipe(e.password);
        return;
    }
    e.id = 1;
    for (const Entry& existing : s.entries)
    {
        e.id = std::max(e.id, existing.id + 1);
    }
    s.entries.push_back(e);
    wipe(e.password);
    if (save_vault(s.username, s.key, s.entries))
    {
        std::cout << "Entry " << s.entries.back().id << " added.\n";
    }
    else
    {
        std::cout << "Could not save the vault.\n";
    }
}

// Takes the session and prints the id, site and username of every entry (never the password).
void do_list(const Session& s)
{
    if (s.entries.empty())
    {
        std::cout << "Vault is empty.\n";
        return;
    }
    for (const Entry& e : s.entries)
    {
        std::cout << e.id << "\t" << e.site << "\t" << e.username << "\n";
    }
}

// Takes the session and an id string and returns an iterator to the matching entry, or entries.end() if the id is invalid or not found.
std::vector<Entry>::iterator find_entry(Session& s, const std::string& arg)
{
    int id = 0;
    auto [end, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), id);
    if (arg.empty() || ec != std::errc() || end != arg.data() + arg.size())
    {
        return s.entries.end();
    }
    for (auto it = s.entries.begin(); it != s.entries.end(); ++it)
    {
        if (it->id == id)
        {
            return it;
        }
    }
    return s.entries.end();
}

// Takes the session and an id string and copies that entry's password to the clipboard.
void do_get(Session& s, const std::string& arg)
{
    auto it = find_entry(s, arg);
    if (it == s.entries.end())
    {
        std::cout << "No such entry.\n";
    }
    else if (copy_to_clipboard(it->password))
    {
        std::cout << "Password for " << it->site << " copied to clipboard.\n";
    }
    else
    {
        std::cout << "Clipboard is not available (install wl-copy or xclip).\n";
    }
}

// Takes the session and an id string, removes that entry and saves the vault.
void do_delete(Session& s, const std::string& arg)
{
    auto it = find_entry(s, arg);
    if (it == s.entries.end())
    {
        std::cout << "No such entry.\n";
        return;
    }
    wipe(it->password);
    s.entries.erase(it);
    if (save_vault(s.username, s.key, s.entries))
    {
        std::cout << "Entry deleted.\n";
    }
    else
    {
        std::cout << "Could not save the vault.\n";
    }
}

}  // namespace

// Initialises libsodium and the data directory, then runs the command loop until exit.
int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Failed to initialise.\n";
        return 1;
    }
    std::signal(SIGPIPE, SIG_IGN);  // a missing clipboard tool must not kill the process
    if (!ensure_data_dirs())
    {
        std::cerr << "Cannot access the data directory.\n";
        return 1;
    }

    std::unique_ptr<Session> session;
    print_help(false);
    std::string line;
    while (read_line(session ? session->username + "> " : "pwman> ", line))
    {
        std::istringstream in(line);
        std::string cmd, arg;
        in >> cmd >> arg;
        if (cmd.empty())
        {
            continue;
        }

        if (cmd == "exit")
        {
            break;
        }
        if (cmd == "help")
        {
            print_help(session != nullptr);
        }
        else if (!session)
        {
            if (cmd == "register")
            {
                do_register();
            }
            else if (cmd == "login")
            {
                session = do_login();
            }
            else
            {
                std::cout << "Unknown command. Type 'help'.\n";
            }
        }
        else
        {
            if (cmd == "add")
            {
                do_add(*session);
            }
            else if (cmd == "list")
            {
                do_list(*session);
            }
            else if (cmd == "get")
            {
                do_get(*session, arg);
            }
            else if (cmd == "delete")
            {
                do_delete(*session, arg);
            }
            else if (cmd == "logout")
            {
                session.reset();
                std::cout << "Vault locked.\n";
            }
            else
            {
                std::cout << "Unknown command. Type 'help'.\n";
            }
        }
    }
    return 0;
}
