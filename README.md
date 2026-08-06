# Vault Command Line Project

Hello and welcome to the vault!

This program creates encrypted vaults for users.
When you use vault, you can create a username
and password for each individual vault you want!

Each vault is encrypted with AES-256-GCM, and the key for it is
derived from your master password with PBKDF2-HMAC-SHA256. All the
data within your vaults is encrypted and cleaned.

Every one of those primitives is written from scratch in this
repository — no OpenSSL, no libsodium.

## Building

Needs `gcc` and Linux (it uses `getrandom`, `termios` and `poll`).

```
make              # builds ./vault
make clean        # removes build artifacts
sudo make install # copies vault to /usr/local/bin
```

## Using it

```
./vault init      # create a vault, prompts for a username and password
./vault login     # unlock a vault and start a session
./vault close     # delete a vault, after confirming the password
```

Once you are logged in you get a prompt, and these commands:

| command   | what it does                                  |
| --------- | --------------------------------------------- |
| `help`    | show the command list                         |
| `add`     | store a new site, username and password       |
| `get`     | show the entries for a site, password included|
| `list`    | show every site and username, passwords hidden|
| `replace` | change the password on an existing entry       |
| `remove`  | delete an entry                                |
| `exit`    | leave the session                              |

A short session looks like this:

```
$ ./vault login
Username: tyson
Password:

Type 'help' for a list of commands

tyson@vault> add

Site: github
User: mrbakesfps
Pass:
Password added to vault successfully!

tyson@vault> list

Site            User            Password
----            ----            --------
github          mrbakesfps      ********

1 of 256 entries used.

tyson@vault> exit
```

Your master password is asked for once, at login, because deriving the
key is deliberately slow. The session then locks itself after five
minutes with no input, so an unattended terminal does not stay unlocked.

## Where your vault lives

```
~/.config/vault/vault.<username>.bin
```

The directory is created `0700` and the file `0600`, so nobody else on
the machine can read it. Writes go to a temporary file that is fully
flushed to disk before it replaces the real one, so an interrupted or
failed write leaves your existing vault untouched.

## How it works

| piece            | what is used                                          |
| ---------------- | ----------------------------------------------------- |
| key derivation   | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt   |
| encryption       | AES-256-GCM, fresh 12-byte nonce on every write        |
| authentication   | 16-byte GCM tag, covering the file header as well      |

A wrong master password and a damaged file are the same thing to the
tag check, so both come back as an authentication failure. The
implementations are checked against published test vectors — SHA-256,
HMAC-SHA256 from RFC 4231, PBKDF2-HMAC-SHA256, and NIST AES-256-GCM.

## Limits

- 256 entries per vault, with a warning from 230 onward
- Site, username and password fields hold up to 127 bytes each,
  and cannot contain tabs or newlines
- Vault usernames may use letters, digits, `-` and `_`

## A word of warning

This is a learning project. The cryptography here is written from
scratch by hand, and while it matches its test vectors, it has not been
audited and it makes no attempt to defend against an attacker who can
run code on your machine.

Please enjoy it, read it, and take it apart — but keep your real
passwords in something that has been reviewed by people who do this for
a living.

Thank you for choosing Vault!

--Tyson Koopman-Baker
