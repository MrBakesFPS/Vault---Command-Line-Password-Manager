# Vault Program

A command-line password vault written in C, implementing its own crypto
primitives from scratch (no OpenSSL/libsodium) as a learning project.

## Build & Run
- `make` — builds the `vault` binary from the tracked `.o` files
- `make clean` — removes build artifacts
- `make install` — copies `vault` to `/usr/local/bin`
- Compiler: gcc, `-std=gnu99 -Wall -Wextra` (keep new code warning-clean)

## Usage
- `./vault init` — create a new vault (prompts for username/password)
- `./vault login` — log into an existing vault, then drop into an
  interactive session (`help` lists in-session commands: list, get,
  addEntry, replaceEntry, removeEntry, etc.)
- `./vault close` — delete a vault (requires password confirmation)

## File Layout
- `main.c` — CLI entry point, argument parsing, login session loop
- `vault.c` / `vault.h` — vault file format, read/write, entry
  add/remove/replace/list/get, `VaultStatus` error enum
- `aes.c` / `aes.h` — AES-GCM encrypt/decrypt (hand-rolled)
- `passHash.c` / `passHash.h` — PBKDF2 key derivation + HMAC-SHA256
  (hand-rolled)

## Vault File Format
Files are written with a `VLT1` magic + 2-byte version, 16-byte salt,
12-byte nonce, 16-byte GCM tag, then AES-GCM ciphertext of the
serialized `VaultItems` (site/user/pass, 128 bytes each). See
`writeVault`/`readVault`/`parse`/`serializeEntries` in vault.h for the
exact contract.

## Conventions
- Functions return `VaultStatus` (`VAULT_OK` = 0, negative = specific
  error); check and propagate rather than exiting inline where possible.
- Header files carry full doc comments per function (params + possible
  return codes) — match that style for new public functions.
- Passwords/secrets are read via `disable_echo()`/`enable_echo()`
  (termios) — never print or log them.

## Notes
- This is an educational/from-scratch crypto implementation, not
  audited — treat security review suggestions here as learning
  exercises, not production hardening advice.
- Build artifacts (`*.o`, `vault` binary) are currently committed to
  git — be aware `make` will overwrite them.
