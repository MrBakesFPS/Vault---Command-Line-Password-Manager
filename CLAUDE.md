# Vault Program

A command-line password vault written in C, implementing its own crypto
primitives from scratch (no OpenSSL/libsodium) as a learning project.

## Build & Run
- `make` — compiles the sources into the `vault` binary
- `make clean` — removes build artifacts
- `make install` — copies `vault` to `/usr/local/bin`
- Compiler: gcc, `-std=gnu99 -Wall -Wextra` (keep new code warning-clean)

## Usage
- `./vault init` — create a new vault (prompts for username/password).
  Creates `~/.config/vault/` (0700) if it doesn't exist.
- `./vault login` — log into an existing vault, then drop into an
  interactive session (`help` lists in-session commands: list, get,
  add, remove, replace, exit)
- `./vault close` — delete a vault (requires password confirmation)

## Architecture
`openSession` derives the AES key from the master password once, at
login, and stores it in a `VaultSession` along with the username. Every
entry function takes that session rather than a password, so the
deliberately-slow PBKDF2 (600k iterations, ~2.9s) runs once per login
instead of once per command. `closeSession` wipes the key.

The tradeoff: the vault stays unlocked for the whole session rather
than re-authenticating per command. An idle timeout would be the
natural next step.

All vault I/O funnels through two private helpers in `vault.c`:
- `loadVault` — read, authenticate, decrypt, parse into `VaultItems`
- `saveVault` — serialize, fresh nonce, encrypt, write, commit

**New vault operations should go through these two.** They exist
because the read/derive/decrypt preamble was previously copy-pasted
across seven functions, which is how `closeVault` came to report a
wrong password as `VAULT_ERR_INTERNAL` while the other six returned
`VAULT_ERR_AUTH`.

## File Layout
- `main.c` — CLI entry point, argument parsing, login session loop
- `vault.c` / `vault.h` — `VaultSession`, vault file format, read/write,
  entry add/remove/replace/list/get, `VaultStatus` error enum
- `aes.c` / `aes.h` — AES-GCM encrypt/decrypt (hand-rolled)
- `passHash.c` / `passHash.h` — PBKDF2 key derivation + HMAC-SHA256
  (hand-rolled)

## Vault File Format
Files live at `~/.config/vault/vault.<username>.bin`, created 0600 in a
0700 directory. Layout is a `VLT1` magic + 2-byte version, 16-byte salt,
12-byte nonce, 16-byte GCM tag, then AES-GCM ciphertext of the
serialized `VaultItems` (site/user/pass, 128 bytes each), tab/newline
delimited. Magic + version are the GCM additional authenticated data.
See `writeVault`/`readVault`/`parse`/`serializeEntries` in vault.h for
the exact contract.

Writes go to a `.temp` sibling first: every `fwrite` is checked and
fsynced before `commitVault` renames it into place, so a failed write
leaves the existing vault untouched rather than truncating it. Don't
add a write path that skips this.

## Conventions
- Functions return `VaultStatus` (`VAULT_OK` = 0, negative = specific
  error); check and propagate rather than exiting inline where possible.
- Header files carry full doc comments per function (params + possible
  return codes) — match that style for new public functions.
- Passwords/secrets are read via `disable_echo()`/`enable_echo()`
  (termios) — never print or log them.
- Wipe key material with `explicit_bzero` before `free()` or before it
  goes out of scope. Multi-allocation functions use a single
  `goto cleanup` block so no error path can skip a wipe — follow that
  pattern rather than duplicating frees per branch.
- Library code returns status codes instead of printing; user-facing
  messages belong in `reportError` in `main.c`.

## Notes
- This is an educational/from-scratch crypto implementation, not
  audited — treat security review suggestions here as learning
  exercises, not production hardening advice.
- The primitives are verified against published test vectors
  (SHA-256, HMAC-SHA256 RFC 4231, PBKDF2-HMAC-SHA256, and NIST
  AES-256-GCM). If you touch `aes.c` or `passHash.c`, re-check them.
- Build artifacts (`*.o`, `vault`) are gitignored, not tracked.
- Build with optimization. `CFLAGS` carries `-O2` because the key
  derivation is 600k iterations of hand-rolled SHA-256; an unoptimized
  build is ~5x slower and dominates every other cost in the program.
  Benchmark before concluding anything about hashing performance, and
  benchmark at `-O2` — results at `-O0` do not carry over. `padMessage`
  is a worked example: allocating once instead of reallocating per byte
  is 13x faster in isolation and 18% faster end-to-end at `-O2`, but
  measurably *slower* at `-O0`.
- `aes.c` implements the forward cipher only. GCM is CTR-based, so it
  never runs AES decryption; the inverse cipher was removed as dead
  code. Don't re-add it unless something actually calls it.
- `gf128` is written branch-free on purpose: the GHASH subkey H is
  secret, so every decision uses a 0 / all-ones mask rather than an
  `if`. Keep it that way, and re-check the disassembly for
  data-dependent jumps if you touch it.
- Known rough edges, not yet addressed: `verifyPassword` in `main.c`
  only reads a hidden line and verifies nothing, despite the name.
