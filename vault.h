/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			vault.h
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the vault implementation file
===================================================================== */

#ifndef VAULT_H
#define VAULT_H

// Enumerator for the type of vault errors
typedef enum {
    VAULT_OK = 0,
    VAULT_ERR_NOT_FOUND = -1,
    VAULT_ERR_AUTH = -2,
    VAULT_ERR_ITEM = -3,
    VAULT_ERR_FULL = -4,
    VAULT_ERR_FIELD_LEN = -5,
    VAULT_ERR_FIELD_CHAR = -6,
    VAULT_ERR_IO = -7,
    VAULT_ERR_INTERNAL = -8,
} VaultStatus;

// Most entries a vault can hold. addEntry refuses to go past this with
// VAULT_ERR_FULL.
#define VAULT_MAX_ITEMS 256

// Entry count at which callers should start warning the user that the
// vault is filling up (90% of capacity).
#define VAULT_WARN_ITEMS ((VAULT_MAX_ITEMS * 9) / 10)

/*
* A structure of vault data containing site, user and password data
*/
struct VaultItems
{
	char site[128];
	char user[128];
	char pass[128];
};

/*
* An unlocked vault. Holds the AES key derived from the master password
* so the (deliberately slow) key derivation runs once per login rather
* than once per command.
*
* Create with openSession, destroy with closeSession. Contains live key
* material: never log it, copy it, or let it outlive the login.
*/
typedef struct
{
	char username[128];
	uint32_t key[8];
} VaultSession;

/*
* Derives the vault key from the master password and verifies it by
* authenticating the stored vault. On success the session is ready to
* pass to the entry functions below; on failure it is left wiped.
*
* @param masterPass - The password the key is derived from
* @param username - The username for finding the vault
* @param session - The session being opened
*
* @return VAULT_ERR_NOT_FOUND
* @return VAULT_ERR_FIELD_LEN
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus openSession(const char* masterPass, const char* username, VaultSession* session);

/*
* Wipes the key material held by a session. Safe to call on a session
* that was never successfully opened.
*
* @param session - The session being closed
*/
void closeSession(VaultSession* session);

/*
* Removes the vault belonging to an open session
*
* @param session - The unlocked session whose vault is being deleted
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus closeVault(const VaultSession* session);

/*
* Initializes a new vault with a Usernamd and Master Password
*
* @param masterPass - The password used for decryption confirmation
* @param username - The username for finding the vault
*
* @return VAULT_ERR_FIELD_LEN
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus initVault(const char* masterPass, const char* username);

/*
* Replaces an entry's password
*
* @param site - The site being replaced
* @param user - The user being replaced
* @param newPass - The new password
* @param session - The unlocked session holding the vault key
*
* @return VAULT_ERR_FIELD_CHAR
* @return VAULT_ERR_FIELD_LEN
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_ITEM
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus replaceEntry(const char* site, const char* user, const char* newPass, const VaultSession* session);

/*
* Deletes an entry from a vault
*
* @param site - The site being removed from the entry
* @param user - The user being removed from the entry
* @param session - The unlocked session holding the vault key
*
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_ITEM
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus removeEntry(const char* site, const char* user, const VaultSession* session);

/*
* Adds an entry to the vault
*
* @param site - The site being added to the entry
* @param user - The user being added to the entry
* @param pass - The password being added to the entry
* @param session - The unlocked session holding the vault key
* @param countOut - Set to the entry count after the add, so callers can
*                   warn as the vault approaches VAULT_MAX_ITEMS. Only
*                   written on VAULT_OK. May be NULL.
*
* @return VAULT_ERR_FIELD_CHAR
* @return VAULT_ERR_FIELD_LEN
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_ITEM
* @return VAULT_ERR_FULL
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus addEntry(const char* site, const char* user, const char* pass, const VaultSession* session, size_t* countOut);

/*
* Prints the sites and usernames of all items in the vault
*
* @param session - The unlocked session holding the vault key
*
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_OK
*/
VaultStatus list(const VaultSession* session);

/*
* Prints the site, username, and password from a given site name
*
* @param site - The site given to find the password
* @param session - The unlocked session holding the vault key
*
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_ITEM
* @return VAULT_OK
*/
VaultStatus get(const char* site, const VaultSession* session);

/*
* Turns a vault of text into a list of vault items
*
* @param cipher - The text being read from
* @param cipLen - The text length
* @param vaultItems - The list of vault items being created
* @param maxItems - the max amount of items allowed in the list
*
* @return - The size of the vault
*/
size_t parse(uint8_t* cipher, size_t cipLen, struct VaultItems* vaultItems, size_t maxItems);

/*
* Turns an array of vault items into a uint8_t array for encrypting
*
* @param vaultItems - The site, user, and password list of items
* @param itemCount - The number of items in the list
* @param newLen - The byte count of the outgoing text
*
* @return - The string of text to be encrypted
*/
uint8_t* serializeEntries(struct VaultItems* vaultItems, size_t itemCount, size_t* newLen);

/*
* Writes a vault to disk. The file is created 0600, every write is
* checked, and the contents are fsynced before the function returns, so
* a successful return means the bytes are durably on disk. The file is
* removed on any failure.
*
* @param magic - The 4 byte vault code VLT1
* @param version - The 2 byte vault version 01
* @param salt - The 16 byte random password addon
* @param nonce - The 12 byte random password addon, changes often
* @param tag - The confirmation tag produced from read/write
* @param cipher - The cipher text being wrote to
* @param cipLen - The cipher length
* @param fileName - The temporary filename used as a file failsafe
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus writeVault(const uint8_t magic[4], const uint8_t version[2], const uint8_t salt[16], const uint8_t nonce[12], const uint8_t tag[16], const uint8_t* cipher, size_t cipLen, const char* fileName);

/*
* Reads from a vault based on the given username
*
* @param magic - The 4 byte vault code VLT1
* @param version - The 2 byte vault version 01
* @param salt - The 16 byte random password addon
* @param nonce - The 12 byte random password addon, changes often
* @param tag - The confirmation tag produced from read/write
* @param cipherOut - The cipher text being read
* @param cipLenOut - The cipher length
* @param username - The username being used to find the vault
*
* @return VAULT_ERR_NOT_FOUND
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus readVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t** cipherOut, size_t* cipLenOut, const char* username);

/*
* Produces a vault path for where to store your vault
* Path is determined by temp code and username
*
* @param dest - The destination path being created
* @param size - the size of the destination
* @param temp - The temp code where 1 = temp, 0 = not temp
* @param username - The username for the vault
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus vaultPath(char* dest, size_t size, int temp, const char* username);

/*
* Fills a buffer with a random byte string
*
* @param buf - The buffer for the random bytes
* @param len - The length of the buffer
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
VaultStatus randomBytes(uint8_t* buf, size_t len);

#endif
