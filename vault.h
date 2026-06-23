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
 * Removes a current vault based on the username and passwords provided
 *
 * @param masterPass - The password used for decryption confirmation
 * @param username - The username for finding the vault
 *
 * @return -3 if the vault couldn't be removed
 * @return -2 if the vault couldn't be found
 * @return -1 if the vault failed to decrypt
 * @return 0 on success
*/
int closeVault(const char* masterPass, const char* username);

/*
* Initializes a new vault with a Usernamd and Master Password
*
* @return -1 if the vault path couldn't be found
* @return 0 on success
*/
int initVault(const char* masterPass, const char* username);

/*
* Deletes an entry from a vault
*
* @param site - The site being added to the entry
* @param masterPass - The password used for encrypting
* @param username - The username used for finding the vault
*
* @return -3 if the item couldn't be found
* @return -2 if the decrypt fails
* @return -1 if the vault couldn't be read or found
* @return 0 on success
*/
int removeEntry(const char* site, const char* masterPass, const char* username);

/*
* Adds an entry to the vault
*
* @param site - The site being added to the entry
* @param user - The user being added to the entry
* @param pass - The password being added to the entry
* @param masterPass - The password used for encrypting
* @param username - The username used for finding the vault
*
* @return -3 if any of the 3 parameters are beyond 128 bytes long
* @return -2 if the decrypt fails
* @return -1 if the vault couldn't be read or found
* @return 0 on success
*/
int addEntry(const char* site, const char* user, const char* pass, const char* masterPass, const char* username);

/*
* Prints the sites and usernames of all items in the vault
*
* @param site - The site given to find the password
* @param masterPass - The password used for decrypting
* @param username - The username used for finding the vault
*
* @return -2 if the decrypt fails
* @return -1 if the vault couldn't be read
* @return 0 on success
*/
int list(const char* masterPass, const char* username);

/*
* Prints the site, username, and password from a given site name
*
* @param site - The site given to find the password
* @param masterPass - The password used for decrypting
* @param username - The username used for finding the vault
*
* @return -3 if the decrypt fails
* @return -2 if the site couldn't be found
* @return -1 if the vault couldn't be read
* @return 0 on success
*/
int get(const char* site, const char* masterPass, const char* username);

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
* Reads from a vault based on the given username
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
* @return -2 if failed to find vault
* @return -1 if error opening the file
* @return 0 on success
*/
int writeVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t* cipher, size_t cipLen, char* fileName);

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
* @return -2 if failed to find vault
* @return -1 if error opening the file
* @return 0 on success
*/
int readVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t** cipherOut, size_t* cipLenOut, const char* username);

/*
* Produces a vault path for where to store your vault
* Path is determined by temp code and username
* 
* @param dest - The destination path being created
* @param size - the size of the destination
* @param temp - The temp code where 1 = temp, 0 = not temp
* 
* @return - 0 on success
* @return -1 if path is NULL
*/
int vaultPath(char* dest, size_t size, int temp, const char* username);

/*
* Fills a buffer with a random byte string
* 
* @param buf - The buffer for the random bytes
* @param len - The length of the buffer
* 
* @return - 0 on success, -1 on fail to fill
*/
int randomBytes(uint8_t* buf, size_t len);

#endif