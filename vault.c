/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			vault.c
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the vault implementation file
===================================================================== */

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "aes.h"
#include "passHash.h"
#include "vault.h"

//======================================================================

static int compareEntries(const void* a, const void* b)
{
	const struct VaultItems* ia = a;
	const struct VaultItems* ib = b;
	int bySite = strcmp(ia->site, ib->site);
	if (bySite != 0)
		return bySite;
	return strcmp(ia->user, ib->user);
}
//======================================================================

/*
* Creates ~/.config and ~/.config/vault if they don't already exist.
* Both are made private (0700); an existing directory is left as-is.
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
static VaultStatus ensureVaultDir(void)
{
	const char* home = getenv("HOME");
	if (home == NULL)
		return VAULT_ERR_IO;

	char dir[512];
	if ((size_t)snprintf(dir, sizeof dir, "%s/.config", home) >= sizeof dir)
		return VAULT_ERR_IO;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return VAULT_ERR_IO;

	if ((size_t)snprintf(dir, sizeof dir, "%s/.config/vault", home) >= sizeof dir)
		return VAULT_ERR_IO;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return VAULT_ERR_IO;

	return VAULT_OK;
}
//======================================================================

/*
* Atomically moves a fully-written temp vault over the real one, then
* syncs the directory so the rename itself survives a crash. The temp
* file is removed if the rename fails.
*
* @param tempPath - The temp file holding the new vault
* @param path - The vault file being replaced
*
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
static VaultStatus commitVault(const char* tempPath, const char* path)
{
	if (rename(tempPath, path) != 0)
	{
		remove(tempPath);
		return VAULT_ERR_IO;
	}

	char dir[512];
	if ((size_t)snprintf(dir, sizeof dir, "%s", path) >= sizeof dir)
		return VAULT_OK;

	char* slash = strrchr(dir, '/');
	if (slash != NULL)
	{
		*slash = '\0';
		int dfd = open(dir, O_RDONLY | O_DIRECTORY);
		if (dfd >= 0)
		{
			fsync(dfd);
			close(dfd);
		}
	}
	return VAULT_OK;
}
//======================================================================

VaultStatus confirmPassword(const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	int status;

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}
	status = VAULT_OK;

cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	explicit_bzero(key, sizeof key);
	return status;
}
//======================================================================
VaultStatus closeVault(const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	int status;
	uint32_t key[8] = { 0 };

	// use gcm to decrypt and tell if the password worked

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}

	char path[512];
	if (vaultPath(path, sizeof(path), 0, username) == VAULT_OK)
	{
		if (remove(path) == 0)
			status = VAULT_OK;
		else
			status = VAULT_ERR_IO;
	}
	else
	{
		status = VAULT_ERR_IO;
	}

cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus initVault(const char* masterPass, const char* username)
{
	uint8_t magic[4] = { 'V', 'L', 'T', '1' };
	uint8_t version[2] = { '0', '1' };
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t aad[6];
	uint32_t key[8] = { 0 };
	uint8_t* buffer = NULL;
	size_t bufLen = 0;
	int status;
	uint8_t* derKey = NULL;

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	// Do this before the (slow) key derivation so an unusable config
	// directory fails immediately rather than after 600k iterations.
	if (ensureVaultDir() != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	if (randomBytes(salt, 16) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}
	if (randomBytes(nonce, 12) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	buffer = malloc(1);
	if (buffer == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	gcmEncrypt(key, nonce, buffer, bufLen, aad, 6, tag);
	
	char path[512];
	char tempPath[512];
	if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK || vaultPath(tempPath, sizeof(tempPath), 1, username) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	if (writeVault(magic, version, salt, nonce, tag, buffer, bufLen, tempPath) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}
	status = commitVault(tempPath, path);

cleanup:
	if (buffer)
	{
		explicit_bzero(buffer, bufLen);
		free(buffer);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus replaceEntry(const char* site, const char* user, const char* newPass, const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	struct VaultItems* vaultItems = NULL;
	int status;
	size_t newLen = 0;
	uint8_t* blob = NULL;

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}

	vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
	if (vaultItems == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
	
	size_t found = 0;
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0 && strcmp(vaultItems[x].user, user) == 0)
		{
			strcpy(vaultItems[x].pass, newPass);
			found = 1;
			break;
		}
	}
	if (found == 1)
	{
		newLen = 0;
		blob = serializeEntries(vaultItems, vaultSize, &newLen);
		if (blob == NULL)
		{
			status = VAULT_ERR_INTERNAL;
			goto cleanup;
		}
		if (randomBytes(nonce, 12) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}
		gcmEncrypt(key, nonce, blob, newLen, aad, 6, tag);

		char path[512];
		char tempPath[512];
		if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK || vaultPath(tempPath, sizeof(tempPath), 1, username) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}

		if (writeVault(magic, version, salt, nonce, tag, blob, newLen, tempPath) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}
		status = commitVault(tempPath, path);
	}
	else
	{
		status = VAULT_ERR_ITEM;
	}
cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	if (vaultItems)
	{
		explicit_bzero(vaultItems, SIZE_256 * sizeof(struct VaultItems));
		free(vaultItems);
	}
	if (blob)
	{
		explicit_bzero(blob, newLen);
		free(blob);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus removeEntry(const char* site, const char* user, const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	struct VaultItems* vaultItems = NULL;
	int status;
	size_t newLen = 0;
	uint8_t* blob = NULL;

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}

	vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
	if (vaultItems == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
	
	size_t found = 0;
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0 && strcmp(vaultItems[x].user, user) == 0)
		{
			for (size_t y = x; y < vaultSize - 1; y++)
			{
				vaultItems[y] = vaultItems[y + 1];
			}
			vaultSize--;
			found = 1;
			break;
		}
	}
	if (found == 1)
	{
		newLen = 0;
		blob = serializeEntries(vaultItems, vaultSize, &newLen);
		if (blob == NULL)
		{
			status = VAULT_ERR_INTERNAL;
			goto cleanup;
		}
		if (randomBytes(nonce, 12) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}
		gcmEncrypt(key, nonce, blob, newLen, aad, 6, tag);

		char path[512];
		char tempPath[512];
		if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK || vaultPath(tempPath, sizeof(tempPath), 1, username) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}

		if (writeVault(magic, version, salt, nonce, tag, blob, newLen, tempPath) != VAULT_OK)
		{
			status = VAULT_ERR_IO;
			goto cleanup;
		}
		status = commitVault(tempPath, path);
	}
	else
	{
		status = VAULT_ERR_ITEM;
	}
cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	if (vaultItems)
	{
		explicit_bzero(vaultItems, SIZE_256 * sizeof(struct VaultItems));
		free(vaultItems);
	}
	if (blob)
	{
		explicit_bzero(blob, newLen);
		free(blob);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus addEntry(const char* site, const char* user, const char* pass, const char* masterPass, const char* username)
{
	if (strlen(site) < SIZE_128 && strlen(user) < SIZE_128 && strlen(pass) < SIZE_128)
	{
		size_t siteLen = strlen(site);
		size_t userLen = strlen(user);
		size_t passLen = strlen(pass);

		for (size_t x = 0; x < siteLen; x++)
		{
			if (site[x] == '\t' || site[x] == '\n')
				return VAULT_ERR_FIELD_CHAR;
		}
		for (size_t x = 0; x < userLen; x++)
		{
			if (user[x] == '\t' || user[x] == '\n')
				return VAULT_ERR_FIELD_CHAR;
		}
		for (size_t x = 0; x < passLen; x++)
		{
			if (pass[x] == '\t' || pass[x] == '\n')
				return VAULT_ERR_FIELD_CHAR;
		}
	}
	else
		return VAULT_ERR_FIELD_LEN;

	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	struct VaultItems* vaultItems = NULL;
	int status;
	size_t newLen = 0;
	uint8_t* blob = NULL;

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}

	vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
	if (vaultItems == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);

	if (vaultSize >= SIZE_256)
	{
		status = VAULT_ERR_FULL;
		goto cleanup;
	}
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0 && strcmp(vaultItems[x].user, user) == 0)
		{
			status = VAULT_ERR_ITEM;
			goto cleanup;
		}
	}
	strcpy(vaultItems[vaultSize].site, site);
	strcpy(vaultItems[vaultSize].user, user);
	strcpy(vaultItems[vaultSize].pass, pass);
	vaultSize++;

	qsort(vaultItems, vaultSize, sizeof(struct VaultItems), compareEntries);
	
	blob = serializeEntries(vaultItems, vaultSize, &newLen);
	if (blob == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	if (randomBytes(nonce, 12) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}
	gcmEncrypt(key, nonce, blob, newLen, aad, 6, tag);

	char path[512];
	char tempPath[512];
	if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK || vaultPath(tempPath, sizeof(tempPath), 1, username) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	if (writeVault(magic, version, salt, nonce, tag, blob, newLen, tempPath) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}
	status = commitVault(tempPath, path);

cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	if (vaultItems)
	{
		explicit_bzero(vaultItems, SIZE_256 * sizeof(struct VaultItems));
		free(vaultItems);
	}
	if (blob)
	{
		explicit_bzero(blob, newLen);
		free(blob);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus list(const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* cipher = NULL;
	size_t cipLen = 0;
	uint8_t* derKey = NULL;
	struct VaultItems* vaultItems = NULL;
	int status;


	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}
	
	vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
	if (vaultItems == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}
	size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);

	printf("\n%-15s\t%-15s\t%-15s\n", "Site", "User", "Password");
	printf("%-15s\t%-15s\t%-15s\n", "----", "----", "--------");
	for (size_t x = 0; x < vaultSize; x++)
	{
		printf("%-15s\t%-15s\t%-15s\n", vaultItems[x].site, vaultItems[x].user, "********");
	}
	printf("\n");
	status = VAULT_OK;
	
cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	if (vaultItems)
	{
		explicit_bzero(vaultItems, SIZE_256 * sizeof(struct VaultItems));
		free(vaultItems);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
VaultStatus get(const char* site, const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint32_t key[8] = { 0 };
	uint8_t* derKey = NULL;
	uint8_t* cipher = NULL;
	struct VaultItems* vaultItems = NULL;
	size_t cipLen = 0;
	int status;

	int rc = readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}

	uint8_t aad[6];
	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) != 0)
	{
		status = VAULT_ERR_AUTH;
		goto cleanup;
	}

	vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
	if (vaultItems == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
	int found = 0;
	
	printf("\n%-15s\t%-15s\t%-15s\n", "Site", "User", "Password");
	printf("%-15s\t%-15s\t%-15s\n", "----", "----", "--------");
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0)
		{
			printf("%-15s\t%-15s\t%-15s\n", vaultItems[x].site, vaultItems[x].user, vaultItems[x].pass);
			found = 1;
		}
	}
	status = found ? VAULT_OK : VAULT_ERR_ITEM;

cleanup:
	if (cipher)
	{
		explicit_bzero(cipher, cipLen);
		free(cipher);
	}
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	if (vaultItems)
	{
		explicit_bzero(vaultItems, SIZE_256 * sizeof(struct VaultItems));
		free(vaultItems);
	}
	explicit_bzero(key, sizeof key);
	return status;
}

//======================================================================
size_t parse(uint8_t* cipher, size_t cipLen, struct VaultItems* vaultItems, size_t maxItems)
{
	size_t txtIndex = 0;
	size_t wordIndex = 0;
	size_t itemIndex = 0;

	while (txtIndex < cipLen && itemIndex < maxItems)
	{
		while (txtIndex < cipLen && cipher[txtIndex] != '\t')
		{
			if (wordIndex < 127)
				vaultItems[itemIndex].site[wordIndex] = cipher[txtIndex];
			wordIndex++;
			txtIndex++;
		}
		vaultItems[itemIndex].site[wordIndex < 127 ? wordIndex : 127] = '\0';
		wordIndex = 0;
		txtIndex++;

		while (txtIndex < cipLen && cipher[txtIndex] != '\t')
		{
			if (wordIndex < 127)
				vaultItems[itemIndex].user[wordIndex] = cipher[txtIndex];
			wordIndex++;
			txtIndex++;
		}
		vaultItems[itemIndex].user[wordIndex < 127 ? wordIndex : 127] = '\0';
		wordIndex = 0;
		txtIndex++;

		while (txtIndex < cipLen && cipher[txtIndex] != '\n')
		{
			if (wordIndex < 127)
				vaultItems[itemIndex].pass[wordIndex] = cipher[txtIndex];
			wordIndex++;
			txtIndex++;
		}
		vaultItems[itemIndex].pass[wordIndex < 127 ? wordIndex : 127] = '\0';
		wordIndex = 0;
		txtIndex++;
		itemIndex++;
	}

	return itemIndex;
}

//======================================================================
uint8_t* serializeEntries(struct VaultItems* vaultItems, size_t itemCount, size_t* newLen)
{
	size_t byteTotal = 0;
	for (size_t x = 0; x < itemCount; x++)
	{
		byteTotal += strlen(vaultItems[x].site) + strlen(vaultItems[x].user) + strlen(vaultItems[x].pass) + 3;
	}
	uint8_t* buffer = malloc(byteTotal ? byteTotal : 1);
	if (buffer == NULL)
		return NULL;

	size_t bufIndex = 0;
	size_t len;

	for (size_t i = 0; i < itemCount; i++)
	{
		len = strlen(vaultItems[i].site);
		for (size_t x = 0; x < len; x++)
		{
			buffer[bufIndex] = vaultItems[i].site[x];
			bufIndex++;
		}
		buffer[bufIndex] = '\t';
		bufIndex++;
		len = strlen(vaultItems[i].user);
		for (size_t x = 0; x < len; x++)
		{
			buffer[bufIndex] = vaultItems[i].user[x];
			bufIndex++;
		}
		buffer[bufIndex] = '\t';
		bufIndex++;
		len = strlen(vaultItems[i].pass);
		for (size_t x = 0; x < len; x++)
		{
			buffer[bufIndex] = vaultItems[i].pass[x];
			bufIndex++;
		}
		buffer[bufIndex] = '\n';
		bufIndex++;
	}
	*newLen = bufIndex;
	return buffer;
}

//======================================================================
VaultStatus writeVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t* cipher, size_t cipLen, char* fileName)
{
	// 0600 at creation time: never let the vault exist world-readable,
	// not even for the moment between fopen and a later chmod.
	int fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return VAULT_ERR_IO;

	FILE* file = fdopen(fd, "wb");
	if (file == NULL)
	{
		close(fd);
		remove(fileName);
		return VAULT_ERR_IO;
	}

	if (fwrite(magic, sizeof(uint8_t), 4, file) != 4
		|| fwrite(version, sizeof(uint8_t), 2, file) != 2
		|| fwrite(salt, sizeof(uint8_t), 16, file) != 16
		|| fwrite(nonce, sizeof(uint8_t), 12, file) != 12
		|| fwrite(tag, sizeof(uint8_t), 16, file) != 16
		|| fwrite(cipher, sizeof(uint8_t), cipLen, file) != cipLen)
	{
		fclose(file);
		remove(fileName);
		return VAULT_ERR_IO;
	}

	// Force the bytes to disk before the caller renames this over the
	// live vault, so a crash can't promote a truncated file.
	if (fflush(file) != 0 || fsync(fileno(file)) != 0)
	{
		fclose(file);
		remove(fileName);
		return VAULT_ERR_IO;
	}

	if (fclose(file) != 0)
	{
		remove(fileName);
		return VAULT_ERR_IO;
	}

	return VAULT_OK;
}

//======================================================================
VaultStatus readVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t** cipherOut, size_t* cipLenOut, const char* username)
{
	char path[512];
	if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK)
		return VAULT_ERR_IO;
	FILE* file = fopen(path, "rb");
	if (file == NULL)
	{
		printf("Error opening file...\n");
		return VAULT_ERR_NOT_FOUND;
	}
	else
	{
		fseek(file, 0, SEEK_END);
		long total = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (total < 50)
		{
			fclose(file);
			return VAULT_ERR_IO;
		}

		size_t cipLen = (size_t)total - 50;

		if (fread(magic, sizeof(uint8_t), 4, file) != 4 || fread(version, sizeof(uint8_t), 2, file) != 2 || fread(salt, sizeof(uint8_t), 16, file) != 16 || fread(nonce, sizeof(uint8_t), 12, file) != 12 || fread(tag, sizeof(uint8_t), 16, file) != 16)
		{
			fclose(file);
			return VAULT_ERR_IO;
		}

		uint8_t* cipher = malloc(sizeof(uint8_t) * (cipLen ? cipLen : 1));
		if (cipher == NULL)
		{
			fclose(file);
			return VAULT_ERR_IO;
		}
		if (fread(cipher, sizeof(uint8_t), cipLen, file) != cipLen)
		{
			free(cipher);
			fclose(file);
			return VAULT_ERR_IO;
		}
		*cipherOut = cipher;
		*cipLenOut = cipLen;
	}
	fclose(file);
	return VAULT_OK;
}

//======================================================================
VaultStatus vaultPath(char* dest, size_t size, int temp, const char* username)
{
	size_t len = strlen(username);
	if (len == 0)
		return VAULT_ERR_IO;
	for (size_t x = 0; x < len; x++)
	{
		char c = username[x];
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_'))
			return VAULT_ERR_IO;
	}
	const char* home = getenv("HOME");
	if (home == NULL)
		return VAULT_ERR_IO;
	snprintf(dest, size, "%s/.config/vault/vault.%s.bin%s", home, username, temp ? ".temp" : "");
	return VAULT_OK;
}

//======================================================================
VaultStatus randomBytes(uint8_t* buf, size_t len)
{
	size_t got = 0;
	while (got < len)
	{
		ssize_t r = getrandom(buf + got, len - got, 0);
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			return VAULT_ERR_IO;
		}
		got += (size_t)r;
	}
	return VAULT_OK;
}
