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

// PBKDF2 cost. Deliberately slow, so it runs once per login (see
// openSession) rather than once per command.
#define PBKDF2_ITERATIONS 600000

/*
* The plaintext preamble of a vault file. Read back on every load and
* written out unchanged, since the salt fixes the key and the magic and
* version are covered by the GCM tag as additional authenticated data.
*/
typedef struct
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
} VaultHeader;

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

/*
* Builds the 6 bytes of additional authenticated data (magic+version)
* that bind a vault's header to its GCM tag
*
* @param header - The header being authenticated
* @param aad - The 6 byte buffer being filled
*/
static void buildAad(const VaultHeader* header, uint8_t aad[6])
{
	for (size_t x = 0; x < 4; x++)
		aad[x] = header->magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = header->version[x];
}
//======================================================================

/*
* Packs the 32 derived key bytes into the 8 big-endian words AES wants
*
* @param derKey - The 32 bytes coming out of pbkdf2
* @param key - The 8 word AES key being filled
*/
static void unpackKey(const uint8_t derKey[32], uint32_t key[8])
{
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24)
			| ((uint32_t)derKey[x * 4 + 1] << 16)
			| ((uint32_t)derKey[x * 4 + 2] << 8)
			| (uint32_t)derKey[x * 4 + 3];
	}
}
//======================================================================

/*
* Rejects field values the flat tab/newline vault format can't round
* trip, and values too long for a VaultItems field
*
* @param field - The site, user, or password being checked
*
* @return VAULT_ERR_FIELD_LEN
* @return VAULT_ERR_FIELD_CHAR
* @return VAULT_OK
*/
static VaultStatus validateField(const char* field)
{
	size_t len = strlen(field);
	if (len >= SIZE_128)
		return VAULT_ERR_FIELD_LEN;

	for (size_t x = 0; x < len; x++)
	{
		if (field[x] == '\t' || field[x] == '\n')
			return VAULT_ERR_FIELD_CHAR;
	}
	return VAULT_OK;
}
//======================================================================

/*
* Reads the session's vault off disk, authenticates and decrypts it with
* the session key, and parses the plaintext into vaultItems
*
* @param session - The unlocked session holding the vault key
* @param header - The header read back off disk
* @param vaultItems - A VAULT_MAX_ITEMS array being filled
* @param itemCount - The number of entries parsed
*
* @return VAULT_ERR_NOT_FOUND
* @return VAULT_ERR_AUTH
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
static VaultStatus loadVault(const VaultSession* session, VaultHeader* header, struct VaultItems* vaultItems, size_t* itemCount)
{
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t aad[6];
	uint8_t* cipher = NULL;
	size_t cipLen = 0;

	VaultStatus rc = readVault(header->magic, header->version, header->salt, nonce, tag, &cipher, &cipLen, session->username);
	if (rc != VAULT_OK)
		return rc;

	buildAad(header, aad);

	VaultStatus status;
	if (gcmDecrypt(session->key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		status = VAULT_ERR_AUTH;
	}
	else
	{
		status = parse(cipher, cipLen, vaultItems, VAULT_MAX_ITEMS, itemCount);
	}

	explicit_bzero(cipher, cipLen);
	free(cipher);
	return status;
}
//======================================================================

/*
* Serializes, encrypts under a fresh nonce, and durably replaces the
* session's vault file
*
* @param session - The unlocked session holding the vault key
* @param header - The header to write back out
* @param vaultItems - The entries being stored
* @param itemCount - The number of entries
*
* @return VAULT_ERR_INTERNAL
* @return VAULT_ERR_IO
* @return VAULT_OK
*/
static VaultStatus saveVault(const VaultSession* session, const VaultHeader* header, struct VaultItems* vaultItems, size_t itemCount)
{
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t aad[6];
	char path[512];
	char tempPath[512];
	VaultStatus status;
	size_t blobLen = 0;

	uint8_t* blob = serializeEntries(vaultItems, itemCount, &blobLen);
	if (blob == NULL)
		return VAULT_ERR_INTERNAL;

	// Never reuse a nonce with the same key.
	if (randomBytes(nonce, 12) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	buildAad(header, aad);
	gcmEncrypt(session->key, nonce, blob, blobLen, aad, 6, tag);

	if (vaultPath(path, sizeof path, 0, session->username) != VAULT_OK
		|| vaultPath(tempPath, sizeof tempPath, 1, session->username) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}

	if (writeVault(header->magic, header->version, header->salt, nonce, tag, blob, blobLen, tempPath) != VAULT_OK)
	{
		status = VAULT_ERR_IO;
		goto cleanup;
	}
	status = commitVault(tempPath, path);

cleanup:
	explicit_bzero(blob, blobLen);
	free(blob);
	return status;
}
//======================================================================

VaultStatus openSession(const char* masterPass, const char* username, VaultSession* session)
{
	VaultHeader header;
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t aad[6];
	uint8_t* cipher = NULL;
	uint8_t* derKey = NULL;
	size_t cipLen = 0;
	VaultStatus status;

	explicit_bzero(session, sizeof *session);

	if (strlen(username) >= sizeof session->username)
		return VAULT_ERR_FIELD_LEN;

	VaultStatus rc = readVault(header.magic, header.version, header.salt, nonce, tag, &cipher, &cipLen, username);
	if (rc != VAULT_OK)
		return rc;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), header.salt, 16, PBKDF2_ITERATIONS);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	memcpy(session->username, username, strlen(username) + 1);
	unpackKey(derKey, session->key);

	buildAad(&header, aad);

	// The tag check is what actually proves the password was right.
	if (gcmDecrypt(session->key, nonce, cipher, cipLen, aad, 6, tag) != VAULT_OK)
	{
		explicit_bzero(session, sizeof *session);
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
	return status;
}
//======================================================================

void closeSession(VaultSession* session)
{
	explicit_bzero(session, sizeof *session);
}
//======================================================================

VaultStatus closeVault(const VaultSession* session)
{
	// The session already proved the master password at openSession.
	char path[512];
	if (vaultPath(path, sizeof path, 0, session->username) != VAULT_OK)
		return VAULT_ERR_IO;

	if (remove(path) != 0)
		return VAULT_ERR_IO;

	return VAULT_OK;
}
//======================================================================

VaultStatus initVault(const char* masterPass, const char* username)
{
	VaultHeader header = { { 'V', 'L', 'T', '1' }, { '0', '1' }, { 0 } };
	VaultSession session;
	uint8_t* derKey = NULL;
	VaultStatus status;

	explicit_bzero(&session, sizeof session);

	if (strlen(username) >= sizeof session.username)
		return VAULT_ERR_FIELD_LEN;

	// Do this before the (slow) key derivation so an unusable config
	// directory fails immediately rather than after 600k iterations.
	if (ensureVaultDir() != VAULT_OK)
		return VAULT_ERR_IO;

	if (randomBytes(header.salt, 16) != VAULT_OK)
		return VAULT_ERR_IO;

	derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), header.salt, 16, PBKDF2_ITERATIONS);
	if (derKey == NULL)
	{
		status = VAULT_ERR_INTERNAL;
		goto cleanup;
	}

	memcpy(session.username, username, strlen(username) + 1);
	unpackKey(derKey, session.key);

	status = saveVault(&session, &header, NULL, 0);

cleanup:
	if (derKey)
	{
		explicit_bzero(derKey, SIZE_32);
		free(derKey);
	}
	closeSession(&session);
	return status;
}
//======================================================================

VaultStatus replaceEntry(const char* site, const char* user, const char* newPass, const VaultSession* session)
{
	VaultHeader header;
	struct VaultItems* vaultItems = NULL;
	size_t vaultSize = 0;
	VaultStatus status;

	status = validateField(newPass);
	if (status != VAULT_OK)
		return status;

	vaultItems = malloc(VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	if (vaultItems == NULL)
		return VAULT_ERR_INTERNAL;

	status = loadVault(session, &header, vaultItems, &vaultSize);
	if (status != VAULT_OK)
		goto cleanup;

	status = VAULT_ERR_ITEM;
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0 && strcmp(vaultItems[x].user, user) == 0)
		{
			memcpy(vaultItems[x].pass, newPass, strlen(newPass) + 1);
			status = saveVault(session, &header, vaultItems, vaultSize);
			break;
		}
	}

cleanup:
	explicit_bzero(vaultItems, VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	free(vaultItems);
	return status;
}
//======================================================================

VaultStatus removeEntry(const char* site, const char* user, const VaultSession* session)
{
	VaultHeader header;
	struct VaultItems* vaultItems = NULL;
	size_t vaultSize = 0;
	VaultStatus status;

	vaultItems = malloc(VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	if (vaultItems == NULL)
		return VAULT_ERR_INTERNAL;

	status = loadVault(session, &header, vaultItems, &vaultSize);
	if (status != VAULT_OK)
		goto cleanup;

	status = VAULT_ERR_ITEM;
	for (size_t x = 0; x < vaultSize; x++)
	{
		if (strcmp(vaultItems[x].site, site) == 0 && strcmp(vaultItems[x].user, user) == 0)
		{
			for (size_t y = x; y < vaultSize - 1; y++)
			{
				vaultItems[y] = vaultItems[y + 1];
			}
			vaultSize--;
			status = saveVault(session, &header, vaultItems, vaultSize);
			break;
		}
	}

cleanup:
	explicit_bzero(vaultItems, VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	free(vaultItems);
	return status;
}
//======================================================================

VaultStatus addEntry(const char* site, const char* user, const char* pass, const VaultSession* session, size_t* countOut)
{
	VaultHeader header;
	struct VaultItems* vaultItems = NULL;
	size_t vaultSize = 0;
	VaultStatus status;

	status = validateField(site);
	if (status != VAULT_OK)
		return status;
	status = validateField(user);
	if (status != VAULT_OK)
		return status;
	status = validateField(pass);
	if (status != VAULT_OK)
		return status;

	vaultItems = malloc(VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	if (vaultItems == NULL)
		return VAULT_ERR_INTERNAL;

	status = loadVault(session, &header, vaultItems, &vaultSize);
	if (status != VAULT_OK)
		goto cleanup;

	if (vaultSize >= VAULT_MAX_ITEMS)
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

	memcpy(vaultItems[vaultSize].site, site, strlen(site) + 1);
	memcpy(vaultItems[vaultSize].user, user, strlen(user) + 1);
	memcpy(vaultItems[vaultSize].pass, pass, strlen(pass) + 1);
	vaultSize++;

	qsort(vaultItems, vaultSize, sizeof(struct VaultItems), compareEntries);

	status = saveVault(session, &header, vaultItems, vaultSize);
	if (status == VAULT_OK && countOut != NULL)
		*countOut = vaultSize;

cleanup:
	explicit_bzero(vaultItems, VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	free(vaultItems);
	return status;
}
//======================================================================

VaultStatus list(const VaultSession* session)
{
	VaultHeader header;
	struct VaultItems* vaultItems = NULL;
	size_t vaultSize = 0;
	VaultStatus status;

	vaultItems = malloc(VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	if (vaultItems == NULL)
		return VAULT_ERR_INTERNAL;

	status = loadVault(session, &header, vaultItems, &vaultSize);
	if (status != VAULT_OK)
		goto cleanup;

	printf("\n%-15s\t%-15s\t%-15s\n", "Site", "User", "Password");
	printf("%-15s\t%-15s\t%-15s\n", "----", "----", "--------");
	for (size_t x = 0; x < vaultSize; x++)
	{
		printf("%-15s\t%-15s\t%-15s\n", vaultItems[x].site, vaultItems[x].user, "********");
	}
	printf("\n%zu of %d entries used.\n", vaultSize, VAULT_MAX_ITEMS);
	if (vaultSize >= VAULT_MAX_ITEMS)
		printf("The vault is full — remove an entry before adding another.\n");
	else if (vaultSize >= VAULT_WARN_ITEMS)
		printf("Warning: only %d left before the vault is full.\n", (int)(VAULT_MAX_ITEMS - vaultSize));
	printf("\n");
	status = VAULT_OK;

cleanup:
	explicit_bzero(vaultItems, VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	free(vaultItems);
	return status;
}
//======================================================================

VaultStatus get(const char* site, const VaultSession* session)
{
	VaultHeader header;
	struct VaultItems* vaultItems = NULL;
	size_t vaultSize = 0;
	int found = 0;
	VaultStatus status;

	vaultItems = malloc(VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	if (vaultItems == NULL)
		return VAULT_ERR_INTERNAL;

	status = loadVault(session, &header, vaultItems, &vaultSize);
	if (status != VAULT_OK)
		goto cleanup;

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
	explicit_bzero(vaultItems, VAULT_MAX_ITEMS * sizeof(struct VaultItems));
	free(vaultItems);
	return status;
}
//======================================================================

VaultStatus parse(const uint8_t* cipher, size_t cipLen, struct VaultItems* vaultItems, size_t maxItems, size_t* itemCount)
{
	size_t txtIndex = 0;
	size_t items = 0;

	while (txtIndex < cipLen)
	{
		// More records than the caller can hold. Carrying on would drop
		// the remainder, and the next save would write the truncation
		// back over the file.
		if (items >= maxItems)
			return VAULT_ERR_CORRUPT;

		char* field[3] = { vaultItems[items].site, vaultItems[items].user, vaultItems[items].pass };
		const uint8_t endsAt[3] = { '\t', '\t', '\n' };

		for (size_t f = 0; f < 3; f++)
		{
			size_t len = 0;
			while (txtIndex < cipLen && cipher[txtIndex] != endsAt[f])
			{
				// A newline before the password field means the record
				// ended early; writers reject newlines in site and user.
				if (f < 2 && cipher[txtIndex] == '\n')
					return VAULT_ERR_CORRUPT;

				// Longer than a VaultItems field. The old code truncated
				// here, quietly corrupting the entry.
				if (len >= SIZE_128 - 1)
					return VAULT_ERR_CORRUPT;

				field[f][len] = (char)cipher[txtIndex];
				len++;
				txtIndex++;
			}

			// Ran out of data before the field terminator.
			if (txtIndex >= cipLen)
				return VAULT_ERR_CORRUPT;

			field[f][len] = '\0';
			txtIndex++;
		}
		items++;
	}

	*itemCount = items;
	return VAULT_OK;
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
VaultStatus writeVault(const uint8_t magic[4], const uint8_t version[2], const uint8_t salt[16], const uint8_t nonce[12], const uint8_t tag[16], const uint8_t* cipher, size_t cipLen, const char* fileName)
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
		return VAULT_ERR_NOT_FOUND;

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
