/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			vault.c
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the vault implementation file
===================================================================== */

#include "aes.h"
#include "passHash.h"
#include "vault.h"

//======================================================================
int closeVault(const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher;
	size_t cipLen;

	// use gcm to decrypt and tell if the password worked

	if (readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username) != 0)
	{
		return -2;
	}

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) == 0)
	{
		free(cipher);
		char path[512];
		if (vaultPath(path, sizeof(path), 0, username) == 0)
		{
			if (remove(path) == 0)
				return 0;
			else
				return -3;
		}
		else
			return -2;
	}
	else
		return -1;
}

//======================================================================
int initVault(const char* masterPass, const char* username)
{
	uint8_t magic[4] = { 'V', 'L', 'T', '1' };
	uint8_t version[2] = { '0', '1' };
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	randomBytes(salt, 16);
	randomBytes(nonce, 12);

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t* buffer = malloc(1);
	size_t bufLen = 0;
	gcmEncrypt(key, nonce, buffer, bufLen, aad, 6, tag);

	char path[512];
	char tempPath[512];
	if (vaultPath(path, sizeof(path), 0, username) == -1)
		return -1;
	if (vaultPath(tempPath, sizeof(tempPath), 1, username) == -1)
		return -1;

	int wrote = writeVault(magic, version, salt, nonce, tag, buffer, bufLen, tempPath);
	if (wrote == 0)
	{
		rename(tempPath, path);
	}
	free(buffer);
	return 0;
}

//======================================================================
int removeEntry(const char* site, const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher;
	size_t cipLen;

	if (readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username) != 0)
	{
		return -1;
	}

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) == 0)
	{
		struct VaultItems* vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
		size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
		free(cipher);
		size_t found = 0;
		for (size_t x = 0; x < vaultSize; x++)
		{
			if (strcmp(vaultItems[x].site, site) == 0)
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
			size_t newLen = 0;
			uint8_t* blob = serializeEntries(vaultItems, vaultSize, &newLen);
			free(vaultItems);
			randomBytes(nonce, 12);
			gcmEncrypt(key, nonce, blob, newLen, aad, 6, tag);

			char path[512];
			char tempPath[512];
			if (vaultPath(path, sizeof(path), 0, username) == -1)
				return -1;
			if (vaultPath(tempPath, sizeof(tempPath), 1, username) == -1)
				return -1;

			int wrote = writeVault(magic, version, salt, nonce, tag, blob, newLen, tempPath);
			if (wrote == 0)
			{
				rename(tempPath, path);
			}
			free(blob);
			return wrote;
		}
		else
		{
			free(vaultItems);
			return -3;
		}
	}
	else
	{
		free(cipher);
		return -2;
	}
}

//======================================================================
int addEntry(const char* site, const char* user, const char* pass, const char* masterPass, const char* username)
{
	if (strlen(site) < SIZE_128 && strlen(user) < SIZE_128 && strlen(pass) < SIZE_128)
	{
		size_t siteLen = strlen(site);
		size_t userLen = strlen(user);
		size_t passLen = strlen(pass);

		for (size_t x = 0; x < siteLen; x++)
		{
			if (site[x] == '\t' || site[x] == '\n')
				return -2;
		}
		for (size_t x = 0; x < userLen; x++)
		{
			if (user[x] == '\t' || user[x] == '\n')
				return -2;
		}
		for (size_t x = 0; x < passLen; x++)
		{
			if (pass[x] == '\t' || pass[x] == '\n')
				return -2;
		}
	}
	else
		return -3;

	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher;
	size_t cipLen;

	if (readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username) != 0)
	{
		return -1;
	}

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) == 0)
	{
		struct VaultItems* vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
		size_t vaultSize = parse(cipher, cipLen, vaultItems, 256);
		free(cipher);
		if (vaultSize >= SIZE_256)
		{
			free(vaultItems); return -4;
		}
		strcpy(vaultItems[vaultSize].site, site);
		strcpy(vaultItems[vaultSize].user, user);
		strcpy(vaultItems[vaultSize].pass, pass);
		vaultSize++;
		size_t newLen = 0;
		uint8_t* blob = serializeEntries(vaultItems, vaultSize, &newLen);
		free(vaultItems);
		randomBytes(nonce, 12);
		gcmEncrypt(key, nonce, blob, newLen, aad, 6, tag);

		char path[512];
		char tempPath[512];
		if (vaultPath(path, sizeof(path), 0, username) == -1)
			return -1;
		if (vaultPath(tempPath, sizeof(tempPath), 1, username) == -1)
			return -1;

		int wrote = writeVault(magic, version, salt, nonce, tag, blob, newLen, tempPath);
		if (wrote == 0)
		{
			rename(tempPath, path);
		}
		free(blob);
		return wrote;
	}
	else
	{
		free(cipher);
		return -2;
	}
}

//======================================================================
int list(const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher;
	size_t cipLen;

	if (readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username) != 0)
	{
		return -1;
	}

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) == 0)
	{
		struct VaultItems* vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
		size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
		free(cipher);
		printf("\n%-15s\t%-15s\t%-15s\n", "Site", "User", "Password");
		printf("%-15s\t%-15s\t%-15s\n", "----", "----", "--------");
		for (size_t x = 0; x < vaultSize; x++)
		{
			printf("%-15s\t%-15s\t%-15s\n", vaultItems[x].site, vaultItems[x].user, "********");
		}
		printf("\n");
		free(vaultItems);
		return 0;
	}
	else
	{
		free(cipher);
		return -2;
	}
}

//======================================================================
int get(const char* site, const char* masterPass, const char* username)
{
	uint8_t magic[4];
	uint8_t version[2];
	uint8_t salt[16];
	uint8_t nonce[12];
	uint8_t tag[16];
	uint8_t* cipher;
	size_t cipLen;

	if (readVault(magic, version, salt, nonce, tag, &cipher, &cipLen, username) != 0)
	{
		return -1;
	}

	uint8_t* derKey = pbkdf2((uint8_t*)masterPass, strlen(masterPass), salt, 16, 600000);
	uint32_t key[8];
	for (size_t x = 0; x < 8; x++)
	{
		key[x] = ((uint32_t)derKey[x * 4] << 24) | ((uint32_t)derKey[x * 4 + 1] << 16) | ((uint32_t)derKey[x * 4 + 2] << 8) | (uint32_t)derKey[x * 4 + 3];
	}
	free(derKey);

	uint8_t aad[6];

	for (size_t x = 0; x < 4; x++)
		aad[x] = magic[x];
	for (size_t x = 0; x < 2; x++)
		aad[x + 4] = version[x];

	if (gcmDecrypt(key, nonce, cipher, cipLen, aad, 6, tag) == 0)
	{
		int found = 0;
		struct VaultItems* vaultItems = malloc(SIZE_256 * sizeof(struct VaultItems));
		size_t vaultSize = parse(cipher, cipLen, vaultItems, SIZE_256);
		free(cipher);

		for (size_t x = 0; x < vaultSize; x++)
		{
			if (strcmp(vaultItems[x].site, site) == 0)
			{
				printf("\n%-15s\t%-15s\t%-15s\n", "Site", "User", "Password");
				printf("%-15s\t%-15s\t%-15s\n", "----", "----", "--------");
				printf("%-15s\t%-15s\t%-15s\n\n", vaultItems[x].site, vaultItems[x].user, vaultItems[x].pass);
				found = 1;
			}
		}
		if (found == 0)
		{
			printf("%s not found...\n", site);
			free(vaultItems);
			return -2;
		}
		free(vaultItems);
		return 0;
	}
	else
	{
		free(cipher);
		return -3;
	}
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
int writeVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t* cipher, size_t cipLen, char* fileName)
{
	FILE* file = fopen(fileName, "wb");
	if (file == NULL)
	{
		printf("Error opening file...\n");
		return -1;
	}
	else
	{
		fwrite(magic, sizeof(uint8_t), 4, file);
		fwrite(version, sizeof(uint8_t), 2, file);
		fwrite(salt, sizeof(uint8_t), 16, file);
		fwrite(nonce, sizeof(uint8_t), 12, file);
		fwrite(tag, sizeof(uint8_t), 16, file);
		fwrite(cipher, sizeof(uint8_t), cipLen, file);
	}
	fclose(file);
	return 0;
}

//======================================================================
int readVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t** cipherOut, size_t* cipLenOut, const char* username)
{
	char path[512];
	if (vaultPath(path, sizeof(path), 0, username) == -1)
		return -2;
	FILE* file = fopen(path, "rb");
	if (file == NULL)
	{
		printf("Error opening file...\n");
		return -1;
	}
	else
	{
		fseek(file, 0, SEEK_END);
		long total = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (total < 50)
		{
			fclose(file);
			return -1;
		}

		size_t cipLen = (size_t)total - 50;

		if (fread(magic, sizeof(uint8_t), 4, file) != 4 || fread(version, sizeof(uint8_t), 2, file) != 2 || fread(salt, sizeof(uint8_t), 16, file) != 16 || fread(nonce, sizeof(uint8_t), 12, file) != 12 || fread(tag, sizeof(uint8_t), 16, file) != 16)
		{
			fclose(file);
			return -1;
		}

		uint8_t* cipher = malloc(sizeof(uint8_t) * (cipLen ? cipLen : 1));
		if (cipher == NULL)
		{
			fclose(file);
			return -1;
		}
		if (fread(cipher, sizeof(uint8_t), cipLen, file) != cipLen)
		{
			free(cipher);
			fclose(file);
			return -1;
		}
		*cipherOut = cipher;
		*cipLenOut = cipLen;
	}
	fclose(file);
	return 0;
}

//======================================================================
int vaultPath(char* dest, size_t size, int temp, const char* username)
{
	const char* home = getenv("HOME");
	if (home == NULL)
		return -1;
	snprintf(dest, size, "%s/.config/vault/vault.%s.bin%s", home, username, temp ? ".temp" : "");
	return 0;
}

//======================================================================
int randomBytes(uint8_t* buf, size_t len)
{
	size_t got = 0;
	while (got < len)
	{
		ssize_t r = getrandom(buf + got, len - got, 0);
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)r;
	}
	return 0;
}
