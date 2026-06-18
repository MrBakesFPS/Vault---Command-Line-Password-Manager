struct VaultItems
{
	char site[128];
	char user[128];
	char pass[128];
};

int initVault(const char* masterPass, const char* username);
int removeEntry(const char* site, const char* masterPass, const char* username);
int addEntry(const char* site, const char* user, const char* pass, const char* masterPass, const char* username);
int list(const char* masterPass, const char* username);
int get(const char* site, const char* masterPass, const char* username);
size_t parse(uint8_t* cipher, size_t cipLen, struct VaultItems* vaultItems, size_t maxItems);
uint8_t* serializeEntries(struct VaultItems* vaultItems, size_t itemCount, size_t* newLen);
int writeVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t* cipher, size_t cipLen, char* fileName, const char* username);
int readVault(uint8_t magic[4], uint8_t version[2], uint8_t salt[16], uint8_t nonce[12], uint8_t tag[16], uint8_t** cipherOut, size_t* cipLenOut, const char* username);


int vaultPath(char* dest, size_t size, int temp, const char* username);

int randomBytes(uint8_t* buf, size_t len);

