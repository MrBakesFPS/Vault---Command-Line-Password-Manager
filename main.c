#include <termios.h>
#include <unistd.h>
#include "aes.h"
#include "passHash.h"
#include "vault.h"

void printUsage();
int verifyUsername(char username[SIZE_128]);
int verifyPassword(char password[SIZE_128], const char* printText);
void disable_echo();
void enable_echo();

int main(int argc, char*argv[])
{
	char username[SIZE_128];
	char password[SIZE_128];
	char confirmPass[SIZE_128];
	if (argc < 2)
	{
		printUsage();
	}
	else if (argc == 2)
	{
		if (strcmp(argv[1], "list") == 0)
		{
			if (verifyUsername(username) == -1)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = list(password, username);
			if (rc == -3)
			{
				printf("Wrong master password or corrupted vault.\n");
				return 1;
			}
			if (rc == -1)
			{
				printf("No vault found — run 'init' first.\n");
				return 1;
			}
		}
		else if (strcmp(argv[1], "init") == 0)
		{
			if (verifyUsername(username) == 0)
			{
				printf("User vault already exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			if (verifyPassword(confirmPass, "Confirm Password: ") == -1)
			{
				return -1;
			}
			if (strcmp(password, confirmPass) != 0)
			{
				printf("Passwords don't match. Vault initialize failed!\n");
				return -1;
			}

			int rc = initVault(password, username);
			if (rc == -1)
			{
				printf("ERROR -- Unable to create vault\n");
				return 1;
			}
		}
		else
		{
			printUsage();
		}
	}
	else if (argc == 3)
	{
		if (strcmp(argv[1], "get") == 0)
		{
			if (verifyUsername(username) == -1)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = get(argv[2], password, username);
			if (rc == -3)
			{
				printf("Wrong master password or corrupted vault.\n");
				return 1;
			}
			if (rc == -1)
			{
				printf("No vault found — run 'init' first.\n");
				return 1;
			}
		}
		else if (strcmp(argv[1], "remove") == 0)
		{
			if (verifyUsername(username) == -1)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = removeEntry(argv[2], password, username);
			if (rc == -3)
			{
				printf("Wrong master password or corrupted vault.\n");
				return 1;
			}
			if (rc == -1)
			{
				printf("No vault found — run 'init' first.\n");
				return 1;
			}
			printf("Password removed from vault successfully!\n");
		}
		else
		{
			printUsage();
		}
	}
	else if (argc == 5)
	{
		if (verifyUsername(username) == -1)
		{
			printf("User vault doesnt't exist!\n");
			return -1;
		}
		if (verifyPassword(password, "Password: ") == -1)
		{
			return -1;
		}
		int rc = addEntry(argv[2], argv[3], argv[4], password, username);
		if (rc == -3)
		{
			printf("Wrong master password or corrupted vault.\n");
			return 1;
		}
		if (rc == -1)
		{
			printf("No vault found — run 'init' first.\n");
			return 1;
		}
		printf("Password added to vault successfully!\n");
	}
	else
	{
		printUsage();
	}
	return 0;
}

void printUsage()
{
	printf("Usage: vault init | add <site> <user> <pass> | get <site> | list | remove <site>\n");
}

int verifyUsername(char username[SIZE_128])
{
	printf("Username: ");
	if (fgets(username, SIZE_128, stdin) != NULL)
	{
		username[strcspn(username, "\n")] = '\0';
	}
	char path[512];
	if (vaultPath(path, sizeof(path), 0, username) == -1)
		return -1;
	FILE* file = fopen(path, "r");
	if (file != NULL)
	{
		fclose(file);
		return 0;
	}
	return -1;
}

int verifyPassword(char password[SIZE_128], const char* printText)
{
	printf("%s", printText);
	disable_echo();
	if (fgets(password, SIZE_128, stdin) != NULL)
	{
		enable_echo();
		password[strcspn(password, "\n")] = '\0';
		printf("\n");
		return 0;
	}
	enable_echo();
	return -1;
}

void disable_echo()
{
	struct termios t;
	tcgetattr(STDIN_FILENO, &t);

	t.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

void enable_echo()
{
	struct termios t;
	tcgetattr(STDIN_FILENO, &t);

	t.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}
