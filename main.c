/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			main.c
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the main file used for the Vault program
				to direct commands to their correct destination
===================================================================== */

#include <termios.h>
#include <unistd.h>
#include "aes.h"
#include "passHash.h"
#include "vault.h"

//======================================================================

void printUsage();
int verifyUsername(char username[SIZE_128]);
int verifyPassword(char password[SIZE_128], const char* printText);
void disable_echo();
void enable_echo();
static void reportError(int rc);

//======================================================================
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
			if (verifyUsername(username) != 0)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = list(password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				return -1;
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
			if (rc != VAULT_OK)
			{
				reportError(rc);
				return -1;
			}
			printf("Vault created successfully!\n");
		}
		else if (strcmp(argv[1], "close") == 0)
		{
			if (verifyUsername(username) != 0)
			{
				printf("User doesn't exist\n");
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
				printf("Passwords don't match. Vault close failed!\n");
				return -1;
			}

			int rc = closeVault(password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				return -1;
			}
			printf("Vault removed successfully!\n");
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
			if (verifyUsername(username) != 0)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = get(argv[2], password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				return -1;
			}
		}
		else if (strcmp(argv[1], "remove") == 0)
		{
			if (verifyUsername(username) != 0)
			{
				printf("User vault doesnt't exist!\n");
				return -1;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				return -1;
			}
			int rc = removeEntry(argv[2], password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				return -1;
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
		if (verifyUsername(username) != 0)
		{
			printf("User vault doesnt't exist!\n");
			return -1;
		}
		if (verifyPassword(password, "Password: ") == -1)
		{
			return -1;
		}
		int rc = addEntry(argv[2], argv[3], argv[4], password, username);
		if (rc != VAULT_OK)
		{
			reportError(rc);
			return -1;
		}
		printf("Password added to vault successfully!\n");
	}
	else
	{
		printUsage();
	}
	return 0;
}

/*
* Usage: vault init | add <site> <user> <pass> | get <site> | list | remove <site>
*/
void printUsage()
{
	printf("Usage: vault init | close | add <site> <user> <pass> | get <site> | list | remove <site>\n");
}

/*
* Verifies that the username is attached to an active vault
* 
* @param username - The username being searched for
* 
* @return -2 if failed to write to file
* @return -1 if failed to find path
* @return 0 on success
*/
int verifyUsername(char username[SIZE_128])
{
	printf("Username: ");
	if (fgets(username, SIZE_128, stdin) != NULL)
	{
		username[strcspn(username, "\n")] = '\0';
	}
	char path[512];
	if (vaultPath(path, sizeof(path), 0, username) != VAULT_OK)
		return -1;
	FILE* file = fopen(path, "r");
	if (file != NULL)
	{
		fclose(file);
		return 0;
	}
	return -2;
}

/*
* Retrieves a hidden password
*
* @param password - The password being entered
* @param printText - The text being printed for password prompt
*
* @return -1 if failed to get password
* @return 0 on success
*/
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

/*
* Disables command line echo
*/
void disable_echo()
{
	struct termios t;
	tcgetattr(STDIN_FILENO, &t);

	t.c_lflag &= ~ECHO;

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

/*
* Enables command line echo
*/
void enable_echo()
{
	struct termios t;
	tcgetattr(STDIN_FILENO, &t);

	t.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

/*
* Reports which error caused a problem
* 
* @param rc - The error check number
*/
static void reportError(int rc)
{
	switch (rc) {
	case VAULT_ERR_NOT_FOUND:  printf("No vault found — run 'init' first.\n"); break;
	case VAULT_ERR_AUTH:       printf("Wrong master password or corrupted vault.\n"); break;
	case VAULT_ERR_ITEM:       printf("Item not found.\n"); break;
	case VAULT_ERR_FULL:       printf("Vault is full.\n"); break;
	case VAULT_ERR_FIELD_LEN:  printf("Field too long (max 127 bytes).\n"); break;
	case VAULT_ERR_FIELD_CHAR: printf("Fields can't contain tabs or newlines.\n"); break;
	case VAULT_ERR_IO:         printf("Storage error accessing the vault file.\n"); break;
	default:                   printf("Unexpected internal error.\n"); break;
	}
}