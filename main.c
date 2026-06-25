/* =====================================================================
   @Author:			Tyson Koopman-Baker
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
void loginVault(char username[SIZE_128]);
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
	int status;
	if (argc < 2)
	{
		printUsage();
	}
	else if (argc == 2)
	{
		if (strcmp(argv[1], "login") == 0)
		{
			if (verifyUsername(username) != 0)
			{
				printf("User vault doesnt't exist!\n");
				status = -1;
				goto cleanup;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			int rc = confirmPassword(password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				status = -1;
				goto cleanup;
			}
			printf("\nType 'help' for a list of commands\n\n");
			loginVault(username);
		}
		else if (strcmp(argv[1], "init") == 0)
		{
			if (verifyUsername(username) == 0)
			{
				printf("User vault already exist!\n");
				status = -1;
				goto cleanup;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (verifyPassword(confirmPass, "Confirm Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (strcmp(password, confirmPass) != 0)
			{
				printf("Passwords don't match. Vault initialize failed!\n");
				status = -1;
				goto cleanup;
			}

			int rc = initVault(password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				status = -1;
				goto cleanup;
			}
			printf("Vault created successfully!\n");
		}
		else if (strcmp(argv[1], "close") == 0)
		{
			if (verifyUsername(username) != 0)
			{
				printf("User doesn't exist\n");
				status = -1;
				goto cleanup;
			}
			if (verifyPassword(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (verifyPassword(confirmPass, "Confirm Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (strcmp(password, confirmPass) != 0)
			{
				printf("Passwords don't match. Vault close failed!\n");
				status = -1;
				goto cleanup;
			}

			int rc = closeVault(password, username);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				status = -1;
				goto cleanup;
			}
			printf("Vault removed successfully!\n");
		}
		else
		{
			printUsage();
		}
	}
	else
	{
		printUsage();
	}
	status = 0;

cleanup:
	explicit_bzero(username, sizeof username);
	explicit_bzero(password, sizeof password);
	explicit_bzero(confirmPass, sizeof confirmPass);

	return status;
}

/*
 * Usage: vault init | add <site> <user> <pass> | get <site> | list | remove <site>
 */
void printUsage()
{
	printf("Usage: vault init | login | close\n");
}

/*
* Logs into and runs the vault CLI via username and password
* 
* @param username - The username for the user vault
*/
void loginVault(char username[SIZE_128])
{
	char userInput[SIZE_128] = "";
	char password[SIZE_128];
	while (strcmp(userInput, "exit") != 0)
	{
		printf("%s@vault> ", username);
		if (fgets(userInput, SIZE_128, stdin) == NULL)
			break;
		userInput[strcspn(userInput, "\n")] = '\0';
		printf("\n");
		
		if (strcmp(userInput, "help") == 0)
		{
			printf(" * help -- Shows a list of commands.\n");
			printf(" * add -- Adds a password to the vault.\n");
			printf(" * remove -- Removes a password from the vault.\n");
			printf(" * list -- Lists all sites and users in the vault.\n");
			printf(" * get -- Gets the specified sites, username and password.\n");
			printf(" * exit -- Exits the vault.\n\n");
		}
		else if (strcmp(userInput, "add") == 0)
		{
			char site[SIZE_128];
			char user[SIZE_128];
			char pass[SIZE_128];

			printf("Site: ");
			if (fgets(site, SIZE_128, stdin) != NULL)
			{
				site[strcspn(site, "\n")] = '\0';
			}
			printf("User: ");
			if (fgets(user, SIZE_128, stdin) != NULL)
			{
				user[strcspn(user, "\n")] = '\0';
			}
			printf("Pass: ");
			disable_echo();
			if (fgets(pass, SIZE_128, stdin) != NULL)
			{
				pass[strcspn(pass, "\n")] = '\0';
			}
			enable_echo();
			printf("\n\n");

			if (verifyPassword(password, "Master Password: ") == -1)
			{
				explicit_bzero(pass, sizeof pass);
				explicit_bzero(password, sizeof password);
				printf("Wrong password!\n");
				continue;
			}
			int rc = addEntry(site, user, pass, password, username);
			explicit_bzero(pass, sizeof pass);
			explicit_bzero(password, sizeof password);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
			printf("Password added to vault successfully!\n\n");
		}
		else if (strcmp(userInput, "remove") == 0)
		{
			char site[SIZE_128];
			char user[SIZE_128];

			printf("Site: ");
			if (fgets(site, SIZE_128, stdin) != NULL)
			{
				site[strcspn(site, "\n")] = '\0';
			}
			printf("User: ");
			if (fgets(user, SIZE_128, stdin) != NULL)
			{
				user[strcspn(user, "\n")] = '\0';
			}
			if (verifyPassword(password, "Master Password: ") == -1)
			{
				printf("Wrong password!\n\n");
				continue;
			}
			int rc = removeEntry(site, user, password, username);
			explicit_bzero(password, sizeof password);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
			printf("Password removed from vault successfully!\n\n");
		}
		else if (strcmp(userInput, "list") == 0)
		{
			if (verifyPassword(password, "Master Password: ") == -1)
			{
				explicit_bzero(password, sizeof password);
				printf("Wrong password!\n");
				continue;
			}
			int rc = list(password, username);
			explicit_bzero(password, sizeof password);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
		}
		else if (strcmp(userInput, "get") == 0)
		{
			char site[SIZE_128];
			printf("Site: ");
			if (fgets(site, SIZE_128, stdin) != NULL)
			{
				site[strcspn(site, "\n")] = '\0';
			}

			if (verifyPassword(password, "Master Password: ") == -1)
			{
				explicit_bzero(password, sizeof password);
				printf("Wrong password!\n");
				continue;
			}
			int rc = get(site, password, username);
			explicit_bzero(password, sizeof password);
			printf("\n");
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
		}
	}
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
