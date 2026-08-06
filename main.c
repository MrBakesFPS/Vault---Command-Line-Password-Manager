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
void loginVault(const VaultSession* session);
int verifyUsername(char username[SIZE_128]);
int readSecret(char secret[SIZE_128], const char* printText);
void disable_echo();
void enable_echo();
static void reportError(int rc);

//======================================================================
int main(int argc, char*argv[])
{
	char username[SIZE_128];
	char password[SIZE_128];
	char confirmPass[SIZE_128];
	VaultSession session;
	int status;

	closeSession(&session);

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
			if (readSecret(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}

			// Derive the key once here; every command in the session
			// below reuses it instead of re-running the 600k iterations.
			int rc = openSession(password, username, &session);
			explicit_bzero(password, sizeof password);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				status = -1;
				goto cleanup;
			}
			printf("\nType 'help' for a list of commands\n\n");
			loginVault(&session);
		}
		else if (strcmp(argv[1], "init") == 0)
		{
			if (verifyUsername(username) == 0)
			{
				printf("User vault already exist!\n");
				status = -1;
				goto cleanup;
			}
			if (readSecret(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (readSecret(confirmPass, "Confirm Password: ") == -1)
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
			if (readSecret(password, "Password: ") == -1)
			{
				status = -1;
				goto cleanup;
			}
			if (readSecret(confirmPass, "Confirm Password: ") == -1)
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

			// Opening the session is what proves the master password
			// before anything gets deleted.
			int rc = openSession(password, username, &session);
			explicit_bzero(password, sizeof password);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				status = -1;
				goto cleanup;
			}

			rc = closeVault(&session);
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
	closeSession(&session);
	explicit_bzero(username, sizeof username);
	explicit_bzero(password, sizeof password);
	explicit_bzero(confirmPass, sizeof confirmPass);

	return status;
}

/*
 * Usage: vault init | login | close
 */
void printUsage()
{
	printf("Usage: vault init | login | close\n");
}

/*
* Runs the interactive vault CLI against an already unlocked session.
* The master password is not asked for again; openSession already
* derived and verified the key.
*
* @param session - The unlocked session
*/
void loginVault(const VaultSession* session)
{
	char userInput[SIZE_128] = "";
	while (strcmp(userInput, "exit") != 0)
	{
		printf("%s@vault> ", session->username);
		if (fgets(userInput, SIZE_128, stdin) == NULL)
			break;
		userInput[strcspn(userInput, "\n")] = '\0';

		if (strcmp(userInput, "help") == 0)
		{
			printf("\n");
			printf(" * help -- Shows a list of commands.\n");
			printf(" * add -- Adds a password to the vault.\n");
			printf(" * remove -- Removes a password from the vault.\n");
			printf(" * replace -- Replaces the password of an entry.\n");
			printf(" * list -- Lists all sites and users in the vault.\n");
			printf(" * get -- Gets the specified sites, username and password.\n");
			printf(" * exit -- Exits the vault.\n\n");
		}
		else if (strcmp(userInput, "add") == 0)
		{
			printf("\n");
			char site[SIZE_128] = "";
			char user[SIZE_128] = "";
			char pass[SIZE_128] = "";

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
			printf("\n");

			int rc = addEntry(site, user, pass, session);
			explicit_bzero(pass, sizeof pass);
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
			printf("\n");
			char site[SIZE_128] = "";
			char user[SIZE_128] = "";

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

			int rc = removeEntry(site, user, session);
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
			int rc = list(session);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
		}
		else if (strcmp(userInput, "get") == 0)
		{
			printf("\n");
			char site[SIZE_128] = "";
			printf("Site: ");
			if (fgets(site, SIZE_128, stdin) != NULL)
			{
				site[strcspn(site, "\n")] = '\0';
			}

			int rc = get(site, session);
			printf("\n");
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
		}
		else if (strcmp(userInput, "replace") == 0)
		{
			printf("\n");
			char site[SIZE_128] = "";
			char user[SIZE_128] = "";
			char newPass[SIZE_128] = "";

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
			printf("New Pass: ");
			disable_echo();
			if (fgets(newPass, SIZE_128, stdin) != NULL)
			{
				newPass[strcspn(newPass, "\n")] = '\0';
			}
			enable_echo();
			printf("\n");

			int rc = replaceEntry(site, user, newPass, session);
			explicit_bzero(newPass, sizeof newPass);
			if (rc != VAULT_OK)
			{
				reportError(rc);
				printf("\n");
				continue;
			}
			printf("Password replaced successfully!\n\n");
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
	username[0] = '\0';
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
 * Reads one line from stdin with terminal echo off. This only collects
 * the input; nothing is checked against the vault here. openSession is
 * what actually verifies a master password.
 *
 * @param secret - Buffer receiving the entered text
 * @param printText - The text being printed for the prompt
 *
 * @return -1 if the read failed (EOF or closed stdin), not if the
 *         entered value was wrong - this function has no way to know
 * @return 0 on success
 */
int readSecret(char secret[SIZE_128], const char* printText)
{
	printf("%s", printText);
	secret[0] = '\0';
	disable_echo();
	if (fgets(secret, SIZE_128, stdin) != NULL)
	{
		enable_echo();
		secret[strcspn(secret, "\n")] = '\0';
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
