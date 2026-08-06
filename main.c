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
#include <poll.h>
#include <time.h>
#include "aes.h"
#include "passHash.h"
#include "vault.h"

// How long the unlocked session may sit at the prompt before it locks
// itself. The session holds a live vault key, so leaving it unattended
// indefinitely is the main risk of unlocking once per login.
// Override at build time with -DSESSION_TIMEOUT_SECONDS=N.
#ifndef SESSION_TIMEOUT_SECONDS
#define SESSION_TIMEOUT_SECONDS 300
#endif

// Report the timeout in whichever unit reads sensibly, so an overridden
// value doesn't produce "0 minutes".
#define TIMEOUT_AMOUNT (SESSION_TIMEOUT_SECONDS >= 120 ? SESSION_TIMEOUT_SECONDS / 60 : SESSION_TIMEOUT_SECONDS)
#define TIMEOUT_UNIT   (SESSION_TIMEOUT_SECONDS >= 120 ? "minutes" : "seconds")

//======================================================================

void printUsage();
void loginVault(const VaultSession* session);
int verifyUsername(char username[SIZE_128]);
int readSecret(char secret[SIZE_128], const char* printText);
void disable_echo();
void enable_echo();
static void reportError(int rc);
static int waitForInput(int seconds);
static int promptLine(char dest[SIZE_128], const char* prompt, int hidden);

// promptLine outcomes
#define PROMPT_OK       0
#define PROMPT_EOF    (-1)
#define PROMPT_TIMEOUT (-2)

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
	char prompt[SIZE_256];
	int timedOut = 0;
	int pr;

	snprintf(prompt, sizeof prompt, "%s@vault> ", session->username);

	while (strcmp(userInput, "exit") != 0)
	{
		pr = promptLine(userInput, prompt, 0);
		if (pr != PROMPT_OK)
		{
			timedOut = (pr == PROMPT_TIMEOUT);
			break;
		}

		if (strcmp(userInput, "help") == 0)
		{
			printf("\n");
			printf(" * help -- Shows a list of commands.\n");
			printf(" * add -- Adds a password to the vault.\n");
			printf(" * remove -- Removes a password from the vault.\n");
			printf(" * replace -- Replaces the password of an entry.\n");
			printf(" * list -- Lists all sites and users in the vault.\n");
			printf(" * get -- Gets the specified sites, username and password.\n");
			printf(" * exit -- Exits the vault.\n");
			printf("\nThe vault locks itself after %d %s with no input.\n\n",
				TIMEOUT_AMOUNT, TIMEOUT_UNIT);
		}
		else if (strcmp(userInput, "add") == 0)
		{
			printf("\n");
			char site[SIZE_128] = "";
			char user[SIZE_128] = "";
			char pass[SIZE_128] = "";

			if ((pr = promptLine(site, "Site: ", 0)) != PROMPT_OK
				|| (pr = promptLine(user, "User: ", 0)) != PROMPT_OK
				|| (pr = promptLine(pass, "Pass: ", 1)) != PROMPT_OK)
			{
				explicit_bzero(pass, sizeof pass);
				timedOut = (pr == PROMPT_TIMEOUT);
				break;
			}

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

			if ((pr = promptLine(site, "Site: ", 0)) != PROMPT_OK
				|| (pr = promptLine(user, "User: ", 0)) != PROMPT_OK)
			{
				timedOut = (pr == PROMPT_TIMEOUT);
				break;
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
			if ((pr = promptLine(site, "Site: ", 0)) != PROMPT_OK)
			{
				timedOut = (pr == PROMPT_TIMEOUT);
				break;
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

			if ((pr = promptLine(site, "Site: ", 0)) != PROMPT_OK
				|| (pr = promptLine(user, "User: ", 0)) != PROMPT_OK
				|| (pr = promptLine(newPass, "New Pass: ", 1)) != PROMPT_OK)
			{
				explicit_bzero(newPass, sizeof newPass);
				timedOut = (pr == PROMPT_TIMEOUT);
				break;
			}

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

	// Reached from the main prompt and from any sub-prompt, so a command
	// abandoned half way through locks the vault too.
	if (timedOut)
		printf("\nSession locked after %d %s idle. Run 'vault login' to unlock.\n",
			TIMEOUT_AMOUNT, TIMEOUT_UNIT);
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
 * Waits for stdin to become readable, up to a deadline.
 *
 * The deadline is computed once up front, so a signal arriving partway
 * through cannot extend the wait by restarting the clock.
 *
 * @param seconds - How long to wait before giving up
 *
 * @return -1 on error
 * @return 0 if the time ran out with no input
 * @return 1 if stdin is readable (which includes reaching EOF)
 */
static int waitForInput(int seconds)
{
	struct timespec deadline;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
		return -1;
	deadline.tv_sec += seconds;

	for (;;)
	{
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;

		long msLeft = (long)(deadline.tv_sec - now.tv_sec) * 1000L
			+ (deadline.tv_nsec - now.tv_nsec) / 1000000L;
		if (msLeft <= 0)
			return 0;

		struct pollfd pfd;
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;

		int r = poll(&pfd, 1, (int)msLeft);
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		return r > 0 ? 1 : 0;
	}
}

/*
 * Prints a prompt and reads one line, subject to the session idle
 * timeout. Used for every prompt inside an unlocked session so that
 * walking away part way through a command locks the vault just as
 * walking away at the main prompt does.
 *
 * @param dest - Buffer receiving the line, emptied on any failure
 * @param prompt - Text to print before waiting
 * @param hidden - Non-zero to read with terminal echo off
 *
 * @return PROMPT_OK on success
 * @return PROMPT_EOF if stdin ended or the read failed
 * @return PROMPT_TIMEOUT if the idle limit expired
 */
static int promptLine(char dest[SIZE_128], const char* prompt, int hidden)
{
	dest[0] = '\0';
	printf("%s", prompt);
	// Prompts carry no trailing newline, so flush before blocking.
	fflush(stdout);

	// Echo has to be off before the user types, not after the wait
	// returns: the terminal echoes each keystroke as it is entered, and
	// in canonical mode poll only reports the line once Enter is hit. So
	// waiting first would put the whole secret on screen.
	if (hidden)
		disable_echo();

	int ready = waitForInput(SESSION_TIMEOUT_SECONDS);
	char* got = (ready > 0) ? fgets(dest, SIZE_128, stdin) : NULL;

	if (hidden)
	{
		enable_echo();
		printf("\n");
	}

	if (ready == 0)
	{
		dest[0] = '\0';
		return PROMPT_TIMEOUT;
	}
	if (got == NULL)
	{
		dest[0] = '\0';
		return PROMPT_EOF;
	}

	dest[strcspn(dest, "\n")] = '\0';
	return PROMPT_OK;
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
