/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			aes.h
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the file encrypting header file
				which uses AES and other encryption/dectryption
				techniques
===================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <sys/random.h>
#include <errno.h>
#include <stddef.h>

//======================================================================

/*
* Encrypts a text buffer with a given key, nonce, and aad while creating a
a tag for the file to be used for decryption verification
*
* @param key - The key used to encrypt the text
* @param nonce - 12 random bytes created for every encryption
* @param text - The text being enrypted
* @param textLen - The length of the text for a pointer reference
* @param aad - A pregenerated tag, usually 4 byte magic with 2 byte version number
* @param aadLen - The length of the aad
* @param tag - The tag being created for decryption verification
*/
void gcmEncrypt(const uint32_t key[8], uint8_t nonce[12], uint8_t* text, size_t txtLen, uint8_t* aad, size_t aadLen, uint8_t tag[16]);

/*
* Decrypts a text buffer from a given key, nonce, and aad while verifying
* a compare tag with the given tag
*
* @param key - The key used to encrypt the text
* @param nonce - 12 random bytes created for every encryption
* @param text - The text being enrypted
* @param textLen - The length of the text for a pointer reference
* @param aad - A pregenerated tag, usually 4 byte magic with 2 byte version number
* @param aadLen - The length of the aad
* @param tag - The tag being created for decryption verification
*/
int gcmDecrypt(const uint32_t key[8], uint8_t nonce[12], uint8_t* text, size_t txtLen, uint8_t* aad, size_t aadLen, uint8_t tag[16]);

/*
* Folds an aad and text into a block using a key to produce an encrypted state
* 
* @param key - The key being folded into the state
* @param aadBuf - The aad being folded into the state
* @param aadLen - The length of the aad
* @param cipTxt - The text being folded into the state
* @param cipLen - The length of the text
* @param out - The out state being folded into
*/
void ghash(uint32_t key[4], uint8_t* aadBuf, size_t aadLen, uint8_t* cipTxt, size_t cipLen, uint32_t out[4]);

/*
* Folds a buffer into a 16 byte block and and then folds that result
* into a 16 byte key
*
* @param block - The 16 byte block being folded into
* @param key - The key being folded into
* @param buf - The buffer folding into the block
* @param bufLen - The length of the buffer
*/
void foldBuf(uint32_t block[4], uint32_t key[4], uint8_t* buf, size_t bufLen);

/*
* Folds a 16 byte 0x00 block into a 16 byte key
*
* @param schedule - The key schedule being used
* @param out - The output block from the key
*/
void e128(const uint32_t schedule[60], uint32_t out[4]);

/*
* Folds a 16 byte block into a 16 byte key
* 
* @param key - The base key being folded into
* @param block - The block folding into the base and returned
*/
void gf128(uint32_t keya[4], uint32_t block[4]);

/*
* Runs a created keystream (nonce and counter pad) through AES using a given key
* in order to create a new keystream to fold-encrypt into the input buffer
*
* @param schedule - The AES key schedule being used
* @param nonce - The nonce to use for the keystream
* @param buf - The buffer being folded into
* @param len - The length of the buffer
* @param counterStart - The counter for each fold
*/
void ctr(const uint32_t schedule[60], const uint8_t nonce[12], uint8_t* buf, size_t len, uint32_t counterStart);

/*
* Encrypts a given 16 byte state with a 32 byte block
*
* @param schedule - The AES key schedule used to decrypted
* @param state - The final state
*/
void runAES(const uint32_t schedule[60], uint8_t state[16]);

/*
* Encrypts a given 16 byte state with a 32 byte block
* 
* @param block - The block being decrypted
* @param state - The final state
*/
void runDeAES(const uint32_t block[8], uint8_t state[16]);

/*
* Initializes the S-Box and Inverse S-Box for encryption/decryption
*
* @param sbox - The S-Box being initialized
* @param invSbox - The Inverse S-Box being initialized
*/
void initSbox(uint8_t sbox[256], uint8_t invSbox[256]);

/*
* Creates an AES Key schedule from a given AES Key
*
* @param mainKey - The main key being used to create the key schedule
* @param keySchedule - The key schedule being created
* @param sbox - The sbox being used for transformations
*/
void createScheduleAES(const uint32_t mainKey[8], uint32_t keySchedule[60], const uint8_t sbox[256]);

/*
* Adds an AES round key into the current 4x4 byte state (16 bytes)
*
* @param state - The current state being added to
* @param roundKey - The current round key being added
*/
void addRoundKey(uint8_t state[16], const uint8_t roundKey[16]);

/*
* Subs each of the 4x4 grid of bytes (16 bytes) through the given S-Box
*
* @param state - The current state being swapped
* @param sbox - The S-Box being used
*/
void subBytes(uint8_t state[16], const uint8_t sbox[256]);

/*
* Subs each of the 4x4 grid of bytes (16 bytes) through the given Inverse S-Box
*
* @param state - The current state rows being swapped
* @param invsbox - The inverse S-Box being used
*/
void invSubBytes(uint8_t state[16], const uint8_t invsbox[256]);

/*
* Shifts the rows of a 4x4 grid of bytes (16 bytes) left based on row number
*
* @param state - The current state rows being shifted
*/
void shiftRows(uint8_t state[16]);

/*
* Reverse shifts the rows of a 4x4 grid of bytes (16 bytes) right based on row number
*
* @param state - The current state rows being shifted
*/
void invShiftRows(uint8_t state[16]);

/*
* Mixes the columns of a 4x4 grid of bytes (16 bytes) by xoring multiplied bytes together
*
* @param state - The current state columns being mixed
*/
void mixColumns(uint8_t state[16]);

/*
* Unmixes the columns of a 4x4 grid of bytes (16 bytes) by xoring multiplied bytes together
*
* @param state - The current state columns being mixed
*/
void invMixColumns(uint8_t state[16]);

/*
* Multiplies the given byte by 2, carrying the top bit to the other side
*
* @param x - The byte being multiplied
*
* @return - The modified byte
*/
uint8_t xtime(uint8_t x);

/*
* Multiplies the given byte by 2, nine times, carrying the top bit to the other side
*
* @param a - The byte being multiplied
*
* @return - The modified byte
*/
uint8_t mul9(uint8_t a);

/*
* Multiplies the given byte by 2, eleven times, carrying the top bit to the other side
*
* @param a - The byte being multiplied
*
* @return - The modified byte
*/
uint8_t mul11(uint8_t a);

/*
* Multiplies the given byte by 2, thirteen times, carrying the top bit to the other side
*
* @param a - The byte being multiplied
*
* @return - The modified byte
*/
uint8_t mul13(uint8_t a);

/*
* Multiplies the given byte by 2, fourteen times, carrying the top bit to the other side
*
* @param a - The byte being multiplied
*
* @return - The modified byte
*/
uint8_t mul14(uint8_t a);

/*
* Transforms a word by rotating left, pushing through the
* S-Box, and xoring the word with the RCON constants
*
* @param wordIn - The word being transformed
* @param rcon - The word constant for the xor operations
* @param sbox - The S-Box being used
*
* @return - The swapped word
*/
uint32_t transformWord(const uint32_t wordIn, const uint32_t rcon, const uint8_t sbox[256]);

/*
* Pushes a whole word (4 bytes) through the S-Box
*
* @param wordIn - The word being pushed through the S-Box
* @param sbox - The S-Box being used
* 
* @return - The swapped word
*/
uint32_t pushSbox(const uint32_t wordIn, const uint8_t sbox[256]);

/*
* Rotates a word one whole byte (8 bits) to the left
* 
* @param x - The word being rotated
* 
* @return - The rotated word
*/
uint32_t rotL(uint32_t x);


//======================================================================

// This was a helper function found from the wikipedia Rijndael S-Box page :D
#define ROTL8(x, shift) ((uint8_t)((x) << (shift)) | ((x) >> (8 - (shift))))

//======================================================================

