/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			passHash.h
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the password hashing header file which uses a
				pbkdf2 and SHA-256
===================================================================== */

#ifndef PASSHASH_H
#define PASSHASH_H

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
* Creates a hash key from a given password, salt and iteration count
*
* @param password - The password being derived
* @param passLen - The length of the password
* @param salt - The salt being mixed into the password
* @param saltLen - The length of the salt
* @param iterations - The cost iteration used to derive the key
*
* @return uint8_t* - Returns the generated hash key
*/
uint8_t* pbkdf2(uint8_t* password, size_t passLen, uint8_t* salt, size_t saltLen, size_t iterations);

/*
* Creates a hashed message from a given key and message
*
* @param key - The key used for hashing
* @param keyLen - The length of the key
* @param message - The message being hashed
* @param msgLength - The length of the message
*
* @return uint8_t* - Returns the mixed hash message
*/

uint8_t* hmac(uint8_t* key, size_t keyLen, uint8_t* message, size_t msgLength);
/*
* Normalizes a message to a 64 byte usable block
*
* @param message - The message being normalized
* @param msgLen - The length of the message
*
* @return uint8_t* - Returns the normalized message
*/
uint8_t* normalizeK(uint8_t* message, size_t msgLength);

/*
* Creates a hashed message from folding a schedule
* into the message block per 64 byte block
* 
* @param message - The message being turned into a hash
* @param msgLength - The length of the message
* 
* @return uint8_t* - Returnes the basic hashed message
*/
uint8_t* sha256(uint8_t* message, size_t msgLength);

/*
* Pads a message with 0s and returns the number
* of blocks created from the pad
*
* @return uint8_t* - Returns the padded message
*/
uint8_t* padMessage(uint8_t* input, size_t* numBlocks, size_t msgLength);

/*
* Creates a 256 byte key schedule for hashing/mixing a 64 byte block
*
* @param block - The block creating the key
* @param key - Returns key schedule being created from the block
*/
void createScheduleSHA(const uint32_t block[16], uint32_t key[64]);

/*
* Creates an 8 word state from a 64 word block
*
* @param word - The 64 word (256 bytes) starting state
* @param state - Returns the 8 word (32 byte) compressed state
*/
void compress(const uint32_t word[64], uint32_t state[8]);

/*
* Rotates a word (4 bytes) right by n bits
*
* @param x - The word being rotated
* @param n - The number of bits to rotate
*
* @return uint32_t - Returns the rotated word
*/
uint32_t rotR(uint32_t x, int n);

/*
* Shifts a word (4 bytes) right by n bits
*
* @param x - The word being shifted
* @param n - The number of bits to shift
* 
* @return uint32_t - Returns the shifted word
*/
uint32_t shiftR(uint32_t x, int n);

/*
* Mod 2^32s two words (4 bytes each) together
*
* @param a - Word #1
* @param b - Word #2
*
* @return uint32_t - The combined word
*/
uint32_t mod232(uint32_t a, uint32_t b);

/*
* Xors two words (4 bytes each) together
*
* @param a - Word #1
* @param b - Word #2
*
* @return uint32_t - The combined word
*/
uint32_t xorOps(uint32_t a, uint32_t b);

/*
* Chooses each bit for word (4 bytes) e based on what bit f and g are
*
* @param e - Word #1
* @param f - Word #2
* @param g - Word #2
*
* @return uint32_t - The chosen word
*/
uint32_t choose(uint32_t e, uint32_t f, uint32_t g);

/*
* Chooses each bit for a final word based on the majority
* of bits from three words (4 bytes each)
*
* @param a - Word #1
* @param b - Word #2
* @param c - Word #2
*
* @return uint32_t - The chosen word
*/
uint32_t majority(uint32_t a, uint32_t b, uint32_t c);

/*
* Xors 3 copies of rotate rights from a given word (4 bytes)
*
* @param x - The word being modified
* 
* @return - The modified word
*/
uint32_t e0(uint32_t x);

/*
* Xors 3 copies of rotate rights from a given word (4 bytes)
*
* @param x - The word being modified
*
* @return - The modified word
*/
uint32_t e1(uint32_t x);

/*
* Xors 2 copies of rotate rights and a copy
* of a shift right from a given word (4 bytes)
*
* @param x - The word being modified
*
* @return - The modified word
*/
uint32_t o0(uint32_t x);

/*
* Xors 2 copies of rotate rights and a copy
* of a shift right from a given word (4 bytes)
*
* @param x - The word being modified
*
* @return - The modified word
*/
uint32_t o1(uint32_t x);

//======================================================================

enum { SIZE_4 = 4, SIZE_8 = 8, SIZE_16 = 16, SIZE_32 = 32, SIZE_64 = 64, SIZE_128 = 128, SIZE_256 = 256 };
static const uint32_t BASE[SIZE_8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
static const uint32_t KCON[SIZE_64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#endif