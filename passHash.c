/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			passHash.c
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the password hashing implementation file which
				uses a pbkdf2 and SHA-256
===================================================================== */

#include "passHash.h"

//======================================================================
uint8_t* pbkdf2(uint8_t* password, size_t passLen, uint8_t* salt, size_t saltLen, size_t iterations)
{
    size_t msgLen = saltLen + 4;
    uint8_t* msg = malloc(msgLen);
    
    for (size_t i = 0; i < saltLen; i++)
	    msg[i] = salt[i];
    
    msg[saltLen] = 0x00;
    msg[saltLen+1] = 0x00;
    msg[saltLen+2] = 0x00;
    msg[saltLen+3] = 0x01;

    uint8_t* hash = hmac(password, passLen, msg, msgLen);
    free(msg);

    uint8_t* finalHash = malloc(SIZE_32);
    for (size_t i = 0; i < SIZE_32; i++)
		finalHash[i] = hash[i];

    for (size_t j = 1; j < iterations; j++)
    {
        uint8_t* next = hmac(password, passLen, hash, SIZE_32);
        free(hash);
		hash = next;
        for (size_t i = 0; i < SIZE_32; i++)
			finalHash[i] ^= hash[i];
    }
    free(hash);

    return finalHash;
}

//======================================================================
uint8_t* hmac(uint8_t* key, size_t keyLen, uint8_t* message, size_t msgLength)
{
	uint8_t* normalized = normalizeK(key, keyLen);

	uint8_t* inPad = malloc(SIZE_64);
	uint8_t* outPad = malloc(SIZE_64);

	for (size_t x = 0; x < SIZE_64; x++)
	{
		inPad[x] = normalized[x] ^ 0x36;
		outPad[x] = normalized[x] ^ 0x5c;
	}

	size_t innerLen = SIZE_64 + msgLength;
	uint8_t* innerBuf = malloc(innerLen);
	for (size_t x = 0; x < SIZE_64; x++)
	{
		innerBuf[x] = inPad[x];
	}
	for (size_t x = 0; x < msgLength; x++)
	{
		innerBuf[SIZE_64 + x] = message[x];
	}

	uint8_t* innerRes = sha256(innerBuf, innerLen);

	uint8_t* outerBuf = malloc(SIZE_64 + SIZE_32);
	for (size_t x = 0; x < SIZE_64; x++)
	{
		outerBuf[x] = outPad[x];
	}
	for (size_t x = 0; x < SIZE_32; x++)
	{
		outerBuf[SIZE_64 + x] = innerRes[x];
	}

	uint8_t* result = sha256(outerBuf, SIZE_64 + SIZE_32);
	free(normalized);
	free(inPad);
	free(outPad);
	free(innerBuf);
	free(innerRes);
	free(outerBuf);
	return result;
}
//======================================================================

uint8_t* normalizeK(uint8_t* message, size_t msgLength)
{
	uint8_t* normalized = malloc(SIZE_64);

	if (msgLength > SIZE_64)
	{
		uint8_t* temp = sha256(message, msgLength);
		for (size_t x = 0; x < SIZE_32; x++)
		{
			normalized[x] = temp[x];
		}
		free(temp);
		for (size_t x = SIZE_32; x < SIZE_64; x++)
		{
			normalized[x] = 0x00;
		}
	}
	else if (msgLength == SIZE_64)
	{
		for (size_t x = 0; x < SIZE_64; x++)
		{
			normalized[x] = message[x];
		}
	}
	else
	{
		for (size_t x = 0; x < msgLength; x++)
		{
			normalized[x] = message[x];
		}
		for (size_t x = msgLength; x < SIZE_64; x++)
		{
			normalized[x] = 0x00;
		}
	}
	return normalized;
}
//======================================================================

uint8_t* sha256(uint8_t* message, size_t msgLength)
{
	size_t blockCount;
	uint8_t* padded = padMessage(message, &blockCount, msgLength);

	uint32_t state[SIZE_8];
	for (size_t i = 0; i < 8; i++)
		state[i] = BASE[i];

	uint32_t block[SIZE_16];
	uint32_t word[SIZE_64];
	
	for (size_t b = 0; b < blockCount; b++)
	{
		for (size_t i = 0; i < 16; i++)
		{
			block[i] = ((uint32_t)padded[(b * 64 + i * 4)] << 24) | ((uint32_t)padded[(b * 64 + i * 4) + 1] << 16) | ((uint32_t)padded[(b * 64 + i * 4) + 2] << 8) | (uint32_t)padded[(b * 64 + i * 4) + 3];
		}
		createScheduleSHA(block, word);
		compress(word, state);
	}

	uint8_t* out = malloc(SIZE_32);
	for (size_t i = 0; i < 8; i++)
	{
		out[i * 4] = (state[i] >> 24) & 0xff;
		out[i * 4 + 1] = (state[i] >> 16) & 0xff;
		out[i * 4 + 2] = (state[i] >> 8) & 0xff;
		out[i * 4 + 3] = state[i] & 0xff;
	}
	free(padded);
	return out;
}
//======================================================================

uint8_t* padMessage(uint8_t* input, size_t* numBlocks, size_t msgLength)
{
	size_t length = msgLength + 1;
	uint8_t* myChar = malloc(length);

	for (size_t x = 0; x < msgLength; x++)
	{
		myChar[x] = input[x];
	}

	myChar[msgLength] = 0x80;

	while (length % 64 != 56)
	{
		length += 1;
		uint8_t* temp = realloc(myChar, length);
		if (temp == NULL)
		{
			free(myChar);
			return NULL;
		}
		myChar = temp;
		myChar[length - 1] = 0x00;
	}

	length += 8;
	*numBlocks = length / 64;
	uint8_t* temp2 = realloc(myChar, length);
	if (temp2 == NULL)
	{
		free(myChar);
		return NULL;
	}
	myChar = temp2;

	unsigned long bitLen = (unsigned long)msgLength * 8;

	for (size_t x = length - 1; x >= length - 8; x--)
	{
		myChar[x] = bitLen & 0xff;
		bitLen >>= 8;
	}

	return myChar;
}
//======================================================================

void createScheduleSHA(const uint32_t block[16], uint32_t key[64])
{
	for (int t = 0; t < 16; t++)
		key[t] = block[t];

	for (int t = 16; t < 64; t++)
		key[t] = mod232(mod232(key[t - 16], o0(key[t - 15])), mod232(key[t - 7], o1(key[t - 2])));
}
//======================================================================

void compress(const uint32_t word[64], uint32_t state[8])
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
	for (int t = 0; t < 64; t++)
	{
		uint32_t T1 = h + e1(e) + choose(e, f, g) + KCON[t] + word[t];
		uint32_t T2 = e0(a) + majority(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}
//======================================================================

uint32_t rotR(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}
//======================================================================

uint32_t shiftR(uint32_t x, int n)
{
	return x >> n;
}
//======================================================================

uint32_t mod232(uint32_t a, uint32_t b)
{
	return a + b;
}
//======================================================================

uint32_t xorOps(uint32_t a, uint32_t b)
{
	return a ^ b;
}
//======================================================================

uint32_t choose(uint32_t e, uint32_t f, uint32_t g)
{
	return (e & f) ^ (~e & g);
}
//======================================================================

uint32_t majority(uint32_t a, uint32_t b, uint32_t c)
{
	return (a&b)^(a&c)^(b&c);
}
//======================================================================

uint32_t e0(uint32_t x)
{
	return rotR(x,2) ^ rotR(x,13) ^ rotR(x,22);
}
//======================================================================

uint32_t e1(uint32_t x)
{
	return rotR(x,6) ^ rotR(x,11) ^ rotR(x,25);
}
//======================================================================

uint32_t o0(uint32_t x)
{
	return rotR(x,7) ^ rotR(x,18) ^ shiftR(x,3);
}
//======================================================================

uint32_t o1(uint32_t x)
{
	return rotR(x,17) ^ rotR(x,19) ^ shiftR(x,10);
}
//======================================================================





