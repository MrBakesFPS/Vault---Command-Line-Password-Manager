/* =====================================================================
@Author:		Tyson Koopman-Baker
@Date:			6/17/2026
@File:			aes.c
@Version:		1.0
@IDE:			Vim and Visual Studios
@Description:	This is the file encrypting implementation file
				which uses AES and other encryption/dectryption
				techniques
===================================================================== */
#include "aes.h"
#include "passHash.h"

//======================================================================

static uint8_t sbox[256];
static uint8_t invsbox[256];
static int sboxReady = 0;

static void ensureSbox(void)
{
    if (!sboxReady)
    {
        initSbox(sbox, invsbox);
        sboxReady = 1;
    }
}
//======================================================================

void gcmEncrypt(const uint32_t key[8], uint8_t nonce[12], uint8_t* text, size_t txtLen, uint8_t* aad, size_t aadLen, uint8_t tag[16])
{
	ensureSbox();
	uint32_t schedule[60];
	createScheduleAES(key, schedule, sbox);

	uint32_t foldKey[4];
	uint8_t foldNonce[16];
	uint32_t state[4];

	e128(schedule, foldKey);
	
	for (size_t i = 0; i < 12; i++)
		foldNonce[i] = nonce[i];
	
	foldNonce[12] = 0x0;
	foldNonce[13] = 0x0;
	foldNonce[14] = 0x0;
	foldNonce[15] = 0x01;

	runAES(schedule, foldNonce);
	
	ctr(schedule, nonce, text, txtLen, 2);

	ghash(foldKey, aad, aadLen, text, txtLen, state);

	for (size_t x = 0; x < 4; x++)
	{
		uint32_t extendNonce = ((uint32_t)foldNonce[x * 4] << 24) | ((uint32_t)foldNonce[x * 4 + 1] << 16) | ((uint32_t)foldNonce[x * 4 + 2] << 8) | (uint32_t)foldNonce[x * 4 + 3];
		uint32_t temp = state[x] ^ extendNonce;
		tag[x * 4] = (temp >> 24) & 0xff;
		tag[x * 4 + 1] = (temp >> 16) & 0xff;
		tag[x * 4 + 2] = (temp >> 8) & 0xff;
		tag[x * 4 + 3] = temp & 0xff;
	}
}
//======================================================================

int gcmDecrypt(const uint32_t key[8], uint8_t nonce[12], uint8_t* text, size_t txtLen, uint8_t* aad, size_t aadLen, uint8_t tag[16])
{
	ensureSbox();
	uint32_t schedule[60];
	createScheduleAES(key, schedule, sbox);

	uint32_t foldKey[4];
	uint32_t state[4];
	uint8_t foldNonce[16];
	uint8_t compTag[16];

	e128(schedule, foldKey);

	for (size_t i = 0; i < 12; i++)
		foldNonce[i] = nonce[i];

	foldNonce[12] = 0x0;
	foldNonce[13] = 0x0;
	foldNonce[14] = 0x0;
	foldNonce[15] = 0x01;

	runAES(schedule, foldNonce);

	ghash(foldKey, aad, aadLen, text, txtLen, state);

	for (size_t x = 0; x < 4; x++)
	{
		uint32_t extendNonce = ((uint32_t)foldNonce[x * 4] << 24) | ((uint32_t)foldNonce[x * 4 + 1] << 16) | ((uint32_t)foldNonce[x * 4 + 2] << 8) | (uint32_t)foldNonce[x * 4 + 3];
		uint32_t temp = state[x] ^ extendNonce;
		compTag[x * 4] = (temp >> 24) & 0xff;
		compTag[x * 4 + 1] = (temp >> 16) & 0xff;
		compTag[x * 4 + 2] = (temp >> 8) & 0xff;
		compTag[x * 4 + 3] = temp & 0xff;
	}

	uint8_t diff = 0;
	for (size_t x = 0; x < 16; x++)
		diff |= compTag[x] ^ tag[x];

	if (diff == 0)
	{
		ctr(schedule, nonce, text, txtLen, 2);
		return 0;
	}
	else
	{
		for (size_t x = 0; x < txtLen; x++)
		{
			text[x] = 0x00;
		}
		return -1;
	}
}
//======================================================================

void ghash(uint32_t key[4], uint8_t* aadBuf, size_t aadLen, uint8_t* cipTxt, size_t cipLen, uint32_t out[4])
{
	uint32_t temp[4] = {0x0, 0x0, 0x0, 0x0};
	
	if (aadLen != 0)
	{
		foldBuf(temp, key, aadBuf, aadLen);
	}	
	
	foldBuf(temp, key, cipTxt, cipLen);
	
	uint64_t addBits = (uint64_t)aadLen * 8;
	temp[0] ^= (addBits >> 32);
	temp[1] ^= (addBits & 0xffffffff);
	
	addBits = (uint64_t)cipLen * 8;
	temp[2] ^= (addBits >> 32);
	temp[3] ^= (addBits & 0xffffffff);
	
	gf128(key, temp);
	
	for (size_t x = 0; x < 4; x++)
	{
		out[x] = temp[x];
	}
}
//======================================================================

void foldBuf(uint32_t block[4], uint32_t key[4], uint8_t* buf, size_t bufLen)
{

	for (size_t x = 0; x < bufLen; x+=16)
	{
		if (x + 16 > bufLen)
		{
			for (size_t y = x; y < bufLen; y++)
			{
				block[(y - x) / 4] ^= (uint32_t)buf[y] << (3 - ((y - x) % 4)) * 8;
			}
		}
		else
		{
			for (size_t y = 0; y < 4; y++)
			{
				block[y] ^= (uint32_t)buf[y * 4 + x] << 24;
				block[y] ^= (uint32_t)buf[y * 4 + 1 + x] << 16;
				block[y] ^= (uint32_t)buf[y * 4 + 2 + x] << 8;
				block[y] ^= (uint32_t)buf[y * 4 + 3 + x];
			}
		}
		gf128(key, block);
	}
}
//======================================================================

void e128(const uint32_t schedule[60], uint32_t out[4])
{
	uint8_t temp[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	runAES(schedule, temp);
	for (size_t i = 0; i < 4; i++)
	{
		out[i] = ((uint32_t)temp[i * 4] << 24) | ((uint32_t)temp[i * 4 + 1] << 16) | ((uint32_t)temp[i * 4 + 2] << 8) | (uint32_t)temp[i * 4 + 3];
	}
}
//======================================================================

void gf128(uint32_t key[4], uint32_t block[4])
{
	uint32_t accumulator[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
	uint32_t shiftB[4];
	for (int i = 0; i < 4; i++)
	{
		shiftB[i] = block[i];
	}
	uint32_t checkBit = 0x80000000;
	uint32_t pushBit = 0x00000000;

	for (size_t x = 0; x < 4; x++)
	{
		for (size_t y = 0; y < 32; y++)
		{
			if ((shiftB[3] & 0x01) == 0x01)
				pushBit = 0xe1000000;
			else
				pushBit = 0x00000000;
			if ((key[x] & (checkBit >> y)) == (checkBit >> y))
			{
				for (size_t i = 0; i < 4; i++)
					accumulator[i] ^= shiftB[i];
			}
			for (size_t i = 4; i-- > 0; )
			{
				if (((shiftB[i] & 0x01) == 0x01) && i < 3)
					shiftB[i + 1] ^= 0x80000000;

				shiftB[i] >>= 1;
				if (i == 0)
					shiftB[i] ^= pushBit;
			}
		}
	}
	for (size_t i = 0; i < 4; i++)
	{
		block[i] = accumulator[i];
	}
}
//======================================================================

void ctr(const uint32_t schedule[60], const uint8_t nonce[12], uint8_t* buf, size_t len, uint32_t counterStart)
{
	uint8_t keystream[16];
	uint32_t counter = counterStart;

	for (size_t offset = 0; offset < len; offset+=16)
	{
		for (size_t i = 0; i < 12; i++)
		{
			keystream[i] = nonce[i];
		}
		keystream[12] = (counter >> 24) & 0xff;
		keystream[13] = (counter >> 16) & 0xff;
		keystream[14] = (counter >> 8) & 0xff;
		keystream[15] = counter & 0xff;

		runAES(schedule, keystream);

		size_t blockSize = (len - offset < 16) ? (len - offset) : 16;
		for (size_t i = 0; i < blockSize; i++)
		{
			buf[offset + i] ^= keystream[i];
		}
		counter++;
	}

}
//======================================================================

void runAES(const uint32_t schedule[60], uint8_t state[16])
{
	uint8_t currKey[16];

	for (size_t x = 0; x < 60; x += 4)
	{
		for (size_t y = x; y < x + 4; y++)
		{
			for (size_t z = 0; z < 4; z++)
			{
				currKey[(y - x) * 4 + z] = (schedule[y] >> (8 * (3 - z))) & 0xff;
			}
		}
		if (x == 0)
		{
			addRoundKey(state, currKey);
		}
		else if (x < 56)
		{
			subBytes(state, sbox);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, currKey);
		}
		else
		{
			subBytes(state, sbox);
			shiftRows(state);
			addRoundKey(state, currKey);
		}
	}
}
//======================================================================

void runDeAES(const uint32_t block[8], uint8_t state[16])
{

	uint8_t sbox[256];
	uint8_t invsbox[256];
	initSbox(sbox, invsbox);

	uint32_t schedule[60];
	uint8_t currKey[16]; // grabs first 4 32t from schedule

	createScheduleAES(block, schedule, sbox);
	for (int x = 56; x >= 0; x -= 4)
	{
		for (size_t y = (size_t)x; y < (size_t)x + 4; y++)
		{
			for (size_t z = 0; z < 4; z++)
			{
				currKey[(y - (size_t)x) * 4 + z] = (schedule[y] >> (8 * (3 - z))) & 0xff;
			}
		}
		if (x == 56)
		{
			addRoundKey(state, currKey);
			invShiftRows(state);
			invSubBytes(state, invsbox);
		}
		else if (x > 0)
		{
			addRoundKey(state, currKey);
			invMixColumns(state);
			invShiftRows(state);
			invSubBytes(state, invsbox);
		}
		else
		{
			addRoundKey(state, currKey);
		}
	}
}
//======================================================================

void initSbox(uint8_t sbox[256], uint8_t invSbox[256])
{
	uint8_t p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);   // p *= 3 in GF(2^8)
		q ^= q << 1;                                 // q *= 0xf6 (= 3^-1)
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;                    // affine transform
	} while (p != 1);
	sbox[0] = 0x63;

	for (size_t i = 0; i < 256; i++)   // inverse table, free: if S(i)=v then InvS(v)=i
		invSbox[sbox[i]] = i;
}
//======================================================================

void createScheduleAES(const uint32_t mainKey[8], uint32_t keySchedule[60], const uint8_t sbox[256])
{
	uint32_t rcon = 0x01000000;

	for (size_t t = 0; t < 8; t++)
		keySchedule[t] = mainKey[t];

	for (size_t t = 8; t < 60; t++)
	{
		if (t % 8 == 0)
		{
			keySchedule[t] = xorOps(keySchedule[t - 8], transformWord(keySchedule[t - 1], rcon, sbox));
			rcon <<= 1;
		}
		else if ((t - 4) % 8 == 0)
		{
			keySchedule[t] = xorOps(keySchedule[t - 8], pushSbox(keySchedule[t - 1], sbox));
		}
		else
			keySchedule[t] = xorOps(keySchedule[t - 8], keySchedule[t - 1]);
	}
}
//=====================================================================

void addRoundKey(uint8_t state[16], const uint8_t roundKey[16])
{
	for (size_t i = 0; i < 16; i++)
		state[i] ^= roundKey[i];
}
//======================================================================

void subBytes(uint8_t state[16], const uint8_t sbox[256])
{
	for (size_t i = 0; i < 16; i++)
		state[i] = sbox[state[i]];
}
//======================================================================

void invSubBytes(uint8_t state[16], const uint8_t invsbox[256])
{
	for (size_t i = 0; i < 16; i++)
		state[i] = invsbox[state[i]];
}
//======================================================================

void shiftRows(uint8_t state[16])
{
	uint8_t t;

	// row 1 (indices 1,5,9,13): rotate left 1
	t = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = t;

	// row 2 (2,6,10,14): rotate left 2  (swap the two pairs)
	t = state[2];
	state[2] = state[10];
	state[10] = t;

	t = state[6];
	state[6] = state[14];
	state[14] = t;

	// row 3 (3,7,11,15): rotate left 3 == rotate right 1
	t = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = t;
}
//======================================================================

void invShiftRows(uint8_t state[16])
{
	uint8_t t;

	// row 3 (3,7,11,15): rotate right 3 == rotate left 1
	t = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = t;

	// row 2 (2,6,10,14): rotate right 2  (swap the two pairs)
	t = state[14];
	state[14] = state[6];
	state[6] = t;

	t = state[10];
	state[10] = state[2];
	state[2] = t;

	// row 1 (indices 1,5,9,13): rotate right 1
	t = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = t;
}
//======================================================================

void mixColumns(uint8_t state[16])
{
	for (size_t c = 0; c < 4; c++)
	{
		uint8_t a0 = state[4 * c], a1 = state[4 * c + 1], a2 = state[4 * c + 2], a3 = state[4 * c + 3];
		state[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
		state[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
		state[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
		state[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
	}
}
//======================================================================

void invMixColumns(uint8_t state[16])
{
	for (size_t c = 0; c < 4; c++)
	{
		uint8_t a0 = state[4 * c], a1 = state[4 * c + 1], a2 = state[4 * c + 2], a3 = state[4 * c + 3];
		state[4 * c] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
		state[4 * c + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
		state[4 * c + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
		state[4 * c + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
	}
}
//======================================================================

uint8_t xtime(uint8_t x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}
//======================================================================

uint8_t mul9(uint8_t a)
{
	uint8_t x2 = xtime(a), x4 = xtime(x2), x8 = xtime(x4);
	return x8 ^ a;
}
//======================================================================

uint8_t mul11(uint8_t a)
{
	uint8_t x2 = xtime(a), x4 = xtime(x2), x8 = xtime(x4);
	return x8 ^ x2 ^ a;
}
//======================================================================

uint8_t mul13(uint8_t a)
{
	uint8_t x2 = xtime(a), x4 = xtime(x2), x8 = xtime(x4);
	return x8 ^ x4 ^ a;
}
//======================================================================

uint8_t mul14(uint8_t a)
{
	uint8_t x2 = xtime(a), x4 = xtime(x2), x8 = xtime(x4);
	return x8 ^ x4 ^ x2;
}
//======================================================================

uint32_t transformWord(const uint32_t wordIn, const uint32_t rcon, const uint8_t sbox[256])
{
	uint32_t wordOut = rotL(wordIn);
	wordOut = pushSbox(wordOut, sbox);
	wordOut = xorOps(wordOut, rcon);
	return wordOut;
}
//=====================================================================

uint32_t pushSbox(const uint32_t wordIn, const uint8_t sbox[256])
{
	uint32_t wordOut = 0;
	uint8_t splitWord[4];
	for (size_t x = 0; x < 4; x++)
	{
		splitWord[x] = wordIn >> ((3 - x) * 8) & 0xff;
	}
	for (size_t x = 0; x < 4; x++)
	{
		splitWord[x] = sbox[splitWord[x]];
		wordOut ^= splitWord[x];
		if (x < 3)
			wordOut <<= 8;
	}
	return wordOut;
}
//=====================================================================

uint32_t rotL(uint32_t x)
{
	return (x << 8) | (x >> 24);
}
//======================================================================
