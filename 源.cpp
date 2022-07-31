#include <cstring>
#include "sm3.h"



static unsigned char mak1[64] = { 0 };
static unsigned int hash[8] = { 0 };
static unsigned int T[64] = { 0 };


void lx()
{
	unsigned int i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", hash[i]);
	}
	printf("\n");
}


void QAQ(unsigned char* out_hash)
{
	int i = 0;
	for (i = 0; i < 8; i++)
	{
		out_hash[i * 4] = (unsigned char)((hash[i] >> 24) & 0xFF);
		out_hash[i * 4 + 1] = (unsigned char)((hash[i] >> 16) & 0xFF);
		out_hash[i * 4 + 2] = (unsigned char)((hash[i] >> 8) & 0xFF);
		out_hash[i * 4 + 3] = (unsigned char)((hash[i]) & 0xFF);
	}
	for (i = 0; i < 32; i++)
		printf("%c", out_hash[i]);
	printf("\n");

}


int init_T() {
	int i = 0;
	for (i = 0; i < 16; i++)
		T[i] = 0x79cc4519;
	for (i = 16; i < 64; i++)
		T[i] = 0x7a879d8a;
	return 1;
}

void SM3_Init() {
	init_T();
	hash[0] = 0x7380166f;
	hash[1] = 0x4914b2b9;
	hash[2] = 0x172442d7;
	hash[3] = 0xda8a0600;
	hash[4] = 0xa96f30bc;
	hash[5] = 0x163138aa;
	hash[6] = 0xe38dee4d;
	hash[7] = 0xb0fb0e4e;
}






unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, unsigned int j) 
{
	unsigned int p1= 0;
	if (0 <= j && j < 16)
		p1= X ^ Y ^ Z;
	else if (16 <= j && j < 64)
		p1= (X & Y) | (X & Z) | (Y & Z);
	return p1;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, unsigned int j) {
	unsigned int p1= 0;
	if (0 <= j && j < 16)
		p1= X ^ Y ^ Z;
	else if (16 <= j && j < 64)
		p1= (X & Y) | ((~X) & Z);
	return p1;
}



unsigned int left(unsigned int a, unsigned int k) {
	k = k % 32;
	return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}

#define P_0(X) X ^ (left(X, 9)) ^ (left(X, 17))
#define P_1(X) X ^ (left(X, 15)) ^ (left(X, 23))


int akrm40(unsigned char* arr) {
	unsigned int W[68];
	unsigned int W_1[64];
	unsigned int j;
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int SS1, SS2, TT1, TT2;
	for (j = 0; j < 16; j++)
		W[j] = arr[j * 4 + 0] << 24 | arr[j * 4 + 1] << 16 | arr[j * 4 + 2] << 8 | arr[j * 4 + 3];
	for (j = 16; j < 68; j++)
		W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (left(W[j - 3], 15))) ^ (left(W[j - 13], 7)) ^ W[j - 6];
	for (j = 0; j < 64; j++)
		W_1[j] = W[j] ^ W[j + 4];
	A = hash[0];
	B = hash[1];
	C = hash[2];
	D = hash[3];
	E = hash[4];
	F = hash[5];
	G = hash[6];
	H = hash[7];
	for (j = 0; j < 64; j++) {
		SS1 = left(((left(A, 12)) + E + (left(T[j], j))) & 0xFFFFFFFF, 7);
		SS2 = SS1 ^ (left(A, 12));
		TT1 = (FF(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
		TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
		D = C;
		C = left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = left(F, 19);
		F = E;
		E = P_0(TT2);
	}

	hash[0] = (A ^ hash[0]);
	hash[1] = (B ^ hash[1]);
	hash[2] = (C ^ hash[2]);
	hash[3] = (D ^ hash[3]);
	hash[4] = (E ^ hash[4]);
	hash[5] = (F ^ hash[5]);
	hash[6] = (G ^ hash[6]);
	hash[7] = (H ^ hash[7]);
	return 1;
}

void change(unsigned char* msg, unsigned int len_of_mak1) {
	int i;
	int left = 0;
	unsigned long long ok = 0;

	for (i = 0; i < (len_of_mak1 / 64); i++) {
		memcpy(mak1, msg + i * 64, 64);
		akrm40(mak1);
	}



	ok = len_of_mak1 * 8;
	left = len_of_mak1 % 64;
	memset(&mak1[left], 0, 64 - left);
	memcpy(mak1, msg + i * 64, left);
	mak1[left] = 0x80;


	if (left <= 55) {
		for (i = 0; i < 8; i++)
			mak1[56 + i] = (ok >> ((8 - 1 - i) * 8)) & 0xFF;
		akrm40(mak1);
	}
	else {
		akrm40(mak1);
		memset(mak1, 0, 64);
		for (i = 0; i < 8; i++)
			mak1[56 + i] = (ok >> ((8 - 1 - i) * 8)) & 0xFF;
		akrm40(mak1);
	}
}


int SM3(unsigned char* msg, unsigned int msglen, unsigned char* out_hash)
{
	SM3_Init();
	change(msg, msglen);
	lx();
	QAQ(out_hash);
	return 1;
}



int main()
{
	unsigned char Hash[32] = { 0 };

	unsigned char op[] = "1654941562365";
	unsigned char* str = op;
	//66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
	int len;
	len =14;
	SM3(str, len, Hash);
	return 0;
}