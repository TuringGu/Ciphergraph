#include <iostream>
#include "DES.h"
using namespace std;

#define BIT bool

BIT keys[16][48];

// ��������
static void permute(BIT *input, BIT *output, int *box, int length);
static void inital_permute(BIT *input, BIT *output);
static void final_permute(BIT *input, BIT *output);
static void generate_keys(BIT key[64]);
static void encrypt_every_turn(BIT left_data[32], BIT right_data[32], BIT key[48], int turn);
static void encrypt_or_decrypt(BIT input[64], BIT output[64], BIT key[64], bool isEncrypt);

// ����
void DES::des_encrypt(BIT input[64], BIT output[64], BIT key[64]) {
	encrypt_or_decrypt(input, output, key, true);
}

// ����
void DES::des_decrypt(BIT input[64], BIT output[64], BIT key[64]) {
	encrypt_or_decrypt(input, output, key, false);
}

// ��װ�õ��û�����
void permute(BIT *input, BIT *output, int *box, int length) {
	for (int i = 0; i < length; ++i) {
		output[i] = input[box[i] - 1];
	}
}

// ��ʼ�û�
void inital_permute(BIT *input, BIT *output) {
	static int IP[64] = {
		58 , 50 , 42 , 34 , 26 , 18 , 10 ,  2 ,
		60 , 52 , 44 , 36 , 28 , 20 , 12 ,  4 ,
		62 , 54 , 46 , 38 , 30 , 22 , 14 ,  6 ,
		64 , 56 , 48 , 40 , 32 , 24 , 16 ,  8 ,
		57 , 49 , 41 , 33 , 25 , 17 ,  9 ,  1 ,
		59 , 51 , 43 , 35 , 27 , 19 , 11 ,  3 ,
		61 , 53 , 45 , 37 , 29 , 21 , 13 ,  5 ,
		63 , 55 , 47 , 39 , 31 , 23 , 15 ,  7 };
	permute(input, output, IP, 64);
}

// �����û�
void final_permute(BIT *input, BIT *output) {
	static int FP[64] = {
		40 ,  8 , 48 , 16 , 56 , 24 , 64 , 32 ,
		39 ,  7 , 47 , 15 , 55 , 23 , 63 , 31 ,
		38 ,  6 , 46 , 14 , 54 , 22 , 62 , 30 ,
		37 ,  5 , 45 , 13 , 53 , 21 , 61 , 29 ,
		36 ,  4 , 44 , 12 , 52 , 20 , 60 , 28 ,
		35 ,  3 , 43 , 11 , 51 , 19 , 59 , 27 ,
		34 ,  2 , 42 , 10 , 50 , 18 , 58 , 26 ,
		33 ,  1 , 41 ,  9 , 49 , 17 , 57 , 25 };
	permute(input, output, FP, 64);
}

// ���ɼ�����Կ
void generate_keys(BIT key[64]) {
	// KP����Կ�û�ѡ��1��64->56��
	static int KP[56] = {
		57 , 49 , 41 , 33 , 25 , 17 ,  9 ,  1 ,
		58 , 50 , 42 , 34 , 26 , 18 , 10 ,  2 ,
		59 , 51 , 43 , 35 , 27 , 19 , 11 ,  3 ,
		60 , 52 , 44 , 36 , 63 , 55 , 47 , 39 ,
		31 , 23 , 15 ,  7 , 62 , 54 , 46 , 38 ,
		30 , 22 , 14 ,  6 , 61 , 53 , 45 , 37 ,
		29 , 21 , 13 ,  5 , 28 , 20 , 12 ,  4 };

	// KM��ÿ��������Կ��λ��
	static int KM[16] = {
		1 ,  1 ,  2 ,  2 ,  2 ,  2 ,  2 ,  2 ,
		1 ,  2 ,  2 ,  2 ,  2 ,  2 ,  2 ,  1 };

	// CP����Կ�û�ѡ��2��56->48��
	static int CP[48] = {
		14 , 17 , 11 , 24 ,  1 ,  5 ,  3 , 28 ,
		15 ,  6 , 21 , 10 , 23 , 19 , 12 ,  4 ,
		26 ,  8 , 16 ,  7 , 27 , 20 , 13 ,  2 ,
		41 , 52 , 31 , 37 , 47 , 55 , 30 , 40 ,
		51 , 45 , 33 , 48 , 44 , 49 , 39 , 56 ,
		34 , 53 , 46 , 42 , 50 , 36 , 29 , 32 };

	BIT L[60], R[60];

	// 1. ��Կ�û�ѡ��1��64->56��
	for (int i = 0; i < 28; ++i) {
		L[i + 28] = L[i] = key[KP[i] - 1],
			R[i + 28] = R[i] = key[KP[i + 28] - 1];
	}

	// 2. ��Կλ�ơ��û�ѡ��2��56->48��
	int shift = 0; // ��Կλ����
	for (int i = 0; i < 16; ++i) {
		shift += KM[i];
		for (int j = 0; j < 48; ++j) {
			if (CP[j] < 28)
				keys[i][j] = L[CP[j] + shift - 1];
			else
				keys[i][j] = R[CP[j] - 28 + shift - 1];
		}
	}
}

// ÿ���ִεļ���
void encrypt_every_turn(BIT left_data[32], BIT right_data[32], BIT key[48], int turn) {
	// ��չ�û�
	static int EP[48] = {
		32 ,  1 ,  2 ,  3 ,  4 ,  5 ,  4 ,  5 ,
		6 ,  7 ,  8 ,  9 ,  8 ,  9 , 10 , 11 ,
		12 , 13 , 12 , 13 , 14 , 15 , 16 , 17 ,
		16 , 17 , 18 , 19 , 20 , 21 , 20 , 21 ,
		22 , 23 , 24 , 25 , 24 , 25 , 26 , 27 ,
		28 , 29 , 28 , 29 , 30 , 31 , 32 ,  1 };

	// S��
	static int S_box[8][4][16] = {
		//S1   
		{ { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
	{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
	{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
	{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 } },
	//S2
	{ { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
	{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
	{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
	{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 } },
	//S3
	{ { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
	{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
	{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
	{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 } },
	//S4
	{ { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
	{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
	{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
	{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 } },
	//S5
	{ { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
	{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
	{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
	{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 } },
	//S6
	{ { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
	{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
	{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
	{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 } },
	//S7
	{ { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
	{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
	{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
	{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 } },
	//S8
	{ { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
	{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
	{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
	{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 } } };

	// P��
	static int PP[32] = {
		16 ,  7 , 20 , 21 , 29 , 12 , 28 , 17 ,
		1  , 15 , 23 , 26 ,  5 , 18 , 31 , 10 ,
		2  ,  8 , 24 , 14 , 32 , 27 ,  3 ,  9 ,
		19 , 13 , 30 ,  6 , 22 , 11 ,  4 , 25 };

	BIT tmp_48[48];
	BIT tmp_32[32];
	memset(tmp_32, 0, sizeof(tmp_32));

	// 1. ��չ�û���32->48�����뱾�ִε���Կ���
	for (int i = 0; i < 48; ++i)
		tmp_48[i] = right_data[EP[i] - 1] ^ key[i];

	// 2. S�д���ѡ��48->32��
	int count_of_box = 8;
	for (int i = 0; i < count_of_box; ++i) {
		int index_of_input = i * 6;
		int row_in_box = (tmp_48[index_of_input] << 1) + tmp_48[index_of_input + 5];
		int column_in_box = (tmp_48[index_of_input + 1] << 3) +
			(tmp_48[index_of_input + 2] << 2) +
			(tmp_48[index_of_input + 3] << 1) +
			(tmp_48[index_of_input + 4]);
		int temp_var = S_box[i][row_in_box][column_in_box];

		int index_of_output = i * 4;
		for (int j = 0; j < 4; ++j)
			tmp_32[index_of_output + (3 - j)] |= (temp_var >> j) & 1;
	}

	// 3. P���û�
	BIT tmp_32_2[32];
	permute(tmp_32, tmp_32_2, PP, 32);

	// 4. ���
	for (int i = 0; i < 32; ++i)
		left_data[i] ^= tmp_32_2[i];

	// 5. ���δ���������򽻻�left_data��right_data
	if (turn != 15) {
		memcpy(tmp_32, left_data, 32);
		memcpy(left_data, right_data, 32);
		memcpy(right_data, tmp_32, 32);
	}
}

// ����/���ܺ������㷨��ͬ��ֻ������Կ��ʹ�ô����෴��
void encrypt_or_decrypt(BIT input[64], BIT output[64], BIT key[64], bool isEncrypt) {
	// ��ʼ�û�
	BIT tmp[64];
	inital_permute(input, tmp);

	// ��64λ���ݷֳ�������
	BIT left_data[32], right_data[32];
	for (int i = 0; i < 32; ++i) {
		left_data[i] = tmp[i];
		right_data[i] = tmp[i + 32];
	}

	// ��������Կ
	generate_keys(key);

	// ����16�ּ���/����
	if (isEncrypt) {
		for (int i = 0; i < 16; ++i)
			encrypt_every_turn(left_data, right_data, keys[i], i);
	}
	else {
		for (int i = 0; i < 16; ++i)
			encrypt_every_turn(left_data, right_data, keys[15 - i], i);
	}

	// ������������������ϳ�64λ����
	for (int i = 0; i < 32; ++i) {
		tmp[i] = left_data[i];
		tmp[i + 32] = right_data[i];
	}

	// �����û�
	final_permute(tmp, output);
}