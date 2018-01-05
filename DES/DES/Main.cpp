#include <iostream>
#include <string>
#include "DES.h"
using namespace std;

#define BIT bool

void strToBit(string str, BIT bit[64]) {
	int count = 0, index_of_str = 0;
	while (true) {
		if (64 == count)
			break;
		if (' ' == str[index_of_str]) {
			++index_of_str;
			continue;
		}
		bit[count] = bool(str[index_of_str] - '0');
		++count;
		++index_of_str;
	}
}

string bitToStr(BIT bit[64]) {
	string str = "";
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 8; ++j)
			str.insert(str.end(), bit[i * 8 + j] + '0');
		str.insert(str.end(), ' ');
	}
	return str;
}

// 测试用例(1)：使用同一密钥，对两组明文进行加密和解密
void test1() {
	string keyStr;
	BIT	   keyBit[64];

	string inputStr;
	BIT    inputBit[64];
	string encryptStr;
	BIT    encryptBit[64];
	string decryptStr;
	BIT    decryptBit[64];

	string inputStr2;
	BIT    inputBit2[64];
	string encryptStr2;
	BIT    encryptBit2[64];
	string decryptStr2;
	BIT    decryptBit2[64];

	cout << "====================================================\n测试用例(1)：使用同一密钥，对两组明文进行加密和解密\n\n";

	keyStr = "00000010 10010110 01001000 11000100 00111000 00110000 00111000 01100100";
	inputStr = "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000";
	inputStr2 = "10000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000";
	strToBit(keyStr, keyBit);
	strToBit(inputStr, inputBit);
	strToBit(inputStr2, inputBit2);

	DES::des_encrypt(inputBit, encryptBit, keyBit);
	DES::des_decrypt(encryptBit, decryptBit, keyBit);
	encryptStr = bitToStr(encryptBit);
	decryptStr = bitToStr(decryptBit);

	DES::des_encrypt(inputBit2, encryptBit2, keyBit);
	DES::des_decrypt(encryptBit2, decryptBit2, keyBit);
	encryptStr2 = bitToStr(encryptBit2);
	decryptStr2 = bitToStr(decryptBit2);

	int diff = 0;
	for (int i = 0; i < 64; ++i) {
		if (encryptBit[i] == encryptBit2[i])
			++diff;
	}

	cout << "Key      : " << keyStr << "\n\n";

	cout << "Input1   : " << inputStr
		<< "\nEncrypt1 : " << encryptStr
		<< "\nDecrypt1 : " << decryptStr << "\n\n";

	cout << "Input2   : " << inputStr2
		<< "\nEncrypt2 : " << encryptStr2
		<< "\nDecrypt2 : " << decryptStr2 << "\n\n";

	cout << "Number of different digits: " << diff << "\n\n";

}

// 测试用例(2)：对同一段明文，使用不同密钥进行加密和解密操作
void test2() {
	string inputStr;
	BIT    inputBit[64];

	string keyStr;
	BIT	   keyBit[64];
	string encryptStr;
	BIT    encryptBit[64];
	string decryptStr;
	BIT    decryptBit[64];

	string keyStr2;
	BIT	   keyBit2[64];
	string encryptStr2;
	BIT    encryptBit2[64];
	string decryptStr2;
	BIT    decryptBit2[64];

	cout << "====================================================\n测试用例(2)：对同一段明文，使用不同密钥进行加密和解密操作\n\n";

	inputStr = "01101000 10000101 00101111 01111010 00010011 01110110 11101011 10100100";
	keyStr = "11100010 11110110 11011110 00110000 00111010 00001000 01100010 11011100";
	keyStr2 = "01100010 11110110 11011110 00110000 00111010 00001000 01100010 11011100";
	strToBit(inputStr, inputBit);
	strToBit(keyStr, keyBit);
	strToBit(keyStr2, keyBit2);

	DES::des_encrypt(inputBit, encryptBit, keyBit);
	DES::des_decrypt(encryptBit, decryptBit, keyBit);
	encryptStr = bitToStr(encryptBit);
	decryptStr = bitToStr(decryptBit);

	DES::des_encrypt(inputBit, encryptBit2, keyBit2);
	DES::des_decrypt(encryptBit2, decryptBit2, keyBit2);
	encryptStr2 = bitToStr(encryptBit2);
	decryptStr2 = bitToStr(decryptBit2);

	int diff = 0;
	for (int i = 0; i < 64; ++i) {
		if (encryptBit[i] == encryptBit2[i])
			++diff;
	}

	cout << "Input    : " << inputStr << "\n\n";

	cout << "Key1     : " << keyStr
		<< "\nEncrypt1 : " << encryptStr
		<< "\nDecrypt1 : " << decryptStr << "\n\n";

	cout << "Key2     : " << keyStr2
		<< "\nEncrypt2 : " << encryptStr2
		<< "\nDecrypt2 : " << decryptStr2 << "\n\n";

	cout << "Number of different digits: " << diff << "\n\n";
}

int main() {
	test1();
	test2();

	system("pause");
	return 0;
}