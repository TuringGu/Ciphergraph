#pragma once
#define BIT bool

class DES {
public:
	static void des_encrypt(BIT input[64], BIT output[64], BIT key[64]);
	static void des_decrypt(BIT input[64], BIT output[64], BIT key[64]);
};