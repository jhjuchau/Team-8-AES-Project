#include <stdio.h>
#include <string>



#define xtime(x)   ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define RCONSIZE 255

using namespace std;

/*
TO DO LIST
----------
-See if changing all chars to unsigned affects the code's actual execution
-Rename variables in MixColumns, maybe rewrite as nested for loop
*/


 class Encryptor{
 public: 

		//"in" is 16 characters worth of plaintext that our algorithm will operate on
		//"state" holds the value of in[] as it runs through our algorithm
		//"out" is the output of running in[] through our algorithm
	 int COLS = 4;
	 int maxRounds = 0, words = 0;

	 unsigned char in[16], out[16], state[4][4];

	 unsigned char RoundKey[240];	//look into making this just 'char RoundKey

	 unsigned char Key[32];

	 int* Rcon = new int[255];


//	------METHODS-------
	Encryptor();
	Encryptor(int in[]); 
	int getSBoxValue(int val);
	void KeyExpansion();
	void AddRoundKey(int round);
	void SubBytes();
	void ShiftRows();
	void MixColumns();
	void Cipher();
	string Encrypt(string input);
};

Encryptor::Encryptor(int in[])
{
	Rcon = in;
}

int Encryptor::getSBoxValue(int val)
{
	int sbox[256] = {	//each row is 16 long
		//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
/*0*/	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
/*16*/	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
/*32*/	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
/*48*/	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
/*64*/	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
/*80*/	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
/*96*/	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
/*112*/	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

	return sbox[val];
}

void Encryptor::KeyExpansion()	//this function puts the RoundKey into the state
{
	int i, j;
	unsigned char temp[4], k;

	for (i = 0; i<words; i++)
	{
		RoundKey[i * 4] = Key[i * 4];
		RoundKey[i * 4 + 1] = Key[i * 4 + 1];
		RoundKey[i * 4 + 2] = Key[i * 4 + 2];
		RoundKey[i * 4 + 3] = Key[i * 4 + 3];
	}

	//cout << "roundKey[] reads: ";
	//for (int i = 0; i < 32; i++)
	//{
	//	cout << RoundKey[i];
	//}
	//cout << endl;

	/*cout << "sbox on d: " << getSBoxValue('d') << endl;
	cout << "sbox on o: " << getSBoxValue('o') << endl;
	cout << "sbox on g: " << getSBoxValue('g') << endl;
	cout << "sbox on blankspace: " << getSBoxValue(' ') << endl;*/



	while (i < (COLS * (maxRounds + 1)))
	{
		for (j = 0; j<4; j++)
		{
			temp[j] = RoundKey[(i - 1) * 4 + j];
		}

		if (i % words == 0)
		{
			// This function rotates the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
			// Function RotWord()
			{
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
			}

			// SubWord() is a function that takes a four-byte input word and
			// applies the S-box to each of the four bytes to produce an output word.
			// Effectively the Subword() function
			{
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
			}
			
			temp[0] = temp[0] ^ Rcon[i / words];
	 	}

		else if (words > 6 && i % words == 4)
		{
			// Effectively the Subword() function
			{
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
			}
		}

		for (j = 0; j<4; j++)	//replace original RoundKey values with those same values to the power of temp[j]
		{
			//cout << "RoundKey[i * 4 + j] before is :" << RoundKey[i * 4 + j] << endl;
			//cout << "[(i - words) * 4 + j] is :" << (i - words) * 4 + j << endl;
			//cout << "temp[j] is :" << temp[j] << endl;
			//cout << "RoundKey[(i - words) * 4 + j] ^ temp[j] is :" << (RoundKey[(i - words) * 4 + j] ^ temp[j]) << endl;
			RoundKey[i * 4 + j] = RoundKey[(i - words) * 4 + j] ^ temp[j];
			//cout << "RoundKey[i * 4 + j] after is :" << RoundKey[i * 4 + j]<<endl;
			//system("pause");
		}
		
		i++;
	}

	//cout << "i equals " << i << endl;
	//cout << "In our test case, i should equal 44" << endl;
	cout << "RoundKey[] reads: ";
	for (int i = 0; i < 64; i++)
	{
		cout << RoundKey[i];
	}
	cout << endl;
	
	system("pause");
}

void Encryptor::AddRoundKey(int round)
{
	int i, j;
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			state[j][i] ^= RoundKey[round * COLS * 4 + i * COLS + j];
		}
	}
}

void Encryptor::SubBytes()
{
	for (int i = 0; i<4; i++)
	{
		for (int j = 0; j<4; j++)

		{
			state[i][j] = getSBoxValue(state[i][j]);
		}

	}
}

void Encryptor::ShiftRows()
{
	unsigned char temp;
	// Rotate first row 1 columns to left
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	// Rotate second row 2 columns to left

	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];

	state[2][1] = state[2][3];
	state[2][3] = temp;

	// Rotate third row 3 columns to left

	temp = state[3][0];

	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;

}

void Encryptor::MixColumns()	//maybe rewrite this as a nested for-loop? definitely rename variables
{
	int i;
	unsigned char Tmp, Tm, t;

	for (i = 0; i<4; i++)
	{
		t = state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		Tm = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
		Tm = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
		Tm = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
		Tm = state[3][i] ^ t; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
	}
}

void Encryptor::Cipher()
{
	int i, j, round = 0;

	//Copy the input PlainText to state array.

	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			state[j][i] = in[i * 4 + j];
			cout << "state[j][i]: " << state[j][i] << endl;
		}
	}

	// Add the First round key to the state before starting the maxRounds.

	AddRoundKey(0);

	// The number of rounds is equal to the value stored within maxRounds
	// The first (maxRounds-1) rounds are identical.
	// These (maxRounds-1) rounds are executed in the loop below.

	for (round = 1; round<maxRounds; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	// The last round is given below.
	// The MixColumns function is not here in the last round.

	SubBytes();
	ShiftRows();
	AddRoundKey(maxRounds);
	// The encryption process is over.

	// Copy the state array to output array.

	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			out[i * 4 + j] = state[j][i];
		}
	}
}

string Encryptor::Encrypt(string Input)
{	// Receive the length of key here.
	//while (maxRounds != 128 && maxRounds != 192 && maxRounds != 256)
	//	{
	//		printf("Enter the length of Key(128, 192 or 256 only): ");
	//		scanf_s("%d", &maxRounds);
	//	}

	cout << "Key length manually set to 128" << endl;
	maxRounds = 128;

	// Calculate words and maxRounds from the received value.
	words = maxRounds / 32;
	maxRounds = words + 6;


	//REDUNDANT CODE? 
	//The array temp stores the key.
	// The array inputTemp stores the plaintext.
	//unsigned char keyTemp[16]; = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	//unsigned char inputTemp[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	//unsigned char inputTemp[16];
	//for (int i = 0; i < 16; i++)
	//{
	//	inputTemp[i] = Input[i];
	//}
	//cout << "inputTemp[] reads: ";
	//for (int i = 0; i < 16; i++)
	//{
	//	cout << inputTemp[i];
	//}
	//cout << endl;

	// Copy the Key and PlainText

	for (int i = 0; i<words * 4; i++)
		{
			//Key[i] = keyArray[i];
			in[i] = Input[i];
		}

	_flushall();	//clears the input buffer

	//Recieve the Key from the user
																//<-------
	//printf("Enter the Key in hexadecimal: ");
	//for (int i = 0; i<3; i++)
	//	{
	//		//scanf_s("%x", &Key[i]);
	//		cin >> Key[i];
	//	}


	Key[0] = 'd';
	Key[1] = 'o';
	Key[2] = 'g';

	cout << "key[] reads: ";
	for (int i = 0; i < 32; i++)
	{
		cout << Key[i];
	}
	cout << endl;


	KeyExpansion();	// The KeyExpansion routine must be called before encryption.

	Cipher();		// The next function call encrypts the PlainText with the Key using AES algorithm.

	// Output the encrypted text.

	printf("\nText after encryption:\n");

	for (int i = 0; i<words * 4; i++)
	{
		printf("%02x ", out[i]);
	}

	printf("\n\n");
	return Input;
}
