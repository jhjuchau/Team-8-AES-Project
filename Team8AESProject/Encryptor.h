#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include <iomanip>



#define xtime(x)   ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

using namespace std;


 class Encryptor{	//the methods within this class allow the user to encrypt any given input string in an AES-compliant fashion
		//"in" is 16 characters worth of plaintext that our algorithm will operate on
		//"state" holds the value of in[] as it runs through our algorithm
		//"out" is the output of running in[] through our algorithm
	 unsigned char in[16], out[16], state[4][4];


	 int COLS = 4;		
	 int maxRounds = 0, words = 0;
	 bool firstrun = true;

	 

	 unsigned char RoundKey[240], Key[32];
	 int* Rcon = new int[255];		//it is difficult to initialize an array with set values within a class in C++, so I worked around this by having you pass the Rcon table in as an argument to a constructor.
									//it's a pretty lazy solution but it was all I could think to do


//	------PRIVATE METHODS-------
	int getSBoxValue(int val);
	void ExpandKey();
	void AddRoundKey(int round);
	void SubBytes();
	void ShiftRows();
	void MixColumns();
	void Cipher();
	void Encrypt(string input);

 public:			//employing encapsulation by only allowing the callee access to the constructor and encryption start point
	 Encryptor();
	 Encryptor(int in[]);
	 void EncryptionController(string input);
};

 Encryptor::Encryptor()	//i kept getting some "left of '.EncryptionController' must have class/struct/union" error when i attempt to make the Encryptor object using this contructor, so this code is unused
 {
	 int in[255] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
		 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
		 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
		 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
		 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
		 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
		 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
		 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
		 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
		 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
		 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
		 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
		 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
		 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
		 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

	 Rcon = in;
 }

Encryptor::Encryptor(int in[])	//constructor that accepts an array for the Rcon table, because it was the first workaround that worked and I didn't want to deal with it
{
	Rcon = in;
}

int Encryptor::getSBoxValue(int val)	//returns a value on the Rijndael Substitution Box that corresponds to the integer value of the character passed in
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

void Encryptor::ExpandKey()	//this function puts the RoundKey into the state
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

	while (i < (COLS * (maxRounds + 1)))
	{
		for (j = 0; j<4; j++)
		{
			temp[j] = RoundKey[(i - 1) * 4 + j];
		}

		if (i % words == 0)
		{		
				//identical to a function called RotWord(), simply implemented here 
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
				//virtually identical to SubWord(), but implemented here to save time passing arguments around
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
			
			temp[0] ^= Rcon[i / words];	//the first element of the new temp array is XOR'd with a value in the Rcon table
	 	}

		else if (words > 6 && i % words == 4)
		{
			//again, virtually identical to SubWord()
				temp[0] = getSBoxValue(temp[0]);
				temp[1] = getSBoxValue(temp[1]);
				temp[2] = getSBoxValue(temp[2]);
				temp[3] = getSBoxValue(temp[3]);
		}

		for (j = 0; j<4; j++)	//replace original RoundKey values with those same values XOR'd with temp[j]
		{
			RoundKey[i * 4 + j] = RoundKey[(i - words) * 4 + j] ^ temp[j];
		}
		
		i++;
	}

	if (firstrun)
	{

		cout << "First 64 characters of RoundKey[] reads: ";
		for (int i = 0; i < 64; i++)
		{
			cout << RoundKey[i];
		}
		cout << endl;
	}
	
}

void Encryptor::AddRoundKey(int round)	//this function XORs each element in the state table with a value from the RoundKey. Each additional 'round' adds 16 to the index of the roundkey
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

void Encryptor::SubBytes()	//this function swaps all elements of the state table with their corresponding element in the Rijndael Substitution Box
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
	// Row at index 0, the "first row", is untouched

	// Rotates row at index 1 a column to the left
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	// Rotates row at index 2 two columns to the left
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];

	state[2][1] = state[2][3];
	state[2][3] = temp;

	// Rotates row at index 3 three columns to left

	temp = state[3][0];

	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
}

void Encryptor::MixColumns()	//this function shuffles the columns by XORing the columns amongst themselves
{
	int i;
	unsigned char a, temp, first;

	for (i = 0; i<4; i++)
	{
		first = state[0][i];
		a = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		temp = state[0][i] ^ state[1][i]; 


		temp = xtime(temp);				//temp is constantly reinitialized so the pseudorandom number for column mixing is always slightly different
		state[0][i] ^= temp ^ a;
		temp = state[1][i] ^ state[2][i]; 


		temp = xtime(temp); 
		state[1][i] ^= temp ^ a;
		temp = state[2][i] ^ state[3][i]; 


		temp = xtime(temp); 
		state[2][i] ^= temp ^ a;
		temp = state[3][i] ^ first; 


		temp = xtime(temp); 
		state[3][i] ^= temp ^ a;
	}
}

void Encryptor::Cipher()	//this function puts the input array into the state array, then calls the "Round Loop"
{
	int i, j, round = 0;

	//
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)  
		{
			state[j][i] = in[i * 4 + j];
		}
	}

	// Add the First round key to the state before starting the maxRounds.

	AddRoundKey(0);

	//We called this the "Round Loop" in our report. It executes four methods that result in AES-compliant encryption
	//These instructions repeat (maxrounds-1) times, with the final loop discluding the MixColumns() step
	for (round = 1; round<maxRounds; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns(); 
		AddRoundKey(round);
	}
	
	//The final "Round loop" discludes MixColumns(), as per AES convention
	SubBytes();
	ShiftRows();
	AddRoundKey(maxRounds);
	

	// Copy the state array to output array.
	for (i = 0; i<4; i++)
	{
		for (j = 0; j<4; j++)
		{
			out[i*4 + j] = state[j][i];
		}
	}
}

void Encryptor::Encrypt(string Input)	//some important calls were moved out of EncryptionController to keep it from getting too bloated
{	
	// Copy the contents of Input into an operable in[] array of length 16. If Input has fewer than 16 characters, assign the empty spaces to NULL.
	for (int i = 0; i<words * 4; i++)
		{
			//Key[i] = keyArray[i];
			if (i > Input.length())
			{ 
				cout << "The input has fewer than "<<words*4<<" characters. Assigning in["<<i<<"] to NULL..." << endl; 
				in[i] = NULL;
			}
			else in[i] = Input[i];
		}

	_flushall();	//clearing the input buffer to ensure no loose characters slide in
	
	ExpandKey();	//populates the RoundKey array with characters permuted from the original Key
	Cipher();		// Cipher() actually encrypts the input text

	firstrun = false;	//the RoundKey is only printed to the user during the first run, to avoid redundancy
}

void Encryptor::EncryptionController(string Input)		//the host function that calls the other methods in the order they need to operate
{
	//Receive the length of key here.
	int keyLength = 0;
	while (keyLength != 128 && keyLength != 192 && keyLength != 256)
		{
			keyLength = 0;
			cout << "Enter your Key size. Only lengths 128, 192 and 256 are allowed: ";
			cin >> keyLength;
		}


	string keyIn;
	//User inputs the key's value
	cout << "Enter the key in ASCII format: ";
	cin >> keyIn;


	for (int i = 0; i < 32; i++)
	{
		if (i > keyIn.length()){  Key[i] = NULL;  }
		else Key[i] = keyIn[i];
	}


		cout << "key[] reads: ";
		for (int i = 0; i < 32; i++)
		{	cout << Key[i];		}
		cout << endl;


	//words and maxRounds are used in several contexts later in the encryption process
	words = keyLength / 32;
	maxRounds = (keyLength/32) + 6;


	string concatenatedInput = Input;	//to keep the original text intact, we moved the encryption operations to a separate variable
	int reps;	//a count of the number of required state tables to encrypt the whole plain text, defined below
	int size = words * 4;	//controls several loops below that change their iteration count based on key length
	ofstream OutFile("Encrypted.txt");	//the name of the output file
	OutFile << std::hex;	//sets the output stream to only print in hexadecimal values


//initializing reps to be equal to input/size, always rounded up
	if (Input.length() % size == 0)
	{
		cout << "The input length " << Input.length() << " is exactly divisible by 16." << endl;
		reps = (Input.length() / size);
	}
	else { reps = trunc(Input.length() / size) + 1; }	//trunc() always rounds down; in conjunction with +1, this covers any remainder

	cout << "This algorithm will loop " << reps << " times." << endl;




	clock_t tStart = clock();	//now that user input has stopped, the clock that measures runtime starts ticking

	cout << "\n------------------------------------" << endl;
	//Encryption loop
	for (int i = 0; i < reps; i++)		//i < reps
	{	//Print original text
		cout << "Encryption Loop Repetition #" << i + 1 << endl;
		Encrypt(concatenatedInput);		//Encrypt() calls Cipher() among other things, meaning the actual encryption takes place on this line


		cout << "Text being encrypted:        |";
		for (int k = 0; k < size; k++)	//this loop ensures that if there are NULL characters in the plaintext, it prints a blank space instead of a garbage character
		{
			if (k > concatenatedInput.length()){ cout << " "; }
			else cout << concatenatedInput[k];
		}
		cout << endl;

		//Print ciphertext
		cout << "Ciphertext after encryption: |";
		for (int j = 0; j < size; j++)
		{
			printf("%02x ", out[j]);				//print the value at out[j] to the screen in 2 digit hex format
			OutFile << static_cast<int>(out[j]);	//print the value at out[j] to file
			OutFile << ' ';							//put a space between each encrypted character so the output file is more legible
		}


		concatenatedInput.erase(0, 16);
		cout << "\nRemaining Text to encrypt:   |" << concatenatedInput << endl;
		cout << "\n------------------------------------" << endl;

		 //delete the first 16 characters of the string that contains a copy of the input
		OutFile << '\n';	//prints the next 16 characters on a new line
		
	}
	OutFile.close();

	cout << "Encryption complete! Output saved in 'Encrypted.txt'. Press any key to close the program." << endl;
	cout << "Character count: " << Input.length() << endl;
	printf("Time taken: %.2fs\n", (double)(clock() - tStart) / CLOCKS_PER_SEC);	//these lines are for gathering runtime vs input size data
}