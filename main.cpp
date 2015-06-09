//
//  main.cpp
//  des
//  Copyright (c) 2015 Lyuba_Vdovina. All rights reserved.
//

#include <vector>
#include <iostream>
#include <fstream>
#include "myLib.h"

using namespace std;


vector<unsigned char> readFile(char* fileName)
{
    vector<unsigned char> input;
    ifstream ifst(fileName, ios::binary);
    if (ifst.fail())
        return input;
    
    ifst.seekg(0, ios::end);
    int size = ifst.tellg();
    ifst.seekg(0, ios::beg);
    
    input.resize(size);
    ifst.read((char*)&input.front(), size);
    ifst.close();
    return input;
}


int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        cout << "Wrong arguments!" << endl;
        cout << "des in out key d/e" << endl;
        return 1;
    }
    
    
    vector<unsigned char> input = readFile(argv[1]);
    if (input.empty())
    {
        cerr << "Can't read input file" << endl;
        return 1;
    }
    
    vector<unsigned char> key = readFile(argv[3]);
    if (key.size() != 8)
    {
        cerr << "Key must be 8 byte!" << endl;
        return 1;
    }
    
    vector<unsigned char> output;
    bool encode = (argv[4][0] == 'e');
    if (encode)
    {
        output.push_back(8 - input.size() % 8);
        input.insert(input.end(), 8 - input.size() % 8, 0);
        
        for (int i = 0; i < input.size() / 8; i++)
        {
            vector<unsigned char> input8;
            input8.insert(input8.end(), input.begin() + i * 8, input.begin() + (i + 1) * 8);
            vector<unsigned char> crypted = crypt(input8, key, encode);
            output.insert(output.end(), crypted.begin(), crypted.end());
        }
    }
    else
    {
        int num0 = input[0];
        vector<unsigned char> temp;
        temp.insert(temp.begin(), input.begin() + 1, input.end());
        input = temp;
        
        for (int i = 0; i < input.size() / 8; i++)
        {
            vector<unsigned char> input8;
            input8.insert(input8.end(), input.begin() + i * 8, input.begin() + (i + 1) * 8);
            
            vector<unsigned char> decrypted = crypt(input8, key, encode);
            output.insert(output.end(), decrypted.begin(), decrypted.end());
        }
        
        for (int i = 0; i < num0; i++)
            output.pop_back();
    }
    
    ofstream outStream(argv[2], ios::binary);
    outStream.write((char*)&output.front(), output.size());
    outStream.close();
    
    return 0;
}
