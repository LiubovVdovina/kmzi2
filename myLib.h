//
//  myLib.h
//  des
//  Copyright (c) 2015 Lyuba_Vdovina. All rights reserved.
//

#include <vector>

using namespace std;

//функция шифрования
vector<unsigned char> crypt(vector<unsigned char> data, vector<unsigned char> key8, bool encode);

//функция генерации ключей для каждого из 16 шагов
vector<vector<unsigned char> > makeKeys(vector<unsigned char> key64);

//шаг операции
void step(vector<unsigned char>& right, vector<unsigned char>& left, vector<unsigned char> key48);

//Функция преобразования 48бит данных к 32
vector<unsigned char> convertTo32(vector<unsigned char> right48);

vector<unsigned char> first(vector<unsigned char> bits); //начальная перестановка
vector<unsigned char> last(vector<unsigned char> bits); //обратная перестановка
