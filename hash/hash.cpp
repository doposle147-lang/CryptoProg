// hash.cpp - программа хэширования содержимого файла
// Библиотека: Crypto++ (https://www.cryptopp.com)
// Вывод: строка шестнадцатеричных цифр в нижнем регистре
//
// Сборка (MinGW/MSYS2, Windows):
//     mingw32-make            -> hash.exe
// Сборка (Linux):
//     make                    -> ./hash
// Использование:
//     hash -a sha256 -f file.txt
//     hash --algorithm sha512 --file file.txt

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <map>
#include <vector>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#endif

#include <cryptopp/cryptlib.h> // HashTransformation
#include <cryptopp/hex.h>      // HexEncoder
#include <cryptopp/sha.h>      // SHA1, SHA224, SHA256, SHA384, SHA512

using namespace std;
using namespace CryptoPP;

static const size_t BUF_SIZE = 4096; // размер блока чтения файла

// Список поддерживаемых алгоритмов: имя -> фабрика хэш-функции
typedef HashTransformation* (*HashFactory)();

static HashTransformation* makeSHA1()   { return new SHA1;   }
static HashTransformation* makeSHA224() { return new SHA224; }
static HashTransformation* makeSHA256() { return new SHA256; }
static HashTransformation* makeSHA384() { return new SHA384; }
static HashTransformation* makeSHA512() { return new SHA512; }

static map<string, HashFactory> make_registry() {
    map<string, HashFactory> r;
    r["sha1"]   = makeSHA1;
    r["sha224"] = makeSHA224;
    r["sha256"] = makeSHA256;
    r["sha384"] = makeSHA384;
    r["sha512"] = makeSHA512;
    return r;
}

static void print_help(const char* prog) {
    cout << "Использование: " << prog << " -a <алгоритм> -f <файл>" << endl;
    cout << endl;
    cout << "Вычисляет хэш содержимого файла и выводит его в виде строки" << endl;
    cout << "шестнадцатеричных цифр." << endl;
    cout << endl;
    cout << "Параметры:" << endl;
    cout << "  -a, --algorithm <имя>  алгоритм хэширования:" << endl;
    cout << "                         sha1, sha224, sha256, sha384, sha512" << endl;
    cout << "                         (по умолчанию sha256)" << endl;
    cout << "  -f, --file <путь>      файл с исходными данными"
         << " (обязательный)" << endl;
    cout << "  -h, --help             показать справку" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  " << prog << " -a sha256 -f test.txt" << endl;
    cout << "  " << prog << " --algorithm sha512 --file test.txt" << endl;
}

// Потоковое чтение файла блоками (файл может быть больше оперативной памяти)
static bool hash_file(const string& path, HashTransformation& hash,
                      string& digest_hex, string& err) {
    ifstream in(path.c_str(), ios::binary);
    if (!in) {
        err = "не удалось открыть файл '" + path + "'";
        return false;
    }

    string buf(BUF_SIZE, '\0');
    while (in) {
        in.read(&buf[0], static_cast<streamsize>(BUF_SIZE));
        streamsize got = in.gcount();
        if (got > 0) {
            hash.Update(reinterpret_cast<const CryptoPP::byte*>(buf.data()),
                        static_cast<size_t>(got));
        }
    }
    if (!in.eof()) {
        err = "ошибка чтения файла '" + path + "'";
        return false;
    }
    in.close();

    // получаем дайджест и кодируем его в hex
    vector<CryptoPP::byte> digest(hash.DigestSize());
    hash.Final(digest.data());

    HexEncoder encoder(new StringSink(digest_hex), false); // false - нижний регистр
    encoder.Put(digest.data(), digest.size());
    encoder.MessageEnd();
    return true;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc == 1) {
        print_help(argv[0]);
        return 0;
    }

    map<string, HashFactory> registry = make_registry();
    string algo = "sha256";
    string file;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 ||
                   strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 >= argc) {
                cerr << "Ошибка: после " << argv[i]
                     << " должно быть имя алгоритма" << endl;
                return 1;
            }
            algo = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 ||
                   strcmp(argv[i], "--file") == 0) {
            if (i + 1 >= argc) {
                cerr << "Ошибка: после " << argv[i]
                     << " должен быть путь к файлу" << endl;
                return 1;
            }
            file = argv[++i];
        } else {
            cerr << "Ошибка: неизвестный параметр '" << argv[i] << "'" << endl;
            print_help(argv[0]);
            return 1;
        }
    }

    if (file.empty()) {
        cerr << "Ошибка: не указан файл (-f или --file)" << endl;
        print_help(argv[0]);
        return 1;
    }

    // приводим имя алгоритма к нижнему регистру: SHA256 -> sha256
    for (size_t i = 0; i < algo.size(); i++) {
        algo[i] = static_cast<char>(tolower(static_cast<unsigned char>(algo[i])));
    }

    if (registry.find(algo) == registry.end()) {
        cerr << "Ошибка: неизвестный алгоритм '" << algo << "'" << endl;
        cerr << "Допустимые алгоритмы: sha1, sha224, sha256, sha384, sha512" << endl;
        return 1;
    }

    HashTransformation* hash = registry[algo]();
    string digest;
    string err;
    bool ok = hash_file(file, *hash, digest, err);
    delete hash; // освобождаем память, выделенную фабрикой

    if (!ok) {
        cerr << "Ошибка: " << err << endl;
        return 1;
    }

    cout << algo << " (" << file << ") = " << digest << endl;
    return 0;
}
