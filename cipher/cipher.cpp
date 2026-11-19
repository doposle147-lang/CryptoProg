// cipher.cpp - программа зашифрования/расшифрования содержимого файлов
// Библиотека: Crypto++ (https://www.cryptopp.com)
// Алгоритм: AES (блочный), режим CBC, ключ вырабатывается из пароля
//           по схеме PBKDF2-HMAC-SHA256 со случайной "солью"
//
// Формат зашифрованного файла:
//   "CPG1" (4 байта) | salt (16 байт) | IV (16 байт) | шифртекст (кратен 16)
//
// Сборка (MinGW/MSYS2, Windows):  mingw32-make      -> cipher.exe
// Сборка (Linux):                 make              -> ./cipher
// Использование:
//   cipher -e -i secret.txt -o secret.enc -p пароль
//   cipher -d -i secret.enc -o secret.dec -p пароль

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cstdio>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace std;
using namespace CryptoPP;

static const char   MAGIC[4]  = { 'C', 'P', 'G', '1' };
static const size_t SALT_SIZE = 16; // размер "соли"
static const size_t IV_SIZE   = AES::BLOCKSIZE; // 16 байт
static const size_t KEY_SIZE  = AES::MAX_KEYLENGTH; // 32 байта -> AES-256
static const unsigned int ITERATIONS = 100000; // число итераций PBKDF2

static void print_help(const char* prog) {
    cout << "Использование: " << prog
         << " <режим> -i <входной файл> -o <выходной файл> [-p <пароль>]" << endl;
    cout << endl;
    cout << "Программа зашифрования/расшифрования файлов." << endl;
    cout << "Алгоритм: AES-256, режим CBC, ключ вырабатывается из пароля"
         << " (PBKDF2)." << endl;
    cout << endl;
    cout << "Параметры:" << endl;
    cout << "  -e, --encrypt          режим зашифрования" << endl;
    cout << "  -d, --decrypt          режим расшифрования" << endl;
    cout << "  -i, --input <файл>     файл с исходными данными" << endl;
    cout << "  -o, --output <файл>    файл для записи результата" << endl;
    cout << "  -p, --password <пароль> пароль для формирования ключа" << endl;
    cout << "                         (по умолчанию - запрос при запуске)" << endl;
    cout << "  -h, --help             показать справку" << endl;
    cout << endl;
    cout << "Примеры:" << endl;
    cout << "  " << prog << " -e -i secret.txt -o secret.enc -p 12345" << endl;
    cout << "  " << prog << " -d -i secret.enc -o secret.dec -p 12345" << endl;
}

// Ввод пароля без отображения символов на экране
static string read_password(const string& prompt) {
    cout << prompt << flush;
    string pass;

#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool console = GetConsoleMode(h, &mode) != 0;
    if (console) SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    getline(cin, pass);
    if (console) SetConsoleMode(h, mode);
#else
    termios oldt, newt;
    bool tty = tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (tty) {
        newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    getline(cin, pass);
    if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    cout << endl;
    return pass;
}

// Чтение файла целиком в буфер
static bool read_file(const string& path, vector<char>& data, string& err) {
    ifstream in(path.c_str(), ios::binary);
    if (!in) { err = "не удалось открыть файл '" + path + "'"; return false; }
    in.seekg(0, ios::end);
    streamoff size = in.tellg();
    if (size < 0) { err = "ошибка чтения файла '" + path + "'"; return false; }
    in.seekg(0, ios::beg);
    data.resize(static_cast<size_t>(size));
    if (size > 0) in.read(&data[0], size);
    if (!in) { err = "ошибка чтения файла '" + path + "'"; return false; }
    return true;
}

// Запись буфера в файл целиком
static bool write_file(const string& path, const string& data, string& err) {
    ofstream out(path.c_str(), ios::binary | ios::trunc);
    if (!out) { err = "не удалось создать файл '" + path + "'"; return false; }
    out.write(data.data(), static_cast<streamsize>(data.size()));
    out.close();
    if (!out) { err = "ошибка записи файла '" + path + "'"; return false; }
    return true;
}

// Выработка ключа из пароля: PBKDF2-HMAC-SHA256
static void derive_key(const string& password, const vector<CryptoPP::byte>& salt,
                       vector<CryptoPP::byte>& key) {
    key.resize(KEY_SIZE);
    PKCS5_PBKDF2_HMAC<SHA256> kdf;
    kdf.DeriveKey(key.data(), key.size(), 0,
                  reinterpret_cast<const CryptoPP::byte*>(password.data()),
                  password.size(), salt.data(), salt.size(), ITERATIONS);
}

static bool encrypt_file(const string& in_path, const string& out_path,
                         const string& password, string& err) {
    vector<char> plain;
    if (!read_file(in_path, plain, err)) return false;

    AutoSeededRandomPool rng;

    vector<CryptoPP::byte> salt(SALT_SIZE);
    rng.GenerateBlock(salt.data(), salt.size());

    vector<CryptoPP::byte> key;
    derive_key(password, salt, key);

    CryptoPP::byte iv[IV_SIZE];
    rng.GenerateBlock(iv, IV_SIZE);

    string cipher_text;
    try {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv, IV_SIZE);
        StringSource ss(
            reinterpret_cast<const CryptoPP::byte*>(plain.data()),
            plain.size(), true,
            new StreamTransformationFilter(enc,              // PKCS#7 padding
                new StringSink(cipher_text)));
    } catch (const Exception& e) {
        err = string("ошибка зашифрования: ") + e.what();
        return false;
    }

    // собираем результирующий файл: заголовок + шифртекст
    string out;
    out.append(MAGIC, sizeof(MAGIC));
    out.append(reinterpret_cast<const char*>(salt.data()), salt.size());
    out.append(reinterpret_cast<const char*>(iv), IV_SIZE);
    out += cipher_text;

    return write_file(out_path, out, err);
}

static bool decrypt_file(const string& in_path, const string& out_path,
                         const string& password, string& err) {
    vector<char> file;
    if (!read_file(in_path, file, err)) return false;

    const size_t need = sizeof(MAGIC) + SALT_SIZE + IV_SIZE;
    if (file.size() < need) {
        err = "файл '" + in_path + "' повреждён (слишком мал)";
        return false;
    }
    if (memcmp(&file[0], MAGIC, sizeof(MAGIC)) != 0) {
        err = "файл '" + in_path + "' не является файлом, созданным этой программой";
        return false;
    }

    vector<CryptoPP::byte> salt(SALT_SIZE), key;
    CryptoPP::byte iv[IV_SIZE];
    memcpy(salt.data(), &file[sizeof(MAGIC)], SALT_SIZE);
    memcpy(iv, &file[sizeof(MAGIC) + SALT_SIZE], IV_SIZE);
    string cipher_text = string(&file[need], file.size() - need);

    derive_key(password, salt, key);

    string plain;
    try {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv, IV_SIZE);
        StringSource ss(
            reinterpret_cast<const CryptoPP::byte*>(cipher_text.data()),
            cipher_text.size(), true,
            new StreamTransformationFilter(dec, new StringSink(plain)));
    } catch (const Exception& e) {
        err = string("не удалось расшифровать (неверный пароль или "
                     "повреждённый файл): ") + e.what();
        return false;
    }

    return write_file(out_path, plain, err);
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

    int mode = 0; // 1 - зашифрование, 2 - расшифрование
    string in_path, out_path, password;
    bool password_given = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-e") == 0 ||
                   strcmp(argv[i], "--encrypt") == 0) {
            if (mode != 0) {
                cerr << "Ошибка: режим указан дважды" << endl;
                return 1;
            }
            mode = 1;
        } else if (strcmp(argv[i], "-d") == 0 ||
                   strcmp(argv[i], "--decrypt") == 0) {
            if (mode != 0) {
                cerr << "Ошибка: режим указан дважды" << endl;
                return 1;
            }
            mode = 2;
        } else if (strcmp(argv[i], "-i") == 0 ||
                   strcmp(argv[i], "--input") == 0) {
            if (i + 1 >= argc) {
                cerr << "Ошибка: после " << argv[i] << " должен быть файл" << endl;
                return 1;
            }
            in_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 ||
                   strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                cerr << "Ошибка: после " << argv[i] << " должен быть файл" << endl;
                return 1;
            }
            out_path = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 ||
                   strcmp(argv[i], "--password") == 0) {
            if (i + 1 >= argc) {
                cerr << "Ошибка: после " << argv[i]
                     << " должен быть пароль" << endl;
                return 1;
            }
            password = argv[++i];
            password_given = true;
        } else {
            cerr << "Ошибка: неизвестный параметр '" << argv[i] << "'" << endl;
            print_help(argv[0]);
            return 1;
        }
    }

    if (mode == 0) {
        cerr << "Ошибка: не указан режим работы (-e или -d)" << endl;
        print_help(argv[0]);
        return 1;
    }
    if (in_path.empty()) {
        cerr << "Ошибка: не указан входной файл (-i)" << endl;
        return 1;
    }
    if (out_path.empty()) {
        cerr << "Ошибка: не указан выходной файл (-o)" << endl;
        return 1;
    }

    if (!password_given) password = read_password("Пароль: ");
    if (password.empty()) {
        cerr << "Ошибка: пароль не может быть пустым" << endl;
        return 1;
    }

    string err;
    bool ok = (mode == 1) ? encrypt_file(in_path, out_path, password, err)
                          : decrypt_file(in_path, out_path, password, err);

    if (!ok) {
        cerr << "Ошибка: " << err << endl;
        return 1;
    }

    cout << (mode == 1 ? "Файл зашифрован: " : "Файл расшифрован: ")
         << out_path << endl;
    return 0;
}
