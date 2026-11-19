# CryptoProg

Практическое задание 4. Программы на C++ с Crypto++, собирал в MSYS2
(UCRT64), через mingw32-make.

hash - считает хэш файла. sha1, sha224, sha256, sha384, sha512,
по умолчанию sha256. Без параметров печатает справку.

    cd hash
    mingw32-make
    .\hash.exe -a sha256 -f ..\tests\test.txt

cipher - шифрует и расшифровывает файлы. AES-256, режим CBC, ключ из пароля
через PBKDF2 (SHA-256, 100000 итераций), соль и IV случайные и пишутся в
начало файла вместе с сигнатурой CPG1, иначе не расшифруешь.

    cd cipher
    mingw32-make
    .\cipher.exe -e -i ..\tests\test.txt -o ..\tests\test.enc -p Student2026
    .\cipher.exe -d -i ..\tests\test.enc -o ..\tests\test.dec -p Student2026

-e / -d - режим, -i / -o - файлы, -p - пароль. Если -p не указать, спросит.

Что проверял: sha256 сверил с certutil, совпало. После шифрования и
расшифрования fc /b различий не нашёл. Исходный 20 байт, зашифрованный 68,
восстановленный 20. С неверным паролем выдаёт ошибку и код 1.

Crypto++ ставится pacman -S mingw-w64-ucrt-x86_64-crypto++ (MSYS2) или
apt install libcrypto++-dev (ubuntu). Если g++ не видит cryptopp/sha.h -
библиотека не стоит или PATH.