# Makefile для программы хэширования (библиотека Crypto++)
# Windows (MinGW/MSYS2): mingw32-make
# Linux:                 make

CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
TARGET   = hash
SRC      = hash.cpp

# Вариант 1 - установленная в систему библиотека Crypto++:
#   MSYS2:  pacman -S mingw-w64-x86_64-cryptopp
#   Debian: apt install libcrypto++-dev
LDLIBS   = -lcryptopp

# Вариант 2 - собранная вручную статическая библиотека (Windows, MSVC/VS):
#   LDLIBS = -L C:/cryptopp -lcryptlib
#   и в CXXFLAGS добавить -I C:/cryptopp

ifeq ($(OS),Windows_NT)
    TARGET := $(TARGET).exe
    RM     := del /Q
else
    RM     := rm -f
endif

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

# цель clean удаляет все файлы, созданные в процессе сборки
clean:
	-$(RM) $(TARGET)

.PHONY: all clean
