BUILD_DIR = build
INSTALL_INCLUDE_DIR = /usr/local/include/ecstk

CFLAGS = -Wall -Wextra -Wno-missing-braces -pedantic -O2 -std=c++20
CFLAGS_LIBSODIUM = $(shell pkg-config --cflags libsodium)
LIBS_LIBSODIUM = $(shell pkg-config --libs libsodium)

CPP = g++

all: tests

tests: tests-crypto

src/buffer.hh:
	ln -s $(INSTALL_INCLUDE_DIR)/buffer.hh src/buffer.hh

tests-crypto: src/buffer.hh
	$(CPP) $(CFLAGS) $(CFLAGS_LIBSODIUM) tests/crypto.cc $(LIBS_LIBSODIUM) -o $(BUILD_DIR)/tests-crypto

clean:
	rm src/buffer.hh
	rm -f $(BUILD_DIR)/*

install:
	cp src/crypto.hh $(INSTALL_INCLUDE_DIR)
	cp src/crypto_*.hh $(INSTALL_INCLUDE_DIR)

uninstall:
	rm $(INSTALL_INCLUDE_DIR)/crypto.hh
	rm $(INSTALL_INCLUDE_DIR)/crypto_*.hh
