cmake_minimum_required(VERSION 3.16)
project(backup2)

set(CMAKE_CXX_STANDARD 20)

link_libraries(crypto)

add_executable(backup2 main.cpp crypto/Encryptor.cpp crypto/Encryptor.h crypto/Decryptor.cpp crypto/Decryptor.h crypto/Aes256GcmEncryptor.cpp crypto/Aes256GcmEncryptor.h crypto/Random.cpp crypto/Random.h crypto/CryptoException.cpp crypto/CryptoException.h crypto/Kdf.cpp crypto/Kdf.h crypto/ScryptKdf.cpp crypto/ScryptKdf.h crypto/AeadContext.cpp crypto/AeadContext.h misc/strings.cpp misc/strings.h crypto/Aes256GcmDecryptor.cpp crypto/Aes256GcmDecryptor.h tests/test_crypto.cpp)