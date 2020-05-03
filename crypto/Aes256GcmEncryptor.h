//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_AES256GCMENCRYPTOR_H
#define BACKUP2_AES256GCMENCRYPTOR_H


#include "Encryptor.h"
#include "Kdf.h"
#include <openssl/evp.h>
#include <array>

class Aes256GcmEncryptor final : public Encryptor {
public:
    Aes256GcmEncryptor(const Aes256GcmEncryptor& other) = delete;
    Aes256GcmEncryptor(Aes256GcmEncryptor&& other) = delete;
    Aes256GcmEncryptor& operator=(const Aes256GcmEncryptor& other) = delete;
    Aes256GcmEncryptor& operator=(Aes256GcmEncryptor&& other) = delete;
    ~Aes256GcmEncryptor() override;

    Aes256GcmEncryptor(const unsigned char* password_bytes, size_t len);
    explicit Aes256GcmEncryptor(const std::vector<unsigned char>& password) : Aes256GcmEncryptor(&(password[0]), password.size()) {}
    explicit Aes256GcmEncryptor(const std::string& password) : Aes256GcmEncryptor(
            reinterpret_cast<const unsigned char *>(&(password[0])), password.size()) {}

    std::vector<unsigned char> Process(const unsigned char *data, size_t data_len) override;
    std::vector<unsigned char> Finish() override;
    std::vector<unsigned char> AuthenticationTag() override;



private:
    const static int TAG_LEN;
    unsigned char key[32];
    unsigned char iv[32];
    unsigned char salt[16];
    EVP_CIPHER_CTX* ctx = nullptr;
};

const int Aes256GcmEncryptor::TAG_LEN = 16


#endif //BACKUP2_AES256GCMENCRYPTOR_H
