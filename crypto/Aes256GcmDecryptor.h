//
// Created by jonathan on 5/3/20.
//

#ifndef BACKUP2_AES256GCMDECRYPTOR_H
#define BACKUP2_AES256GCMDECRYPTOR_H


#include "Decryptor.h"
#include "AeadContext.h"
#include <openssl/evp.h>
#include <string>

class Aes256GcmDecryptor final : public Decryptor {
public:
    Aes256GcmDecryptor(const Aes256GcmDecryptor& other) = delete;
    Aes256GcmDecryptor(Aes256GcmDecryptor&& other) = delete;
    Aes256GcmDecryptor& operator=(const Aes256GcmDecryptor& other) = delete;
    Aes256GcmDecryptor& operator=(Aes256GcmDecryptor&& other) = delete;
    ~Aes256GcmDecryptor() override;

    Aes256GcmDecryptor(const AeadContext<32, 16>& ctx, const unsigned char* password_bytes, size_t len);
    Aes256GcmDecryptor(const AeadContext<32, 16>& ctx, const std::vector<unsigned char>& password) : Aes256GcmDecryptor(ctx, password.data(), password.size()) {}
    Aes256GcmDecryptor(const AeadContext<32, 16>& ctx, const std::string& password) : Aes256GcmDecryptor(ctx,
            reinterpret_cast<const unsigned char *>(&(password[0])), password.size()) {}

    std::vector<unsigned char> Process(const unsigned char *data, size_t data_len) override;
    std::vector<unsigned char> Finish() override;

private:
    unsigned char key[32]{};
    unsigned char iv[16]{};

    AeadContext<32, 16> ectx{};
    bool finished = false;

    EVP_CIPHER_CTX* ctx = nullptr;
};


#endif //BACKUP2_AES256GCMDECRYPTOR_H
