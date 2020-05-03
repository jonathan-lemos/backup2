//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_SCRYPTKDF_H
#define BACKUP2_SCRYPTKDF_H


#include "Kdf.h"
#include <cstdint>
#include <openssl/kdf.h>
#include <openssl/evp.h>

class ScryptKdf final : public Kdf {
public:
    explicit ScryptKdf(unsigned log2_n = 20, unsigned r = 8, unsigned p = 1);
    ~ScryptKdf() override;

    void DeriveKey(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len,
                   unsigned char *out_key, size_t key_len, unsigned char *out_iv, size_t iv_len) override;

private:
    uint64_t n;
    uint32_t r;
    uint32_t p;
    EVP_PKEY_CTX* ctx = nullptr;
};


#endif //BACKUP2_SCRYPTKDF_H
