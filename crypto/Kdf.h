//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_KDF_H
#define BACKUP2_KDF_H


#include <ostream>
#include <vector>

class Kdf {
public:
    Kdf() = default;
    virtual ~Kdf() = default;

    virtual void DeriveKey(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len,
                   unsigned char *out_key, size_t key_len, unsigned char *out_iv, size_t iv_len) = 0;

    virtual void DeriveKey(const char* password, const unsigned char *salt, size_t salt_len,
                           unsigned char *out_key, size_t key_len, unsigned char *out_iv, size_t iv_len);

    virtual void DeriveKey(const std::string& password, const unsigned char *salt, size_t salt_len,
                           unsigned char *out_key, size_t key_len, unsigned char *out_iv, size_t iv_len);
};


#endif //BACKUP2_KDF_H
