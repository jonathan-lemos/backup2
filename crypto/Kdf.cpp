//
// Created by jonathan on 5/2/20.
//

#include <cstring>
#include "Kdf.h"


void Kdf::DeriveKey(const char *password, const unsigned char *salt, size_t salt_len, unsigned char *out_key, size_t key_len,
               unsigned char *out_iv, size_t iv_len) {
    this->DeriveKey(reinterpret_cast<const unsigned char*>(password), strlen(password), salt, salt_len, out_key, key_len, out_iv, iv_len);
}

void Kdf::DeriveKey(const std::string &password, const unsigned char *salt, size_t salt_len, unsigned char *out_key,
                    size_t key_len, unsigned char *out_iv, size_t iv_len) {
    this->DeriveKey(password.c_str(), salt, salt_len, out_key, key_len, out_iv, iv_len);
}
