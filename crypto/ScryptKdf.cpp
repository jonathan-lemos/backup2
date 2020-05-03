//
// Created by jonathan on 5/2/20.
//

#include "ScryptKdf.h"
#include "CryptoException.h"
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <cstring>

ScryptKdf::ScryptKdf(unsigned log2_n, unsigned r, unsigned p) {
    this->n = 1u << log2_n;
    this->r = r;
    this->p = p;

    this->ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_PKEY_CTX_set_scrypt_N(ctx, n) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_PKEY_CTX_set_scrypt_r(ctx, r) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_PKEY_CTX_set_scrypt_p(ctx, p) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }
}

ScryptKdf::~ScryptKdf() {
    EVP_PKEY_CTX_free(ctx);
}

void
ScryptKdf::DeriveKey(const unsigned char *password, size_t password_len, const unsigned char *salt, size_t salt_len,
                     unsigned char *out_key, size_t key_len, unsigned char *out_iv, size_t iv_len) {
    if (EVP_PKEY_CTX_set1_pbe_pass(ctx, password, password_len) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, salt, salt_len) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    std::vector<unsigned char> buf(key_len + iv_len);
    size_t size = key_len + iv_len;

    if (EVP_PKEY_derive(ctx, buf.data(), &size) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    memcpy(out_key, buf.data(), key_len);
    memcpy(out_iv, buf.data() + key_len, iv_len);

    memset(buf.data(), 0, buf.size());
}
