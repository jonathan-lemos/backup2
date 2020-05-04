//
// Created by jonathan on 5/3/20.
//

#include "Aes256GcmDecryptor.h"
#include "ScryptKdf.h"
#include "CryptoException.h"
#include "Random.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

Aes256GcmDecryptor::Aes256GcmDecryptor(const AeadContext<32, 16>& actx, const unsigned char *password_bytes, size_t len) {
    ectx = actx;

    ScryptKdf kdf;
    kdf.DeriveKey(password_bytes, len, ectx.salt, sizeof(ectx.salt), key, sizeof(key), iv, sizeof(iv));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr)) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }
}

Aes256GcmDecryptor::~Aes256GcmDecryptor() {
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    EVP_CIPHER_CTX_free(ctx);
}

std::vector<unsigned char> Aes256GcmDecryptor::Process(const unsigned char *data, size_t data_len) {
    if (finished) {
        throw CryptoException("Cannot process more data after Finish() call");
    }

    std::vector<unsigned char> ret(data_len);
    int len = data_len;

    if (!EVP_DecryptUpdate(ctx, ret.data(), &len, data, data_len)) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    ret.resize(len);
    return ret;
}

std::vector<unsigned char> Aes256GcmDecryptor::Finish() {
    if (finished) {
        return std::vector<unsigned char>();
    }

    int len = 16;
    std::vector<unsigned char> ret(len);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(ectx.tag), ectx.tag)) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_DecryptFinal_ex(ctx, ret.data(), &len) <= 0) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    ret.resize(len);
    finished = true;

    return ret;
}
