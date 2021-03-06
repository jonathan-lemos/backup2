//
// Created by jonathan on 5/2/20.
//

#include "Aes256GcmEncryptor.h"
#include "ScryptKdf.h"
#include "CryptoException.h"
#include "Random.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>

std::vector<unsigned char> Aes256GcmEncryptor::Process(const unsigned char *data, size_t data_len) {
    if (finished) {
        throw CryptoException("Cannot process more data after Finish() call");
    }

    std::vector<unsigned char> ret(data_len);
    int len = data_len;

    if (EVP_EncryptUpdate(ctx, ret.data(), &len, data, data_len) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    ret.resize(len);
    return ret;
}

std::vector<unsigned char> Aes256GcmEncryptor::Finish() {
    if (finished) {
        return std::vector<unsigned char>();
    }

    int len = 16;
    std::vector<unsigned char> ret(len);

    if (EVP_EncryptFinal_ex(ctx, ret.data(), &len) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    ret.resize(len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(ectx.tag), ectx.tag) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }
    finished = true;

    return ret;
}

Aes256GcmEncryptor::Aes256GcmEncryptor(const unsigned char* password_bytes, size_t len) {
    RandBytes(ectx.salt, sizeof(ectx.salt));

    ScryptKdf kdf;
    kdf.DeriveKey(password_bytes, len, ectx.salt, sizeof(ectx.salt), key, sizeof(key), iv, sizeof(iv));

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }
}

Aes256GcmEncryptor::~Aes256GcmEncryptor() {
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    EVP_CIPHER_CTX_free(ctx);
}

AeadContext<32, 16> Aes256GcmEncryptor::Context() const {
    if (!finished) {
        throw CryptoException("Call Finish() before calling Context()");
    }
    return AeadContext<32, 16>(ectx);
}
