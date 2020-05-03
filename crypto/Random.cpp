//
// Created by jonathan on 5/2/20.
//

#include "Random.h"
#include "CryptoException.h"
#include <openssl/rand.h>
#include <openssl/err.h>

void RandBytes(unsigned char *in_out, size_t length) {
    if (RAND_bytes(in_out, length) != 1) {
        throw CryptoException(ERR_error_string(ERR_get_error(), nullptr));
    }
}

std::vector<unsigned char> RandBytes(size_t length) {
    std::vector<unsigned char> ret(length);
    RandBytes(ret.data(), length);
    return ret;
}
