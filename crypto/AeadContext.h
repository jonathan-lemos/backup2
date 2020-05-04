//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_AEADCONTEXT_H
#define BACKUP2_AEADCONTEXT_H


#include <vector>
#include <cstdint>
#include <cstring>
#include "../misc/strings.h"
#include "CryptoException.h"

template <uint16_t salt_len, uint16_t tag_len>
struct AeadContext final {
    unsigned char salt[salt_len];
    unsigned char tag[tag_len];

    ~AeadContext() {
        memset(salt, 0, sizeof(salt));
        memset(tag, 0, sizeof(tag));
    }

#define serialize16(x) {x & 0xFF00u >> 8u, x & 0xFFu}
#define deserialize16(x) (x[0] << 8u) + x[1]

#define concat(val, id) \
    auto id = val; \
    ret.insert(ret.end(), id.begin(), id.end());

    [[nodiscard]] std::vector<unsigned char> Serialize() const {
        std::vector<unsigned char> ret;

        concat(serialize16(LENGTH), len);
        concat(MAGIC_HEADER, mh);
        concat(serialize16(VERSION), ver);
        concat(serialize16(sizeof(salt)), slen);
        concat(salt, s);
        concat(serialize16(sizeof(tag)), tlen);
        concat(tag, t);

        return ret;
    }

#define safe_memcpy(dest, len) \
    if (ptr + len < bytes_len) { \
        throw CryptoException("Reached EOF while reading bytes. Most likely the bytes are corrupt."); \
    } \
    memcpy(dest, bytes + ptr, len); \
    ptr += len;

#define safe_u16(name) \
    if (ptr + 2 < bytes_len) { \
        throw CryptoException("Reached EOF while reading bytes. Most likely the bytes are corrupt."); \
    } \
    memcpy(u16_buf, bytes + ptr, 2); \
    uint16_t name = (u16_buf[0] << 8u) + u16_buf[1];

    static AeadContext<salt_len, tag_len> Deserialize(const unsigned char* bytes, size_t bytes_len) {
        if (bytes_len < LENGTH) {
            throw CryptoException(format("bytes_len needs to be of length %X", LENGTH));
        }

        unsigned char u16_buf[2];

        AeadContext ret{};
        unsigned char mh_buf[sizeof(MAGIC_HEADER)];
        size_t ptr = 0;

        safe_u16(length);
        if (length != LENGTH) {
            throw CryptoException(format("Expected length field of %X, got %X.", LENGTH, length));
        }

        safe_memcpy(mh_buf, sizeof(MAGIC_HEADER));

        if (memcmp(mh_buf, MAGIC_HEADER, sizeof(MAGIC_HEADER)) != 0) {
            throw CryptoException("The magic header was not detected in the bytes. Most likely the bytes are corrupted.");
        }

        safe_u16(version);
        if (version != VERSION) {
            throw CryptoException(format("The version of the context (%X) is not supported.", version));
        }

        safe_u16(sl);
        if (sl != sizeof(ret.salt)) {
            throw CryptoException(format("The salt must be of size %X, was %X", salt_len, sl));
        }
        safe_memcpy(ret.salt, sizeof(ret.salt));

        safe_u16(tl);
        if (tl != sizeof(ret.tag)) {
            throw CryptoException(format("The tag must be of size %X, was %X", tag_len, tl));
        }
        safe_memcpy(ret.tag, sizeof(ret.tag));

        return ret;
    }

    static constexpr const unsigned char MAGIC_HEADER[] = {0xB2, 0xAE, 0xAD, 0x00};
    static constexpr const uint16_t VERSION = 0x0000;
    static constexpr const size_t VERSION_LEN = sizeof(VERSION);

    static constexpr const uint16_t LENGTH = sizeof(MAGIC_HEADER) + sizeof(VERSION) + 2 + sizeof(salt) + 2 + sizeof(tag);
};

#undef serialize16
#undef deserialize16
#undef concat
#undef safe_memcpy
#undef safe_u16

#endif //BACKUP2_AEADCONTEXT_H
