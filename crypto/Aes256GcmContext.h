//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_AES256GCMCONTEXT_H
#define BACKUP2_AES256GCMCONTEXT_H


#include <vector>

struct Aes256GcmContext final {
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char salt[32];
    unsigned char tag[16];

    ~Aes256GcmContext();

    std::vector<unsigned char> Serialize() const;

    static Aes256GcmContext Deserialize(const unsigned char* bytes, size_t bytes_len);

    constexpr static size_t HEADER_LEN = sizeof(key) + sizeof(iv) + sizeof(salt) + sizeof(tag);
};


#endif //BACKUP2_AES256GCMCONTEXT_H
