//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_ENCRYPTOR_H
#define BACKUP2_ENCRYPTOR_H

#include <string>
#include <vector>


class Encryptor {
public:
    Encryptor() = default;
    virtual ~Encryptor() = default;

    virtual std::vector<unsigned char> Process(const unsigned char* data, size_t data_len) = 0;
    virtual std::vector<unsigned char> Process(const std::vector<unsigned char>& data);
    virtual std::vector<unsigned char> Finish() = 0;
    virtual std::vector<unsigned char> AuthenticationTag() = 0;
};


#endif //BACKUP2_ENCRYPTOR_H
