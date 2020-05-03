//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_DECRYPTOR_H
#define BACKUP2_DECRYPTOR_H


#include <vector>

class Decryptor {
public:
    Decryptor() = delete;
    virtual ~Decryptor() = default;

    virtual std::vector<unsigned char> Process(const unsigned char* data, size_t data_len) = 0;
    virtual std::vector<unsigned char> Process(const std::vector<unsigned char>& data);
    virtual std::vector<unsigned char> Finish() = 0;
};


#endif //BACKUP2_DECRYPTOR_H
