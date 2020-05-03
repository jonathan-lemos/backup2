//
// Created by jonathan on 5/2/20.
//

#include "Encryptor.h"

std::vector<unsigned char> Encryptor::Process(const std::vector<unsigned char> &data) {
    return this->Process(data.data(), data.size());
}
