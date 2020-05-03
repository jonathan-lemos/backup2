//
// Created by jonathan on 5/2/20.
//

#include "Decryptor.h"

std::vector<unsigned char> Decryptor::Process(const std::vector<unsigned char> &data) {
    return this->Process(data.data(), data.size());
}
