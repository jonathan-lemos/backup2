//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_RANDOM_H
#define BACKUP2_RANDOM_H


#include <cstddef>
#include <vector>

void RandBytes(unsigned char* in_out, size_t length);
std::vector<unsigned char> RandBytes(size_t length);

#endif //BACKUP2_RANDOM_H
