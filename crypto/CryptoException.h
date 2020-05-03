//
// Created by jonathan on 5/2/20.
//

#ifndef BACKUP2_CRYPTOEXCEPTION_H
#define BACKUP2_CRYPTOEXCEPTION_H


#include <stdexcept>

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const char* reason) : std::runtime_error(reason) {}
    explicit CryptoException(const std::string& reason) : CryptoException(reason.c_str()) {}

};


#endif //BACKUP2_CRYPTOEXCEPTION_H
