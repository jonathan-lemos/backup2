#include <iostream>
#include <openssl/err.h>

int main() {
    ERR_load_CRYPTO_strings();
    ERR_load_ERR_strings();

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
