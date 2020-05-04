//
// Created by jonathan on 5/3/20.
//

#include <gtest/gtest.h>
#include "../crypto/Aes256GcmEncryptor.h"
#include "../crypto/Aes256GcmDecryptor.h"

TEST(crypto, basic_test) {
    const unsigned char test_data[] = {0x01, 0x02, 0x03};
    std::string password = "password";
    std::vector<unsigned char> encData;
    std::vector<unsigned char> decData;

    Aes256GcmEncryptor enc(password);
    auto tmp1 = enc.Process(test_data, sizeof(test_data));
    encData.insert(encData.end(), tmp1.begin(), tmp1.end());
    enc.Finish();

    auto ctx = enc.Context();
    Aes256GcmDecryptor dec(ctx, password);

    auto tmp2 = dec.Process(tmp1.data(), tmp1.size());
    decData.insert(decData.end(), tmp2.begin(), tmp2.end());
    dec.Finish();

    ASSERT_EQ(sizeof(test_data) / sizeof(test_data[0]), tmp2.size());
    for (int i = 0; i < tmp2.size(); ++i) {
        if (test_data[i] != tmp2[i]) {
            FAIL();
        }
    }
}
