// SPDX-License-Identifier: GPL-3.0-or-later
// Base64 encoder/decoder (src/base64.cpp): round trips and invalid input.
#include <cstdint>
#include <cstring>

#include "base64.h"
#include "test_helpers.hpp"

namespace {

void test_encode_decode()
{
    const uint8_t input[] = "Hello";
    char encoded[BASE64_SIZE(5)];
    uint8_t decoded[5];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 5);
    SS_CHECK(ret != nullptr);
    SS_CHECK(std::strlen(encoded) > 0);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    SS_CHECK(decoded_len == 5);
    SS_CHECK(std::memcmp(decoded, input, 5) == 0);
}

void test_empty_input()
{
    char encoded[BASE64_SIZE(0)];
    char *ret = base64_encode(encoded, sizeof(encoded), reinterpret_cast<const uint8_t *>(""), 0);
    SS_CHECK(ret != nullptr);
    SS_CHECK(std::strlen(encoded) == 0);
}

void test_single_byte()
{
    const uint8_t input[] = { 0x41 }; // 'A'
    char encoded[BASE64_SIZE(1)];
    uint8_t decoded[1];

    SS_CHECK(base64_encode(encoded, sizeof(encoded), input, 1) != nullptr);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    SS_CHECK(decoded_len == 1);
    SS_CHECK(decoded[0] == 0x41);
}

void test_two_bytes()
{
    const uint8_t input[] = { 0x41, 0x42 }; // "AB"
    char encoded[BASE64_SIZE(2)];
    uint8_t decoded[2];

    SS_CHECK(base64_encode(encoded, sizeof(encoded), input, 2) != nullptr);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    SS_CHECK(decoded_len == 2);
    SS_CHECK(decoded[0] == 0x41);
    SS_CHECK(decoded[1] == 0x42);
}

void test_three_bytes()
{
    const uint8_t input[] = { 0x00, 0xFF, 0x80 };
    char encoded[BASE64_SIZE(3)];
    uint8_t decoded[3];

    SS_CHECK(base64_encode(encoded, sizeof(encoded), input, 3) != nullptr);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    SS_CHECK(decoded_len == 3);
    SS_CHECK(decoded[0] == 0x00);
    SS_CHECK(decoded[1] == 0xFF);
    SS_CHECK(decoded[2] == 0x80);
}

void test_roundtrip_binary()
{
    const uint8_t input[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    char encoded[BASE64_SIZE(17)];
    uint8_t decoded[17];

    SS_CHECK(base64_encode(encoded, sizeof(encoded), input, 17) != nullptr);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    SS_CHECK(decoded_len == 17);
    SS_CHECK(std::memcmp(decoded, input, 17) == 0);
}

void test_invalid_chars()
{
    // Character '!' (ASCII 33) is below the base64 range start ('+' = 43).
    uint8_t out[4] = {};
    SS_CHECK(base64_decode(out, "!!!!", 4) == -1);
}

} // namespace

int main()
{
    SS_RUN(test_encode_decode);
    SS_RUN(test_empty_input);
    SS_RUN(test_single_byte);
    SS_RUN(test_two_bytes);
    SS_RUN(test_three_bytes);
    SS_RUN(test_roundtrip_binary);
    SS_RUN(test_invalid_chars);
    return 0;
}
