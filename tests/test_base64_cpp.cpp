#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "base64.h"

static void
test_encode_decode(void)
{
    /* Known test vector: "Hello" */
    const uint8_t input[] = "Hello";
    char encoded[BASE64_SIZE(5)];
    uint8_t decoded[5];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 5);
    assert(ret != NULL);
    assert(strlen(encoded) > 0);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    assert(decoded_len == 5);
    assert(memcmp(decoded, input, 5) == 0);
}

static void
test_empty_input(void)
{
    char encoded[BASE64_SIZE(0)];
    char *ret = base64_encode(encoded, sizeof(encoded), (const uint8_t *)"", 0);
    assert(ret != NULL);
    assert(strlen(encoded) == 0);
}

static void
test_single_byte(void)
{
    const uint8_t input[] = { 0x41 }; /* 'A' */
    char encoded[BASE64_SIZE(1)];
    uint8_t decoded[1];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 1);
    assert(ret != NULL);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    assert(decoded_len == 1);
    assert(decoded[0] == 0x41);
}

static void
test_two_bytes(void)
{
    const uint8_t input[] = { 0x41, 0x42 }; /* "AB" */
    char encoded[BASE64_SIZE(2)];
    uint8_t decoded[2];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 2);
    assert(ret != NULL);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    assert(decoded_len == 2);
    assert(decoded[0] == 0x41);
    assert(decoded[1] == 0x42);
}

static void
test_three_bytes(void)
{
    const uint8_t input[] = { 0x00, 0xFF, 0x80 };
    char encoded[BASE64_SIZE(3)];
    uint8_t decoded[3];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 3);
    assert(ret != NULL);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    assert(decoded_len == 3);
    assert(decoded[0] == 0x00);
    assert(decoded[1] == 0xFF);
    assert(decoded[2] == 0x80);
}

static void
test_roundtrip_binary(void)
{
    const uint8_t input[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                              10, 11, 12, 13, 14, 15, 16 };
    char encoded[BASE64_SIZE(17)];
    uint8_t decoded[17];

    char *ret = base64_encode(encoded, sizeof(encoded), input, 17);
    assert(ret != NULL);

    int decoded_len = base64_decode(decoded, encoded, sizeof(decoded));
    assert(decoded_len == 17);
    assert(memcmp(decoded, input, 17) == 0);
}

static void
test_invalid_chars(void)
{
    /* Character '!' (ASCII 33) is below the base64 range start ('+' = 43) */
    int decoded_len = base64_decode((uint8_t[4]){}, "!!!!", 4);
    assert(decoded_len == -1);
}

int
main(void)
{
    test_encode_decode();
    test_empty_input();
    test_single_byte();
    test_two_bytes();
    test_three_bytes();
    test_roundtrip_binary();
    test_invalid_chars();
    return 0;
}
