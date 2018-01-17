/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "unity.h"
#include "core.h"

#ifdef MODULE_NDNLOWPAN
#include "ndnlowpan.h"
#endif

static const uint8_t ndn_int[] = {
    0x05, 0x11, 0x07, 0x05, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x0a, 0x04, 0x12, 0x57, 0x05, 0x00, 0x0c,
    0x02, 0x0f, 0xa0
};

static const uint8_t ndn_int_disp[] = {
    0xF2, ICNL_DISPATCH_NDN_INT, /* Page 2 and LOWPAN_NDN_INT */
    0x05, 0x11, 0x07, 0x05, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x0a, 0x04, 0x12, 0x57, 0x05, 0x00, 0x0c,
    0x02, 0x0f, 0xa0
};

static const uint8_t ndn_data[] = {
    0x06, 0x18, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x01,
    0x31, 0x16, 0x05, 0x1b, 0x01, 0x00, 0x1c, 0x00,
    0x17, 0x00
};

static const uint8_t ndn_data_disp[] = {
    0xF2, ICNL_DISPATCH_NDN_DATA, /* Page 2 and LOWPAN_NDN_DATA */
    0x06, 0x18, 0x07, 0x08, 0x08, 0x03, 0x48, 0x41,
    0x57, 0x08, 0x01, 0x41, 0x14, 0x00, 0x15, 0x01,
    0x31, 0x16, 0x05, 0x1b, 0x01, 0x00, 0x1c, 0x00,
    0x17, 0x00
};
 
void test_page_add(void)
{
    uint8_t out[1];
    unsigned pos = 0;

    out[pos++] = ICNL_DISPATCH_PAGE;

    TEST_ASSERT_EQUAL_UINT8(ICNL_DISPATCH_PAGE, out[0]);
    TEST_ASSERT_EQUAL_UINT(1, pos);
}

#ifdef MODULE_NDNLOWPAN
void test_encode_ndn_int(void)
{
    uint8_t out[sizeof(ndn_int) / sizeof(ndn_int[0]) + 2];
    unsigned pos = 0;

    pos += icnl_encode(out, ICNL_PROTO_NDN, (uint8_t *)ndn_int,
                       sizeof(ndn_int)/sizeof(ndn_int[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_int)/sizeof(ndn_int[0]) + 2, pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_int, out + 2, pos - 2);
}

void test_encode_ndn_data(void)
{
    uint8_t out[sizeof(ndn_data) / sizeof(ndn_data[0]) + 2];
    unsigned pos = 0;

    pos += icnl_encode(out, ICNL_PROTO_NDN, (uint8_t *)ndn_data,
                       sizeof(ndn_data)/sizeof(ndn_data[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(ndn_data)/sizeof(ndn_data[0]) + 2, pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ndn_data, out + 2, pos - 2);
}
#endif
 
int main(void)
{
    UNITY_BEGIN();
 
    RUN_TEST(test_page_add);
#ifdef MODULE_NDNLOWPAN
    RUN_TEST(test_encode_ndn_int);
    RUN_TEST(test_encode_ndn_data);
#endif
 
    return UNITY_END();
}
