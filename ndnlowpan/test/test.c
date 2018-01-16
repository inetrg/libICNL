/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "unity.h"
#include "ndnlowpan.h"
 
void test_ndn_encode_interest(void)
{
    uint8_t out[2];
    uint8_t in[1] = { 0xAA };
    size_t pos = 0;

    pos += icnl_ndn_encode_interest(out, in, sizeof(in)/sizeof(in[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(in)/sizeof(in[0]) + 1,  pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(in, out + 1, pos - 1);
}

void test_ndn_encode_data(void)
{
    uint8_t out[2];
    uint8_t in[1] = { 0xAA };
    size_t pos = 0;

    pos += icnl_ndn_encode_data(out, in, sizeof(in)/sizeof(in[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(in)/sizeof(in[0]) + 1,  pos);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(in, out + 1, pos - 1);
}

void test_dispatch_add_interest(void)
{
    uint8_t out[1];
    size_t pos = 0;

    pos += icnl_ndn_dispatch_add_interest(out);

    TEST_ASSERT_EQUAL_UINT(1, pos);
    TEST_ASSERT_EQUAL_UINT(ICNL_DISPATCH_NDN_INT, out[0]);
}
 
int main(void)
{
    UNITY_BEGIN();
 
    RUN_TEST(test_dispatch_add_interest);
 
    return UNITY_END();
}
