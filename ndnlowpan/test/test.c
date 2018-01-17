/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "unity.h"
#include "ndnlowpan.h"
 
void test_ndn_encode(void)
{
    uint8_t out[2];
    uint8_t in_int[] = { ICNL_NDN_TLV_INTEREST };
    uint8_t in_data[] = { ICNL_NDN_TLV_DATA };

    unsigned pos_int = icnl_ndn_encode(out, in_int, sizeof(in_int)/sizeof(in_int[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(in_int)/sizeof(in_int[0]) + 1, pos_int);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(in_int, out + 1, pos_int - 1);
    TEST_ASSERT_EQUAL_UINT8(ICNL_NDN_TLV_INTEREST, out[1]);

    unsigned pos_data = icnl_ndn_encode(out, in_data, sizeof(in_data)/sizeof(in_data[0]));

    TEST_ASSERT_EQUAL_UINT(sizeof(in_data)/sizeof(in_data[0]) + 1, pos_data);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(in_data, out + 1, pos_data - 1);
    TEST_ASSERT_EQUAL_UINT8(ICNL_NDN_TLV_DATA, out[1]);
}
 
int main(void)
{
    UNITY_BEGIN();
 
    RUN_TEST(test_ndn_encode);
 
    return UNITY_END();
}
