/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        ndnlowpan.h
 * @brief       ndnlowpan module functions
 * @author      Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 * @copyright   GNU Lesser General Public License v2.1
 * @addtogroup  ndnlowpan ndnlowpan module
 * @{
 */
#ifndef NDNLOWPAN_H
#define NDNLOWPAN_H
 
#include <stdint.h>

#include "icnlowpan.h"

/**
 * @brief   Dispatch type for NDN Interest
 */
#define ICNL_DISPATCH_NDN_INT       (0x80)

/**
 * @brief   Dispatch type for NDN Data
 */
#define ICNL_DISPATCH_NDN_DATA      (0x90)

/**
 * @brief   Dispatch type for NDN Interest with header compression.
 *          A octet follows.
 */
#define ICNL_DISPATCH_NDN_INT_HC_A  (0x88)

/**
 * @brief   Dispatch type for NDN Interest with header compression.
 *          A and B octet follows.
 */
#define ICNL_DISPATCH_NDN_INT_HC_AB (0x89)

/**
 * @brief   NDN TLVs
 * @{
 */
typedef enum {
    ICNL_NDN_TLV_INTEREST = 0x05,   /**< NDN Interest */
    ICNL_NDN_TLV_DATA = 0x06        /**< NDN Data */
} icnl_ndn_tlv_t;
/** @} */

/**
 * @brief Encodes a NDN message
 *
 * @param[out]  out     output buffer to write the encoded message to
 * @param[in]   proto   ICN protocol @ref icnl_proto_t
 * @param[in]   in      input buffer that is to be encoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @return      Number of bytes written to @p out
 */
int icnl_ndn_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                    unsigned in_len);

/**
 * @brief Decodes an NDN message
 *
 * @param[out]  out     output buffer to write the decoded message to
 * @param[in]   proto   ICN protocol @ref icnl_proto_t
 * @param[in]   in      input buffer that is to be decoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @return      Number of bytes written to @p out
 */
int icnl_ndn_decode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                    unsigned in_len);

#endif /* NDNLOWPAN_H */
/** @} */
