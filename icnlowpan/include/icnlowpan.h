/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        icnlowpan.h
 * @brief       icnlowpan module functions
 * @author      Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 * @copyright   GNU Lesser General Public License v2.1
 * @addtogroup  icnlowpan icnlowpan module
 * @{
 */
#ifndef ICNLOWPAN_H
#define ICNLOWPAN_H

#include <stdint.h>

/**
 * @brief Page 2
 */
#define ICNL_DISPATCH_PAGE (0xF2)

/**
 * @brief       ICN protocol identifier
 * @{
 */
typedef enum {
#ifdef MODULE_NDNLOWPAN
    ICNL_PROTO_NDN,      /**< protocol identifier for NDN */
#endif
#ifdef MODULE_CCNLOWPAN
    ICNL_PROTO_CCN       /**< protocol identifier for CCN */
#endif
} icnl_proto_t;
/** @} */

/**
 * @brief       Encodes a packet
 *
 * @param[out]  out     output buffer that will contain the encoded format
 * @param[in]   proto   ICN protocol @ref icnl_proto_t
 * @param[in]   in      input buffer that is to be encoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @return      Number of bytes written to @p out
 * @retval      -1 on error
 */
int icnl_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                unsigned in_len);

/**
 * @brief       Decodes a packet
 *
 * @param[out]  out     output buffer that will contain the decoded format
 * @param[in]   in      input buffer that is to be decoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @return      Number of bytes written to @p out
 * @retval      -1 on error
 */
int icnl_decode(uint8_t *out, const uint8_t *in, unsigned in_len);
 
#endif /* ICNLOWPAN_H */
/** @} */
