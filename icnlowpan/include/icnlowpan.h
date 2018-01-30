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

#ifndef ICNL_OPT_OFFSET
/**
 * @brief Size of the TLV offset type @p icnl_tlv_off_t
 */
#define ICNL_OPT_OFFSET     (64)
#endif

/**
 * @brief Size of the offset type
 */
#if ICNL_OPT_OFFSET == 64
typedef uint64_t icnl_tlv_off_t;
#elif ICNL_OPT_OFFSET == 32
typedef uint32_t icnl_tlv_off_t;
#endif

/**
 * @brief       ICN protocol identifier
 * @{
 */
typedef enum {
#ifdef MODULE_NDNLOWPAN
    ICNL_PROTO_NDN,      /**< protocol identifier for NDN */
    ICNL_PROTO_NDN_HC,   /**< protocol identifier for NDN */
#endif
#ifdef MODULE_CCNLOWPAN
    ICNL_PROTO_CCN       /**< protocol identifier for CCN */
    ICNL_PROTO_CCN_HC    /**< protocol identifier for CCN */
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
 * @retval      0 on error
 */
icnl_tlv_off_t icnl_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                           icnl_tlv_off_t in_len);

/**
 * @brief       Decodes a packet
 *
 * @param[out]  out     output buffer that will contain the decoded format
 * @param[in]   in      input buffer that is to be decoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @return      Number of bytes written to @p out
 * @retval      0 on error
 */
icnl_tlv_off_t icnl_decode(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len);
 
#endif /* ICNLOWPAN_H */
/** @} */
