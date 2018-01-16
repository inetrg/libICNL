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

/**
 * @brief   Dispatch type for NDN Interest
 */
#define ICNL_DISPATCH_NDN_INT   (0x80)

/**
 * @brief   Dispatch type for NDN Data
 */
#define ICNL_DISPATCH_NDN_DATA  (0x90)

/**
 * @brief   NDN message types
 * @{
 */
typedef enum {
    ICNL_NDN_MSGT_INTEREST, /**< NDN Interest */
    ICNL_NDN_MSGT_DATA      /**< NDN Data */
} icnl_ndn_msg_type_t;
/** @} */

/**
 * @brief Adds a dispatch type for NDN Interest
 *
 * @param[out]  out     output buffer to write the dispatch to
 */
static inline size_t icnl_ndn_dispatch_add_interest(uint8_t *out)
{
    *out = ICNL_DISPATCH_NDN_INT;
    return 1;
}

/**
 * @brief Adds a dispatch type for NDN Data
 *
 * @param[out]  out     output buffer to write the dispatch to
 */
static inline size_t icnl_ndn_dispatch_add_data(uint8_t *out)
{
    *out = ICNL_DISPATCH_NDN_DATA;
    return 1;
}

/**
 * @brief Encodes a NDN message
 *
 * @param[out]  out     output buffer to write the encoded message to
 * @param[in]   in      input buffer that is to be encoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @pre         \f$ |out| > in\_len \f$
 *
 * @return      Number of bytes written to @p out
 */
size_t icnl_ndn_encode(uint8_t *out, uint8_t *in, size_t in_len);

/**
 * @brief Encodes an NDN Interest message
 *
 * @param[out]  out     output buffer to write the encoded Interest to
 * @param[in]   in      input buffer that is to be encoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @pre         \f$ |out| > in\_len \f$
 *
 * @return      Number of bytes written to @p out
 */
size_t icnl_ndn_encode_interest(uint8_t *out, uint8_t *in, size_t in_len);

/**
 * @brief Encodes an NDN Data message
 *
 * @param[out]  out     output buffer to write the encoded Data to
 * @param[in]   in      input buffer that is to be encoded
 * @param[in]   in_len  length of the input buffer @p in
 *
 * @pre         \f$ |out| > in\_len \f$
 *
 * @return      Number of bytes written to @p out
 */
size_t icnl_ndn_encode_data(uint8_t *out, uint8_t *in, size_t in_len);

#endif /* NDNLOWPAN_H */
/** @} */
