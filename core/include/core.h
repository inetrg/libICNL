/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file        core.h
 * @brief       core module functions
 * @author      Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 * @copyright   GNU Lesser General Public License v2.1
 * @addtogroup  icnlowpan icnlowpan module
 * @{
 */
#ifndef CORE_H
#define CORE_H

#include <stdint.h>

/**
 * @brief Page 2
 */
#define ICNL_DISPATCH_PAGE (2)

/**
 * @brief Paging Switch dispatch
 * @see [RFC 8025](https://tools.ietf.org/html/rfc8025)
 *
 * @param[out]  out     output buffer to write the paging switch dispatch to
 * @param[in]   page    page to switch to
 */
static inline size_t icnl_page_switch_add(uint8_t *out, uint8_t page)
{
    *out = 0xF0 | (0x0F & page);
    return 1;
}

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
 * @pre         \f$ |out| > in\_len \f$
 *
 * @return      Number of bytes written to @p out
 */
size_t icnl_encode(uint8_t *out, icnl_proto_t proto, uint8_t *in,
                   size_t in_len);
 
#endif /* CORE_H */
/** @} */
