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
#include "debug.h"

/**
 * @brief   Dispatch type for NDN Interest
 */
#define ICNL_DISPATCH_NDN_INT           (0x80)

/**
 * @brief   Dispatch type for NDN Data
 */
#define ICNL_DISPATCH_NDN_DATA          (0x90)

/**
 * @brief   Dispatch type for NDN Interest with header compression
 *          A octet follows.
 */
#define ICNL_DISPATCH_NDN_INT_HC_A      (0x88)

/**
 * @brief   Dispatch type for NDN Interest with header compression
 *          A and B octet follows.
 */
#define ICNL_DISPATCH_NDN_INT_HC_AB     (0x89)

/**
 * @brief   Dispatch type for NDN Data with header compression
 *          A octet follows.
 */
#define ICNL_DISPATCH_NDN_DATA_HC_A     (0x98)

/**
 * @brief   Dispatch type for NDN Data with header compression
 *          A and B octet follows.
 */
#define ICNL_DISPATCH_NDN_DATA_HC_AB    (0x99)

/**
 * @brief   NDN TLVs
 * @{
 */
typedef enum {
    ICNL_NDN_TLV_IMPLICIT_SHA256_DIGEST_COMPONENT = 0x01,   /**< NDN GenericNameComponent */
    ICNL_NDN_TLV_INTEREST                         = 0x05,   /**< NDN Interest */
    ICNL_NDN_TLV_DATA                             = 0x06,   /**< NDN Data */
    ICNL_NDN_TLV_NAME                             = 0x07,   /**< NDN Name */
    ICNL_NDN_TLV_GENERIC_NAME_COMPONENT           = 0x08,   /**< NDN GenericNameComponent */
    ICNL_NDN_TLV_SELECTORS                        = 0x09,   /**< NDN Selectors */
    ICNL_NDN_TLV_NONCE                            = 0x0A,   /**< NDN Nonce */
    ICNL_NDN_TLV_INTEREST_LIFETIME                = 0x0C,   /**< NDN InterestLifetime */
    ICNL_NDN_TLV_MUST_BE_FRESH                    = 0x12,   /**< NDN MustBeFresh Selector */
    ICNL_NDN_TLV_META_INFO                        = 0x14,   /**< NDN MetaInfo */
    ICNL_NDN_TLV_CONTENT                          = 0x15,   /**< NDN Content */
    ICNL_NDN_TLV_SIGNATURE_INFO                   = 0x16,   /**< NDN SignatureInfo */
    ICNL_NDN_TLV_SIGNATURE_VALUE                  = 0x17,   /**< NDN SignatureValue */
    ICNL_NDN_TLV_SIGNATURE_TYPE                   = 0x1b,   /**< NDN SignatureType */
} icnl_ndn_tlv_t;
/** @} */

/**
 * @brief Reads the Type or Length field of a TLV
 *
 * @param[in]       in      input buffer to read the Type or Length field from
 * @param[in,out]   pos_in  current position within the input buffer @p in
 *
 * @post            @p pos_in is forwarded to the position after the Type
 *                  or Length field
 *
 * @return          The Type or Length field
 */
icnl_tlv_off_t icnl_ndn_tlv_read(const uint8_t *in, icnl_tlv_off_t *pos_in);

/**
 * @brief Writes the Type or Length field of a TLV
 *
 * @param[in]       val     value to write to @p out at position @p pos_out
 * @param[out]      out     output buffer to write the Type or Length field to
 * @param[in,out]   pos_out current position within the output buffer @p out
 *
 * @post            @p pos_out is forwarded to the position after the Type
 *                  or Length field
 */
void icnl_ndn_tlv_write(icnl_tlv_off_t val, uint8_t *out, icnl_tlv_off_t *pos_out);

/**
 * @brief Reads the Type or Length field of a TLV (compressed version)
 *
 * @param[in]       in      input buffer to read the Type or Length field from
 * @param[in,out]   pos_in  current position within the input buffer @p in
 *
 * @post            @p pos_in is forwarded to the position after the Type
 *                  or Length field
 *
 * @return          The Type or Length field
 */
icnl_tlv_off_t icnl_ndn_tlv_hc_read(const uint8_t *in, icnl_tlv_off_t *pos_in);

/**
 * @brief Writes the Type or Length field of a TLV (compressed version)
 *
 * @param[in]       val     value to write to @p out at position @p pos_out
 * @param[out]      out     output buffer to write the Type or Length field to
 * @param[in,out]   pos_out current position within the output buffer @p out
 *
 * @post            @p pos_out is forwarded to the position after the Type
 *                  or Length field
 */
void icnl_ndn_tlv_hc_write(icnl_tlv_off_t val, uint8_t *out, icnl_tlv_off_t *pos_out);

/**
 * @brief   NDN Signature Types
 * @{
 */
typedef enum {
    ICNL_NDN_SIGNATURE_TYPE_DIGEST_SHA256   = 0x00,   /**< NDN SignatureType DigestSha256 */
} icnl_ndn_sigtype_t;
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
icnl_tlv_off_t icnl_ndn_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len);

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
icnl_tlv_off_t icnl_ndn_decode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len);

#endif /* NDNLOWPAN_H */
/** @} */
