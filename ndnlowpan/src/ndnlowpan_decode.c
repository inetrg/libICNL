/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>

#include "ndnlowpan.h"

icnl_tlv_off_t icnl_ndn_decode_interest(uint8_t *out, const uint8_t *in,
                                        icnl_tlv_off_t in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

icnl_tlv_off_t icnl_ndn_decode_name(uint8_t *out, const uint8_t *in,
                                    icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, name_len;
    uint8_t out_total_name_len = 0;
    uint8_t *name_length;

    out[pos_out++] = ICNL_NDN_TLV_NAME;

    name_len = icnl_ndn_tlv_read(in, pos_in);
    name_length = out + (pos_out++);
    /* skip maximum amount of possible length field size */
    pos_out += 8;

    if ((*a & 0xC0) == 0) {
        memcpy(out + pos_out, in + *pos_in, name_len);
        *pos_in += name_len;
        pos_out += name_len;
    }
    else {
        uint8_t component_type = 0x00;

        if (*a & 0x40) {
            component_type = ICNL_NDN_TLV_GENERIC_NAME_COMPONENT;
        }
        else if (*a & 0x80) {
            component_type = ICNL_NDN_TLV_IMPLICIT_SHA256_DIGEST_COMPONENT;
        }

        icnl_tlv_off_t offset = *pos_in + name_len;
        while (*pos_in < offset) {
            out[pos_out++] = component_type;
            out_total_name_len += 1;
            uint8_t comp_len = in[*pos_in] + 1;
            memcpy(out + pos_out, in + *pos_in, comp_len);
            pos_out += comp_len;
            *pos_in += comp_len;
            out_total_name_len += comp_len;
        }
    }

    icnl_tlv_off_t tmp = 0;
    icnl_ndn_tlv_write(out_total_name_len, name_length, &tmp);
    memmove(name_length + tmp, name_length + 9, pos_out);
    pos_out -= 9 - tmp;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_nonce(uint8_t *out, const uint8_t *in,
                                     icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, nonce_len = 4;

    if ((*a & 0x30) == 0x10) {
        nonce_len = 1;
    }
    else if ((*a & 0x30) == 0x20) {
        nonce_len = 2;
    }

    out[pos_out++] = ICNL_NDN_TLV_NONCE;
    out[pos_out++] = 4;

    memset(out + pos_out, 0, 4);
    memcpy(out + pos_out + 4 - nonce_len, in + *pos_in, nonce_len);
    *pos_in += 4;
    pos_out += 4;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                                 icnl_tlv_off_t *pos_in,
                                                 const uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, length = 0;

    if ((*a & 0x0E) == 0x00) {
        return pos_out;
    }
    else {
        out[pos_out++] = ICNL_NDN_TLV_INTEREST_LIFETIME;
        if ((*a & 0x0E) == 0x02) {
            length = 1;
        }
        else if ((*a & 0x0E) == 0x04) {
            length = 2;
        }
        else if ((*a & 0x0E) == 0x06) {
            length = 4;
        }
        else if ((*a & 0x0E) == 0x08) {
            length = 8;
        }
        else if ((*a & 0x0E) == 0x0A) {
            out[pos_out++] = 2;
            /* default value of 4000 ms */
            out[pos_out++] = 0x0F;
            out[pos_out++] = 0xA0;
            return pos_out;
        }

        icnl_ndn_tlv_write(length, out, &pos_out);
        memcpy(out + pos_out, in + *pos_in, length);
        *pos_in += length;
        pos_out += length;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_meta_info(uint8_t *out, const uint8_t *in,
                                         icnl_tlv_off_t *pos_in, const uint8_t *b)
{
    icnl_tlv_off_t pos_out = 0;

    if (b == NULL) {
        out[pos_out++] = ICNL_NDN_TLV_META_INFO;
        out[pos_out++] = 0;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_content(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t *pos_in, const uint8_t *a)
{
    (void) a;
    icnl_tlv_off_t pos_out = 0, len;

    len = icnl_ndn_tlv_read(in, pos_in);

    out[pos_out++] = ICNL_NDN_TLV_CONTENT;
    icnl_ndn_tlv_write(len, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, len);
    pos_in += len;
    pos_out += len;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_interest_hc(uint8_t *out, const uint8_t *in,
                                           icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    const uint8_t *a;
    uint8_t *out_packet_length;

    a = in + pos_in++;

    out[pos_out++] = ICNL_NDN_TLV_INTEREST;
    out_packet_length = out + (pos_out++);
    /* skip maximum amount of possible length field size */
    pos_out += 8;

    /* skip packet length */
    pos_in++;

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_nonce(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_interest_lifetime(out + pos_out, in, &pos_in, a);

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    icnl_tlv_off_t tmp = 0;
    icnl_ndn_tlv_write(pos_out - 2 - 8, out_packet_length, &tmp);
    memmove(out_packet_length + tmp, out_packet_length + 9, pos_out);
    pos_out -= 9 - tmp;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_data_hc(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t in_len, uint8_t dispatch)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0;
    const uint8_t *a, *b = NULL;
    uint8_t *out_packet_length;

    a = in + pos_in++;
    if ((dispatch & 0x07) == 0x1) {
        b = in + pos_in++;
    }

    out[pos_out++] = ICNL_NDN_TLV_DATA;
    out_packet_length = out + (pos_out++);
    /* skip maximum amount of possible length field size */
    pos_out += 8;

    /* skip packet length */
    pos_in++;

    pos_out += icnl_ndn_decode_name(out + pos_out, in, &pos_in, a);
    pos_out += icnl_ndn_decode_meta_info(out + pos_out, in, &pos_in, b);
    pos_out += icnl_ndn_decode_content(out + pos_out, in, &pos_in, a);

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    icnl_tlv_off_t tmp = 0;
    icnl_ndn_tlv_write(pos_out - 2 - 8, out_packet_length, &tmp);
    memmove(out_packet_length + tmp, out_packet_length + 9, pos_out);
    pos_out -= 9 - tmp;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_decode_data(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

icnl_tlv_off_t icnl_ndn_decode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0, out_len = 0;
    uint8_t *dispatch = (uint8_t *) (in + pos++);

    if (proto == ICNL_PROTO_NDN) {
        if (*dispatch == ICNL_DISPATCH_NDN_INT) {
            out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
        }
        else if (*dispatch == ICNL_DISPATCH_NDN_DATA) {
            out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
        }
    }
    else if (proto == ICNL_PROTO_NDN_HC) {
        if (*dispatch == ICNL_DISPATCH_NDN_INT_HC_A) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos);
        }
        else if (*dispatch == ICNL_DISPATCH_NDN_DATA_HC_A) {
            out_len = icnl_ndn_decode_data_hc(out, in + pos, in_len - pos,
                                              *dispatch);
        }
    }

    return out_len;
}
