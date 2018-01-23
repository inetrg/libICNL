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

int icnl_ndn_encode_data(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_DATA;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

int icnl_ndn_encode_interest(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_INT;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

int icnl_ndn_encode_interest_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos_out = 0;
    unsigned pos_in = 0;

    out[pos_out++] = ICNL_DISPATCH_NDN_INT_HC_A;
    out[pos_out++] = 0x00;

    /* ignore packet type */
    pos_in++;

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    return pos_out;
}

int icnl_ndn_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                    unsigned in_len)
{
    unsigned pos = 0;

    if (proto == ICNL_PROTO_NDN) {
        if (in[0] == 0x05) {
            pos += icnl_ndn_encode_interest(out, in, in_len);
        }
        else if (in[0] == 0x06) {
            pos += icnl_ndn_encode_data(out, in, in_len);
        }
    }
    else if (proto == ICNL_PROTO_NDN_HC) {
        if (in[0] == 0x05) {
            pos += icnl_ndn_encode_interest_hc(out, in, in_len);
        }
        else if (in[0] == 0x06) {
            pos += icnl_ndn_encode_data(out, in, in_len);
        }
    }

    return pos;
}

int icnl_ndn_decode_interest(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

int icnl_ndn_decode_interest_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

int icnl_ndn_decode_data(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    memcpy(out, in, in_len);

    return in_len;
}

int icnl_ndn_decode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                    unsigned in_len)
{
    unsigned pos = 0;
    unsigned out_len = 0;
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
        if (*dispatch == ICNL_DISPATCH_NDN_INT) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos);
        }
        else if (*dispatch == ICNL_DISPATCH_NDN_DATA) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos);
        }
    }

    return out_len;
}

int icnl_ndn_decode_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos = 0;
    unsigned out_len = 0;
    uint8_t *dispatch = (uint8_t *) (in + pos++);

    if (*dispatch == ICNL_DISPATCH_NDN_INT) {
        out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
    }
    else if (*dispatch == ICNL_DISPATCH_NDN_DATA) {
        out_len = icnl_ndn_decode_interest(out, in + pos, in_len - pos);
    }

    return out_len;
}
