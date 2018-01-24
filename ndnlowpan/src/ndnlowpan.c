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

int icnl_ndn_encode_name(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                         uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned name_len = 0;
    uint8_t *name_length;

    if (in[*pos_in] != ICNL_NDN_TLV_NAME) {
        ICNL_DBG("error while encoding name: expected 0x%x, got 0x%x\n",
                 ICNL_NDN_TLV_NAME, in[*pos_in]);
        return -1;
    }

    /* skip name type */
    (*pos_in)++;

    name_len = in[(*pos_in)++];
    name_length = out + (pos_out++);

    uint8_t comp_styles = 0;
    *a &= 0x3F;

    for (unsigned i = 0; i < name_len;) {
        if (in[*pos_in + i] == ICNL_NDN_TLV_GENERIC_NAME_COMPONENT) {
            comp_styles |= 0x40;
        }
        else if (in[*pos_in + i] == ICNL_NDN_TLV_IMPLICIT_SHA256_DIGEST_COMPONENT) {
            comp_styles |= 0x80;
        }
        i += in[*pos_in + i + 1] + 2;
    }

    if (comp_styles == 0x00) {
        ICNL_DBG("error while encoding name: components: 0x%x\n", comp_styles);
        return -1;
    }
    else if (comp_styles == 0xC0) {
        memcpy(out + pos_out, in + *pos_in, name_len);
        *pos_in += name_len;
        pos_out += name_len;
    }
    else {
        *a |= comp_styles;

        uint8_t total_name_length = 0;
        for (unsigned i = 0; i < name_len;) {
            /* skip component type */
            (*pos_in)++;
            i++;

            /* component length including length field */
            uint8_t comp_len = in[*pos_in] + 1;
            total_name_length += comp_len;
            memcpy(out + pos_out, in + *pos_in, comp_len);
            pos_out += comp_len;
            (*pos_in) += comp_len;
            i += comp_len;
        }
        *name_length = total_name_length;
    }

    return pos_out;
}

int icnl_ndn_encode_interest_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos_out = 0;
    unsigned pos_in = 0;
    uint8_t *a;
    int res = 0;

    out[pos_out++] = ICNL_DISPATCH_NDN_INT_HC_A;

    a = out + pos_out;
    out[pos_out++] = 0x00;

    /* skip packet type */
    pos_in++;

    out[pos_out++] = in[pos_in++];

    if ((res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a)) < 0) {
        return res;
    }
    pos_out += res;

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
