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

int icnl_ndn_encode_nonce(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                          uint8_t *a)
{
    unsigned pos_out = 0;

    *a &= 0xCF;

    /* skip nonce length */
    (*pos_in)++;

    memcpy(out + pos_out, in + *pos_in, 4);
    pos_out += 4;
    *pos_in += 4;

    return pos_out;
}

int icnl_ndn_encode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                      unsigned *pos_in, uint8_t *a)
{
    unsigned pos_out = 0;
    const uint8_t *length;

    *a &= 0xF1;

    length = in + (*pos_in)++;

    if (*length == 1) {
        *a |= 0x02;
    }
    else if (*length == 2) {
        uint8_t *val = (uint8_t *) (in + *pos_in);
        if ((val[0] == 0x0F) && (val[1] == 0xA0)) {
            *a |= 0x0A;
            *pos_in += *length;
            return pos_out;
        }
        else {
            *a |= 0x04;
        }
    }
    else if (*length == 4) {
        *a |= 0x06;
    }
    else if (*length == 8) {
        *a |= 0x08;
    }

    memcpy(out + pos_out, in + *pos_in, *length);
    pos_out += *length;
    *pos_in += *length;

    return pos_out;
}

int icnl_ndn_encode_interest_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos_out = 0;
    unsigned pos_in = 0;
    uint8_t *a;
    uint8_t *out_packet_length;
    unsigned type;
    int res = 0;

    out[pos_out++] = ICNL_DISPATCH_NDN_INT_HC_A;

    a = out + (pos_out++);
    *a = 0x00;

    /* skip packet type */
    pos_in++;

    /* remember position of packet length */
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    pos_in++;

    while (pos_in < in_len) {
        unsigned type = in[pos_in++];

        switch (type) {
            case ICNL_NDN_TLV_NAME:
                if ((res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a)) < 0) {
                    return res;
                }
                pos_out += res;
                break;
            case ICNL_NDN_TLV_NONCE:
                if ((res = icnl_ndn_encode_nonce(out + pos_out, in, &pos_in, a)) < 0) {
                    return res;
                }
                pos_out += res;
                break;
            case ICNL_NDN_TLV_INTEREST_LIFETIME:
                if ((res = icnl_ndn_encode_interest_lifetime(out + pos_out, in, &pos_in, a)) < 0) {
                    return res;
                }
                pos_out += res;
                break;
            default:
                ICNL_DBG("error while encoding unknown TLV with type 0x%x\n", type);
                return -1;
        }
    }

    *out_packet_length = pos_out - 3;

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

int icnl_ndn_decode_name(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                         const uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned name_len = 0;
    uint8_t out_total_name_len = 0;
    uint8_t *name_length;

    out[pos_out++] = ICNL_NDN_TLV_NAME;

    name_len = in[(*pos_in)++];
    name_length = out + (pos_out++);

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

        unsigned offset = *pos_in + name_len;
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

    *name_length = out_total_name_len;

    return pos_out;
}

int icnl_ndn_decode_nonce(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                          const uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned nonce_len = 4;

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

int icnl_ndn_decode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                      unsigned *pos_in, const uint8_t *a)
{
    unsigned pos_out = 0;
    uint8_t length = 0;

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

        out[pos_out++] = length;
        memcpy(out + pos_out, in + *pos_in, length);
        *pos_in += length;
        pos_out += length;
    }

    return pos_out;
}

int icnl_ndn_decode_interest_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos_out = 0;
    unsigned pos_in = 0;
    const uint8_t *a;
    uint8_t *out_packet_length;
    int res = 0;

    a = in + pos_in++;

    out[pos_out++] = ICNL_NDN_TLV_INTEREST;
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    pos_in++;

    if ((res = icnl_ndn_decode_name(out + pos_out, in, &pos_in, a)) < 0) {
        return res;
    }
    pos_out += res;

    if ((res = icnl_ndn_decode_nonce(out + pos_out, in, &pos_in, a)) < 0) {
        return res;
    }
    pos_out += res;

    if ((res = icnl_ndn_decode_interest_lifetime(out + pos_out, in, &pos_in, a)) < 0) {
        return res;
    }
    pos_out += res;

    memcpy(out + pos_out, in + pos_in, in_len - pos_in);
    pos_out += in_len - pos_in;

    *out_packet_length = pos_out - 2;

    return pos_out;
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
        if (*dispatch == ICNL_DISPATCH_NDN_INT_HC_A) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos);
        }
        else if (*dispatch == ICNL_DISPATCH_NDN_DATA_HC_A) {
            out_len = icnl_ndn_decode_interest_hc(out, in + pos, in_len - pos);
        }
    }

    return out_len;
}
