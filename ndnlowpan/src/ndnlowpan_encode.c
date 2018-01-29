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

int icnl_ndn_encode_meta_info(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                              uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned length = in[(*pos_in)++];

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

int icnl_ndn_encode_content(uint8_t *out, const uint8_t *in, unsigned *pos_in,
                            uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned length = in[(*pos_in)] + 1;

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

int icnl_ndn_encode_signature_info(uint8_t *out, const uint8_t *in,
                                   unsigned *pos_in, uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned signaturetype;
    unsigned value_length = in[*pos_in];
    unsigned length = value_length + 1;
    unsigned offset = (*pos_in) + 1;
    unsigned type;

    *a &= 0xC7;

    /* check signaturetype type */
    type = in[offset++];
    if (type != ICNL_NDN_TLV_SIGNATURE_TYPE) {
        ICNL_DBG("error while encoding signature info: exptected 0x%x, got 0x%x\n",
                 ICNL_NDN_TLV_SIGNATURE_TYPE, type);
        return -1;
    }

    signaturetype = in[offset + 1];

    if ((signaturetype == ICNL_NDN_SIGNATURE_TYPE_DIGEST_SHA256) && (value_length == 3)) {
        *a |= 0x08;
        *pos_in += length;
        return pos_out;
    }
    else {
        /* sig info length minus sigtype type */
        unsigned tmp = in[(*pos_in)++] - 1;
        out[pos_out++] = tmp;
        /* skip sigtype type */
        (*pos_in)++;
        memcpy(out + pos_out, in + *pos_in, tmp);
        pos_out += tmp;
        *pos_in += tmp;
    }

    return pos_out;
}

int icnl_ndn_encode_signature_value(uint8_t *out, const uint8_t *in,
                                    unsigned *pos_in, uint8_t *a)
{
    unsigned pos_out = 0;
    unsigned length = in[(*pos_in)] + 1;

    if ((*a & 0x38) == 0x08) {
        length = in[(*pos_in)++];
    }
    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

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
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_NONCE:
                res = icnl_ndn_encode_nonce(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_INTEREST_LIFETIME:
                res = icnl_ndn_encode_interest_lifetime(out + pos_out, in, &pos_in, a);
                break;
            default:
                ICNL_DBG("error while encoding unknown Interest TLV with type 0x%x\n", type);
                return -1;
        }

        if (res < 0) {
            return res;
        }

        pos_out += res;
    }

    *out_packet_length = pos_out - 3;

    return pos_out;
}

int icnl_ndn_encode_data_hc(uint8_t *out, const uint8_t *in, unsigned in_len)
{
    unsigned pos_out = 0;
    unsigned pos_in = 0;
    uint8_t *a;
    uint8_t *out_packet_length;
    unsigned type;
    int res = 0;

    out[pos_out++] = ICNL_DISPATCH_NDN_DATA_HC_A;

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
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_META_INFO:
                res = icnl_ndn_encode_meta_info(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_CONTENT:
                res = icnl_ndn_encode_content(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_SIGNATURE_INFO:
                res = icnl_ndn_encode_signature_info(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_SIGNATURE_VALUE:
                res = icnl_ndn_encode_signature_value(out + pos_out, in, &pos_in, a);
                break;
            default:
                ICNL_DBG("error while encoding unknown Data TLV with type 0x%x\n", type);
                return -1;
        }

        if (res < 0) {
            return res;
        }

        pos_out += res;
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
            pos += icnl_ndn_encode_data_hc(out, in, in_len);
        }
    }

    return pos;
}
