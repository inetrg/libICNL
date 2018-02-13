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

icnl_tlv_off_t icnl_ndn_encode_data(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_DATA;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

icnl_tlv_off_t icnl_ndn_encode_interest(uint8_t *out, const uint8_t *in, icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

    out[pos++] = ICNL_DISPATCH_NDN_INT;

    memcpy(out + pos, in, in_len);
    pos += in_len;

    return pos;
}

icnl_tlv_off_t icnl_ndn_encode_name(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                    uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, name_len, len, type;
    uint8_t *name_length;

    name_len = icnl_ndn_tlv_read(in, pos_in);
    name_length = out + (pos_out++);

    uint8_t comp_styles = 0;
    *a &= 0x3F;

    for (icnl_tlv_off_t i = *pos_in; i < (*pos_in) + name_len;) {
        type = icnl_ndn_tlv_read(in, &i);
        len = icnl_ndn_tlv_read(in, &i);

        if (type == ICNL_NDN_TLV_GENERIC_NAME_COMPONENT) {
            comp_styles |= 0x40;
        }
        else if (type == ICNL_NDN_TLV_IMPLICIT_SHA256_DIGEST_COMPONENT) {
            comp_styles |= 0x80;
        }
        i += len;
    }

    if (comp_styles == 0x00) {
        ICNL_DBG("error while encoding name: components: 0x%x\n", comp_styles);
        return 0;
    }
    else if (comp_styles == 0xC0) {
        memcpy(out + pos_out, in + *pos_in, name_len);
        *pos_in += name_len;
        pos_out += name_len;
    }
    else {
        *a |= comp_styles;

        icnl_tlv_off_t total_name_length = 0;
        icnl_tlv_off_t end_pos = (*pos_in) + name_len;
        do {
            /* skip component type */
            type = icnl_ndn_tlv_read(in, pos_in);

            icnl_tlv_off_t tmp = *pos_in;
            len = icnl_ndn_tlv_read(in, pos_in);
            /* component length including length field */
            len += ((*pos_in) - tmp);
            /* rewind position to length field */
            *pos_in = tmp;

            total_name_length += len;

            memcpy(out + pos_out, in + *pos_in, len);
            pos_out += len;
            (*pos_in) += len;
        }
        while (*pos_in < end_pos);
        *name_length = total_name_length;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_nonce(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                     uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0;

    *a &= 0xCF;

    /* skip nonce length */
    icnl_ndn_tlv_read(in, pos_in);

    memcpy(out + pos_out, in + *pos_in, 4);
    pos_out += 4;
    *pos_in += 4;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_selectors(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                         uint8_t *b)
{
    (void) out;

    icnl_tlv_off_t pos_out = 0, res = 0;

    *b &= 0x01;

    icnl_tlv_off_t sel_len = icnl_ndn_tlv_read(in, pos_in) + *pos_in;

    while (*pos_in < sel_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, pos_in);

        switch (type) {
            case ICNL_NDN_TLV_MUST_BE_FRESH:
                res = 0;
                /* skip MustBeFresh TLV length */
                icnl_ndn_tlv_read(in, pos_in);
                *b |= 0x02;
                break;
            default:
                ICNL_DBG("error while encoding unknown Interest Selector TLV\n");
                return 0;
        }

        pos_out += res;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_meta_info(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                         uint8_t *b)
{
    icnl_tlv_off_t pos_out = 0, res = 0, length;

    icnl_tlv_off_t meta_len = icnl_ndn_tlv_read(in, pos_in) + *pos_in;

    while (*pos_in < meta_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, pos_in);

        switch (type) {
            case ICNL_NDN_TLV_FRESHNESS_PERIOD:
                res = 0;
                length = icnl_ndn_tlv_read(in, pos_in);
                if (length == 1) {
                    *b |= 0x10;
                }
                else if (length == 2) {
                    *b |= 0x20;
                }
                else if (length == 4) {
                    *b |= 0x30;
                }
                else if (length == 8) {
                    *b |= 0x40;
                }

                memcpy(out + pos_out, in + *pos_in, length);
                *pos_in += length;
                pos_out += length;

                break;
            default:
                ICNL_DBG("error while encoding unknown Data MetaInfo TLV\n");
                return 0;
        }

        pos_out += res;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_content(uint8_t *out, const uint8_t *in, icnl_tlv_off_t *pos_in,
                                       uint8_t *a)
{
    (void) a;

    icnl_tlv_off_t pos_out = 0;
    icnl_tlv_off_t length = icnl_ndn_tlv_read(in, pos_in);

    icnl_ndn_tlv_hc_write(length, out, &pos_out);

    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_signature_info(uint8_t *out, const uint8_t *in,
                                              icnl_tlv_off_t *pos_in, uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, signaturetype, tmp, offset = *pos_in, type;
    icnl_tlv_off_t value_length = icnl_ndn_tlv_read(in, &offset);
    icnl_tlv_off_t length = value_length + (offset - (*pos_in));

    *a &= 0xC7;

    /* check signaturetype type */
    type = icnl_ndn_tlv_read(in, &offset);

    if (type != ICNL_NDN_TLV_SIGNATURE_TYPE) {
        ICNL_DBG("error while encoding signature info: exptected 0x%x\n",
                 ICNL_NDN_TLV_SIGNATURE_TYPE);
        return 0;
    }

    tmp = offset;

    /* skip signaturetype length */
    icnl_ndn_tlv_read(in, &tmp);

    icnl_tlv_off_t sigtype_typelen = tmp;
    signaturetype = icnl_ndn_tlv_read(in, &tmp);
    sigtype_typelen = tmp - sigtype_typelen;

    if ((signaturetype == ICNL_NDN_SIGNATURE_TYPE_DIGEST_SHA256) && (value_length == 3)) {
        *a |= 0x08;
        *pos_in += length;
        return pos_out;
    }
    else {
        /* sig info length minus sigtype type */
        icnl_tlv_off_t tmp = icnl_ndn_tlv_read(in, pos_in) - sigtype_typelen;
        icnl_ndn_tlv_hc_write(tmp, out, &pos_out);
        /* skip sigtype type */
        icnl_ndn_tlv_read(in, pos_in);
        memcpy(out + pos_out, in + *pos_in, tmp);
        pos_out += tmp;
        *pos_in += tmp;
    }

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_signature_value(uint8_t *out, const uint8_t *in,
                                               icnl_tlv_off_t *pos_in, uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0, tmp = *pos_in;
    icnl_tlv_off_t length = icnl_ndn_tlv_read(in, pos_in) + ((*pos_in) - tmp);
    *pos_in = tmp;

    if ((*a & 0x38) == 0x08) {
        length = icnl_ndn_tlv_read(in, pos_in);
    }
    memcpy(out + pos_out, in + *pos_in, length);
    pos_out += length;
    *pos_in += length;

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_interest_lifetime(uint8_t *out, const uint8_t *in,
                                                 icnl_tlv_off_t *pos_in, uint8_t *a)
{
    icnl_tlv_off_t pos_out = 0;
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

icnl_tlv_off_t icnl_ndn_encode_interest_hc(uint8_t *out, const uint8_t *in,
                                           icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0, res = 0;
    uint8_t *disp, *a, *out_packet_length;
    uint8_t b = 0x00;

    disp = out + (pos_out++);

    a = out + (pos_out++);
    *a = 0x00;

    /* skip packet type */
    icnl_ndn_tlv_read(in, &pos_in);

    /* remember position of packet length */
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_read(in, &pos_in);

    while (pos_in < in_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, &pos_in);

        switch (type) {
            case ICNL_NDN_TLV_NAME:
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_SELECTORS:
                res = icnl_ndn_encode_selectors(out + pos_out, in, &pos_in, &b);
                break;
            case ICNL_NDN_TLV_NONCE:
                res = icnl_ndn_encode_nonce(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_INTEREST_LIFETIME:
                res = icnl_ndn_encode_interest_lifetime(out + pos_out, in, &pos_in, a);
                break;
            default:
                ICNL_DBG("error while encoding unknown Interest TLV\n");
                return 0;
        }

        pos_out += res;
    }


    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_hc_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    uint8_t *b_ptr = NULL;

    if (b) {
        *disp = ICNL_DISPATCH_NDN_INT_HC_AB;
        skip++;
        b_ptr = a + 1;
        out_packet_length = (b_ptr + 1);
    }
    else {
        *disp = ICNL_DISPATCH_NDN_INT_HC_A;
    }

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    if (b_ptr) {
        *b_ptr = b;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode_data_hc(uint8_t *out, const uint8_t *in,
                                       icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos_out = 0, pos_in = 0, res = 0;
    uint8_t *disp, *a, *out_packet_length;
    uint8_t b = 0x00;

    disp = out + (pos_out++);

    a = out + (pos_out++);
    *a = 0x00;

    /* skip packet type */
    icnl_ndn_tlv_read(in, &pos_in);

    /* remember position of packet length */
    out_packet_length = out + (pos_out++);

    /* skip packet length */
    icnl_ndn_tlv_read(in, &pos_in);

    while (pos_in < in_len) {
        icnl_tlv_off_t type = icnl_ndn_tlv_read(in, &pos_in);

        switch (type) {
            case ICNL_NDN_TLV_NAME:
                res = icnl_ndn_encode_name(out + pos_out, in, &pos_in, a);
                break;
            case ICNL_NDN_TLV_META_INFO:
                res = icnl_ndn_encode_meta_info(out + pos_out, in, &pos_in, &b);
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
                ICNL_DBG("error while encoding unknown Data TLV\n");
                return 0;
        }

        pos_out += res;
    }

    uint8_t tmp[9];
    icnl_tlv_off_t tmp_len = 0;
    icnl_tlv_off_t ll = pos_out - (out_packet_length - out);
    icnl_ndn_tlv_hc_write(ll - 1, tmp, &tmp_len);

    icnl_tlv_off_t skip = tmp_len - 1;

    uint8_t *b_ptr = NULL;

    if (b) {
        *disp = ICNL_DISPATCH_NDN_DATA_HC_AB;
        skip++;
        b_ptr = a + 1;
        out_packet_length = (b_ptr + 1);
    }
    else {
        *disp = ICNL_DISPATCH_NDN_DATA_HC_A;
    }

    if (skip) {
        memmove(out_packet_length + skip, out_packet_length, ll);
        pos_out += skip;
    }

    if (b_ptr) {
        *b_ptr = b;
    }

    memcpy(out_packet_length, tmp, tmp_len);

    return pos_out;
}

icnl_tlv_off_t icnl_ndn_encode(uint8_t *out, icnl_proto_t proto, const uint8_t *in,
                               icnl_tlv_off_t in_len)
{
    icnl_tlv_off_t pos = 0;

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
