#include "yeelight_dimmer.h"

#include "bt_hci_common.h"
#include "esp_gap_ble_api.h"
#include "mbedtls/ccm.h"

#include <string.h>

#define DECRYPT_KEY_PADDING ("\x8D\x3D\x3C\x97")

static uint8_t prev_packet_id = 0;

// ccm_auth_crypt is copypasted from mbedtls/ccm.c - it's not exported
#define CCM_ENCRYPT 0
#define CCM_DECRYPT 1
static int ccm_auth_crypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                           const unsigned char *iv, size_t iv_len,
                           const unsigned char *add, size_t add_len,
                           const unsigned char *input, unsigned char *output,
                           unsigned char *tag, size_t tag_len);


void yeelight_dimmers_init(yeelight_dimmers_ctx *ctx) {
    memset(ctx, 0, sizeof(yeelight_dimmers_ctx));
    ctx->dimmers = NULL;
}

void yeelight_dimmers_add(yeelight_dimmers_ctx *ctx, char *mac, char *beacon_key, void *userdata) {
    yeelight_dimmer_t *dimmer = (yeelight_dimmer_t *)malloc(sizeof(yeelight_dimmer_t));

    // add new allocated dimmer to the list
    if (ctx->dimmers != NULL) {
        yeelight_dimmer_t *node = ctx->dimmers;
        while (node->next != NULL) {
            node = node->next;
        }
        node->next = dimmer;
    } else {
        ctx->dimmers = dimmer;
    }

    dimmer->next = NULL;
    for (int i = 0; i < 6; i++)
        dimmer->reversed_mac[i] = mac[6 - i - 1];

    // pad beacon_key with DECRYPT_KEY_PADDING to get the 16 byte AES key
    memcpy(dimmer->decrypt_key, beacon_key, 6);
    memcpy(dimmer->decrypt_key + 6, DECRYPT_KEY_PADDING, 4);
    memcpy(dimmer->decrypt_key + 10, beacon_key + 6, 6);

    dimmer->userdata = userdata;
}

void yeelight_dimmers_destroy(yeelight_dimmers_ctx *ctx) {
    yeelight_dimmer_t *dimmer = ctx->dimmers;

    if (dimmer == NULL)
        return;

    yeelight_dimmer_t *prev = dimmer;
    do {
        dimmer = dimmer->next;
        free(prev);
        prev = dimmer;
    } while (dimmer != NULL);

    ctx->dimmers = NULL;
}
void yellight_dimmer_check(yeelight_dimmers_ctx *ctx, uint8_t *data, uint32_t len) {
    uint8_t hci_event_type, hci_event_opcode, hci_subevent, hci_subevent_type;
    uint8_t hci_num_reports, offset, peer_address_type, adv_data_len;
    uint8_t *address = NULL;
    uint8_t *adv_data;
    // uint8_t hci_parameter_total_len, rssi;

    if (ctx->dimmers == NULL)
        return;

    offset = 0;
    hci_event_type = data[offset++];
    if (hci_event_type != H4_TYPE_EVENT)
        return;

    hci_event_opcode = data[offset++];
    if (hci_event_opcode != LE_META_EVENTS)
        return;

    // commented out to suppress 'set but not used' warning
    // hci_parameter_total_len = data[offset++];
    // rssi = data[len - 1];
    offset++;

    hci_subevent = data[offset++];
    if (hci_subevent != HCI_LE_ADV_REPORT)
        return;

    hci_num_reports = data[offset++];
    for (int i = 0; i < hci_num_reports; i++) {
        hci_subevent_type = data[offset++];
        peer_address_type = data[offset++];

        // Public Device Address or Random Device Address
        if ((peer_address_type == 0x00) || (peer_address_type == 0x01)) {
            address = data + offset;
            offset += 6;
        } else {
            // UNKNOWN ADDRESS TYPE, assume it is 6 bytes and skip
            address = data + offset;
            offset += 6;
            // skip adv data
            adv_data_len = data[offset++];
            offset += adv_data_len;
            continue;
        }

        adv_data_len = data[offset++];
        if (hci_subevent_type != ESP_BLE_EVT_NON_CONN_ADV) {
            offset += adv_data_len;
            continue;
        }

        adv_data = data + offset;
        offset += adv_data_len;

        yeelight_dimmer_t *dimmer = ctx->dimmers;
        do {
            if (!memcmp(dimmer->reversed_mac, address, 6)) {
                // found the matching dimmer
                yeelight_dimmer_handle_advdata(ctx, dimmer, adv_data + 1, adv_data_len - 1);
                break;
            }
            dimmer = dimmer->next;
        } while (dimmer != NULL);
    }
}

void yeelight_dimmer_handle_advdata(yeelight_dimmers_ctx *ctx, yeelight_dimmer_t *dimmer, uint8_t *data, uint32_t len) {
    mbedtls_ccm_context mtctx;

    uint8_t *mac_reversed;
    uint8_t *frame_ctl_data;
    uint8_t *device_type;
    uint8_t *encrypted_payload;
    uint8_t *encrypted_payload_counter;
    uint8_t *packet_id;

    uint8_t nonce[13];
    uint8_t decrypted_payload[6];

    mac_reversed = data + 8;
    frame_ctl_data = data + 3;
    device_type = data + 5;
    encrypted_payload = data + 14;
    encrypted_payload_counter = encrypted_payload + 6;
    packet_id = data + 7;

    if (*packet_id == prev_packet_id) // already handled
        return;
    prev_packet_id = *packet_id;

    uint8_t offset = 0;
    memcpy(nonce + offset, frame_ctl_data, 2);
    offset += 2;
    memcpy(nonce + offset, device_type, 2);
    offset += 2;
    memcpy(nonce + offset, packet_id, 1);
    offset += 1;
    memcpy(nonce + offset, encrypted_payload_counter, 3);
    offset += 3;
    memcpy(nonce + offset, mac_reversed, 5);
    offset += 5;

    mbedtls_ccm_init( &mtctx );
    if (mbedtls_ccm_setkey( &mtctx, MBEDTLS_CIPHER_ID_AES, dimmer->decrypt_key, 128) != 0) {
        // CCM: setup failed
        return;
    }

    uint8_t add[1] = { 0x11 };
    int res;
    res = ccm_auth_crypt(&mtctx, CCM_DECRYPT, 1,
                         nonce, 13,
                         NULL, 0,
                         add, add,
                         NULL, 0);
    if (res != 0)
        return;

    res = ccm_auth_crypt(&mtctx, CCM_DECRYPT, 6,
                         nonce, 13,
                         NULL, 0,
                         encrypted_payload, decrypted_payload,
                         NULL, 0);
    if (res != 0)
        return;

    mbedtls_ccm_free(&mtctx);

    // parse decrypted payload
    yeelight_report_t *report = (yeelight_report_t *)decrypted_payload;
    if (report->type != 0x1001) // unknown packet type
        return;
    if (report->length != 3) // never seen such packet, don't know how to parse it
        return;

    if (report->state == 4) {
        if (ctx->onRotate == NULL)
            return;

        if (report->value1 == 0)
            return ctx->onRotate(dimmer, report->value2, 0);
        if (report->value2 == 0)
            return ctx->onRotate(dimmer, report->value1, 1);

        if ((report->value1 != 0) && (report->value2 != 0)) {
            // this happens but doesn't make sense to me
            return;
        }
    } else if (report->state == 3) {
        if (report->value1 == 0) {
            if (report->value2 == 1) {
                if (ctx->onClick != NULL) {
                    ctx->onClick(dimmer);
                }
            } else if (report->value2 == 2) {
                if (ctx->onDoubleClick != NULL) {
                    ctx->onDoubleClick(dimmer);
                }
            } else {
                if (ctx->onMultipleClicks != NULL) {
                    ctx->onMultipleClicks(dimmer, report->value2);
                }
            }
        } else {
            if (ctx->onLongPress != NULL)
                ctx->onLongPress(dimmer, report->value2);
        }

    } else {
        // never seen it
    }
}

/*
 * Next code is taken from mbedtls ccm.c because it's not exported :(
 */

#define UPDATE_CBC_MAC                                                      \
    for( i = 0; i < 16; i++ )                                               \
        y[i] ^= b[i];                                                       \
                                                                            \
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, y, 16, y, &olen ) ) != 0 ) \
        return( ret );

/*
 * Encrypt or decrypt a partial block with CTR
 * Warning: using b for temporary storage! src and dst must not be b!
 * This avoids allocating one more 16 bytes buffer while allowing src == dst.
 */
#define CTR_CRYPT( dst, src, len  )                                            \
    do                                                                  \
    {                                                                   \
        if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, ctr,       \
                                           16, b, &olen ) ) != 0 )      \
        {                                                               \
            return( ret );                                              \
        }                                                               \
                                                                        \
        for( i = 0; i < (len); i++ )                                    \
            (dst)[i] = (src)[i] ^ b[i];                                 \
    } while( 0 )

/*
 * Authenticated encryption or decryption
 */
static int ccm_auth_crypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                           const unsigned char *iv, size_t iv_len,
                           const unsigned char *add, size_t add_len,
                           const unsigned char *input, unsigned char *output,
                           unsigned char *tag, size_t tag_len )
{
    int ret;
    unsigned char i;
    unsigned char q;
    size_t len_left, olen;
    unsigned char b[16];
    unsigned char y[16];
    unsigned char ctr[16];
    const unsigned char *src;
    unsigned char *dst;

    /*
     * Check length requirements: SP800-38C A.1
     * Additional requirement: a < 2^16 - 2^8 to simplify the code.
     * 'length' checked later (when writing it to the first block)
     *
     * Also, loosen the requirements to enable support for CCM* (IEEE 802.15.4).
     */
    if( tag_len == 2 || tag_len > 16 || tag_len % 2 != 0 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    /* Also implies q is within bounds */
    if( iv_len < 7 || iv_len > 13 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if( add_len > 0xFF00 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    q = 16 - 1 - (unsigned char) iv_len;

    /*
     * First block B_0:
     * 0        .. 0        flags
     * 1        .. iv_len   nonce (aka iv)
     * iv_len+1 .. 15       length
     *
     * With flags as (bits):
     * 7        0
     * 6        add present?
     * 5 .. 3   (t - 2) / 2
     * 2 .. 0   q - 1
     */
    b[0] = 0;
    b[0] |= ( add_len > 0 ) << 6;
    b[0] |= ( ( tag_len - 2 ) / 2 ) << 3;
    b[0] |= q - 1;

    memcpy( b + 1, iv, iv_len );

    for( i = 0, len_left = length; i < q; i++, len_left >>= 8 )
        b[15-i] = (unsigned char)( len_left & 0xFF );

    if( len_left > 0 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );


    /* Start CBC-MAC with first block */
    memset( y, 0, 16 );
    UPDATE_CBC_MAC;

    /*
     * If there is additional data, update CBC-MAC with
     * add_len, add, 0 (padding to a block boundary)
     */
    if( add_len > 0 )
    {
        size_t use_len;
        len_left = add_len;
        src = add;

        memset( b, 0, 16 );
        b[0] = (unsigned char)( ( add_len >> 8 ) & 0xFF );
        b[1] = (unsigned char)( ( add_len      ) & 0xFF );

        use_len = len_left < 16 - 2 ? len_left : 16 - 2;
        memcpy( b + 2, src, use_len );
        len_left -= use_len;
        src += use_len;

        UPDATE_CBC_MAC;

        while( len_left > 0 )
        {
            use_len = len_left > 16 ? 16 : len_left;

            memset( b, 0, 16 );
            memcpy( b, src, use_len );
            UPDATE_CBC_MAC;

            len_left -= use_len;
            src += use_len;
        }
    }

    /*
     * Prepare counter block for encryption:
     * 0        .. 0        flags
     * 1        .. iv_len   nonce (aka iv)
     * iv_len+1 .. 15       counter (initially 1)
     *
     * With flags as (bits):
     * 7 .. 3   0
     * 2 .. 0   q - 1
     */
    ctr[0] = q - 1;
    memcpy( ctr + 1, iv, iv_len );
    memset( ctr + 1 + iv_len, 0, q );
    ctr[15] = 1;

    /*
     * Authenticate and {en,de}crypt the message.
     *
     * The only difference between encryption and decryption is
     * the respective order of authentication and {en,de}cryption.
     */
    len_left = length;
    src = input;
    dst = output;

    while( len_left > 0 )
    {
        size_t use_len = len_left > 16 ? 16 : len_left;

        if( mode == CCM_ENCRYPT )
        {
            memset( b, 0, 16 );
            memcpy( b, src, use_len );
            UPDATE_CBC_MAC;
        }

        CTR_CRYPT( dst, src, use_len );

        if( mode == CCM_DECRYPT )
        {
            memset( b, 0, 16 );
            memcpy( b, dst, use_len );
            UPDATE_CBC_MAC;
        }

        dst += use_len;
        src += use_len;
        len_left -= use_len;

        /*
         * Increment counter.
         * No need to check for overflow thanks to the length check above.
         */
        for( i = 0; i < q; i++ )
            if( ++ctr[15-i] != 0 )
                break;
    }

    /*
     * Authentication: reset counter and crypt/mask internal tag
     */
    for( i = 0; i < q; i++ )
        ctr[15-i] = 0;

    CTR_CRYPT( y, y, 16 );
    memcpy( tag, y, tag_len );

    return( 0 );
}
