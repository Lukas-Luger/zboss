/***************************************************************************
 *                      ZBOSS ZigBee Pro 2007 stack                         *
 *                                                                          *
 *          Copyright (c) 2012 DSR Corporation Denver CO, USA.              *
 *                       http://www.dsr-wireless.com                        *
 *                                                                          *
 *                            All rights reserved.                          *
 *          Copyright (c) 2011 ClarIDy Solutions, Inc., Taipei, Taiwan.     *
 *                       http://www.claridy.com/                            *
 *                                                                          *
 *          Copyright (c) 2011 Uniband Electronic Corporation (UBEC),       *
 *                             Hsinchu, Taiwan.                             *
 *                       http://www.ubec.com.tw/                            *
 *                                                                          *
 *          Copyright (c) 2011 DSR Corporation Denver CO, USA.              *
 *                       http://www.dsr-wireless.com                        *
 *                                                                          *
 *                            All rights reserved.                          *
 *                                                                          *
 *                                                                          *
 * ZigBee Pro 2007 stack, also known as ZBOSS (R) ZB stack is available     *
 * under either the terms of the Commercial License or the GNU General      *
 * Public License version 2.0.  As a recipient of ZigBee Pro 2007 stack, you*
 * may choose which license to receive this code under (except as noted in  *
 * per-module LICENSE files).                                               *
 *                                                                          *
 * ZBOSS is a registered trademark of DSR Corporation AKA Data Storage      *
 * Research LLC.                                                            *
 *                                                                          *
 * GNU General Public License Usage                                         *
 * This file may be used under the terms of the GNU General Public License  *
 * version 2.0 as published by the Free Software Foundation and appearing   *
 * in the file LICENSE.GPL included in the packaging of this file.  Please  *
 * review the following information to ensure the GNU General Public        *
 * License version 2.0 requirements will be met:                            *
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.                   *
 *                                                                          *
 * Commercial Usage                                                         *
 * Licensees holding valid ClarIDy/UBEC/DSR Commercial licenses may use     *
 * this file in accordance with the ClarIDy/UBEC/DSR Commercial License     *
 * Agreement provided with the Software or, alternatively, in accordance    *
 * with the terms contained in a written agreement between you and          *
 * ClarIDy/UBEC/DSR.                                                        *
 *                                                                          *
 ****************************************************************************
   PURPOSE: RIOT-OS specific code
 */
#ifndef ZB_RIOT_SUBMAC_H
#define ZB_RIOT_SUBMAC_H 1

#include "net/ieee802154/submac.h"
#include "mutex.h"

#ifndef UBEC_SPECIFIC_INCLUDED
#define UBEC_SPECIFIC_INCLUDED

#ifndef ZB_NS_BUILD

#define ZB_ADDR_REALIGN(ptr, val)                                \
    *((zb_uint8_t *)(ptr) + 7) = *((zb_uint8_t *)(val)),  \
    *((zb_uint8_t *)(ptr) + 6) = *((zb_uint8_t *)(val) + 1),  \
    *((zb_uint8_t *)(ptr) + 5) = *((zb_uint8_t *)(val) + 2),  \
    *((zb_uint8_t *)(ptr) + 4) = *((zb_uint8_t *)(val) + 3),  \
    *((zb_uint8_t *)(ptr) + 3) = *((zb_uint8_t *)(val) + 4),  \
    *((zb_uint8_t *)(ptr) + 2) = *((zb_uint8_t *)(val) + 5),  \
    *((zb_uint8_t *)(ptr) + 1) = *((zb_uint8_t *)(val) + 6),  \
    *((zb_uint8_t *)(ptr)) = *((zb_uint8_t *)(val) + 7)

#define ZB_RXFLUSH() \
    (ZB_READ_SHORT_REG(ZB_SREG_RXFLUSH), \
     ZB_MAC_GET_BYTE_VALUE() |= 0x01,      \
     ZB_WRITE_SHORT_REG(ZB_SREG_RXFLUSH, ZB_MAC_GET_BYTE_VALUE()))


/**
   Min channel
 */
#define ZB_TRANSCEIVER_START_CHANNEL_NUMBER 11

/**
   Max channel
 */
#define ZB_TRANSCEIVER_MAX_CHANNEL_NUMBER   26

/**
   Send command/data/beacon to the transiver FIFO

   @param header_length - mhr length to write to UZ transiver
   @param buf - buffer to send
 */

#define ZB_TRANS_SEND_COMMAND(header_length, buf)          \
    zb_transceiver_send_packet((header_length), (buf))



/**
   Receive packet from the transiver
 */
#define ZB_TRANS_RECV_PACKET(buf) zb_transceiver_read(buf)

/**
    Start of actually used stuff
*/
#define ZB_TRANS_CHECK_CHANNEL_BUSY_ERROR() ZB_IS_TX_CHANNEL_BUSY() /* not 0 means channel busy error */

/*
   clear ISRSTS bit 0  - TX Normal FIFO transmission interrupt bit
   clear TXSR bit 5 - CCAFAIL: Channel busy causes CSMA-CA fails
   clear TXSR bit 0 - Normal FIFO release status (1 - fail, retry count exceed)
 */
#define ZB_CLEAR_TX_STATUS() (TRANS_CTX().int_status &= 0xFE, \
                              TRANS_CTX().tx_status &= 0xDE)

#define ZB_SET_TX_CHANNEL_BUSY() (TRANS_CTX().tx_status |= 0x20)
/* check TXSR bit 0 - Normal FIFO release status (1 - fail, retry count exceed) */
#define ZB_IS_TX_CHANNEL_BUSY() (TRANS_CTX().tx_status & 0x20)
/* check TXSR bit 5 - CCAFAIL: Channel busy causes CSMA-CA fails */
#define ZB_IS_TX_RETRY_COUNT_EXCEEDED() (TRANS_CTX().tx_status & 0xDF)

#define ZB_TRANS_CHECK_CHANNEL_ERROR() (ZB_IS_TX_CHANNEL_BUSY() || \
                                        ZB_IS_TX_RETRY_COUNT_EXCEEDED())

#define ZB_TRANS_CUT_SPECIFIC_HEADER(zb_buffer) 


/**
   Transiver context specific for RIOT-OS
 */
typedef struct zb_transceiver_ctx_s {
    zb_uint8_t int_status;
    zb_uint8_t tx_status;
    zb_uint8_t interrupt_flag;
    ieee802154_submac_t submac;
    // mutex_t lock;
    zb_uint8_t buffer[IEEE802154_FRAME_LEN_MAX];
    zb_ushort_t b_size;
    zb_bool_t has_src_addr_match;
}
zb_transceiver_ctx_t;

#define ZB_SET_TRANS_INT() (TRANS_CTX().interrupt_flag = 1)
#define ZB_CLEAR_TRANS_INT() (TRANS_CTX().interrupt_flag = 0)
#define ZB_GET_TRANS_INT() (TRANS_CTX().interrupt_flag)
#define ZB_UBEC_GET_RX_DATA_STATUS() (TRANS_CTX().int_status & 0x08)    /* get bit 3 */
#define ZB_UBEC_SET_RX_DATA_STATUS() (TRANS_CTX().int_status |= 0x08)    /* set bit 3 */
#define ZB_UBEC_CLEAR_RX_DATA_STATUS() (TRANS_CTX().int_status &= (~0x08))  /* clear bit 3 */

/**
   Send packet from buffer
   
   @param buf - buffer to send
   @return RET_OK, RET_ERROR
 */
zb_ret_t zb_transceiver_send_packet(zb_uint8_t header_length, zb_buf_t *buf) ZB_SDCC_REENTRANT;

/**
   Read from receiver buffer
 */
void zb_transceiver_read(zb_buf_t *buf) ZB_SDCC_REENTRANT;

/**
   Initialize submac
 */
void init_submac();

/**
   Portable macro for int status check routine
 */
#define ZB_CHECK_INT_STATUS() (0)


/**
   Check that transiver is in the beacon mode
 */
#define ZB_CHECK_BEACON_MODE_ON() ZB_TRUE

/**
   Set pending bit of ack frames
 
   @param param - index of pending data containing address
 */
void zb_set_pending_bit(zb_uint8_t param);

/**
   Clear pending bit of ack frames
   Automagically clears pending queue slot
 
   @param param - index of pending data containing address
 */
void zb_clear_pending_bit(zb_uint8_t param);

/**
   Portable macros for pending bit settings

   @param index - index of pending data queue
 */
#define ZB_SET_PENDING_BIT(index) zb_set_pending_bit(index)

#define ZB_CLEAR_PENDING_BIT(index) zb_clear_pending_bit(index)

/**
   Set channel of submac transiver

   @param channel_number - channel number
 */
void zb_transceiver_set_channel(zb_uint8_t channel_number);

/**
   Portable macro for zb_transceiver_set_channel()
 */
#define ZB_TRANSCEIVER_SET_CHANNEL(channel_number) zb_transceiver_set_channel( \
        channel_number)

/**
   Get channel of submac transiver

   @return channel_number - channel number
 */
zb_uint8_t zb_transceiver_get_channel(void);

/**
   Get RSSI from submac (dummy)

   @param rssi_value - (out) rssi value
 */
void zb_transceiver_get_rssi(zb_uint8_t *rssi_value);

/**
   Set 16-bit short address

   @param addr - 16-bit address
 */
void zb_transceiver_update_short_addr(uint16_t addr);

/**
   Assign short pan ID in submac

   @param pan_id - new pan id
 */
void zb_transceiver_set_pan_id(uint16_t pan_id);

/**
   Portable macro for zb_transceiver_set_pan_id()
 */
#define ZB_TRANSCEIVER_SET_PAN_ID(pan_id) zb_transceiver_set_pan_id(pan_id)

/**
   Assign ext (long) coordinator address (dummy)

   @param coord_addr_long - addres to remember
 */
void zb_transceiver_set_coord_ext_addr(zb_ieee_addr_t coord_addr_long);


/**
   Portable macro for zb_transceiver_set_coord_ext_addr()
 */
#define ZB_TRANSCEIVER_SET_COORD_EXT_ADDR(addr) \
    zb_transceiver_set_coord_ext_addr((addr))

/**
   Assign short coordinator address (dummy)

   @param coord_addr_short - addres to remember
 */
void zb_transceiver_set_coord_short_addr(zb_uint16_t coord_addr_short);

/**
   Portable macro for zb_transceiver_set_coord_short_addr()
 */
#define ZB_TRANSCEIVER_SET_COORD_SHORT_ADDR(addr) \
    zb_transceiver_set_coord_short_addr((addr))

/**
   Set 64-bit long address

   @param addr - 64-bit address
 */
void zb_transceiver_update_long_addr(uint8_t *addr);

/**
   Update submac long address: copy PIB value to the transiver
 */
#define ZB_UPDATE_LONGMAC() \
        zb_transceiver_update_long_addr(ZB_PIB_EXTENDED_ADDRESS())


/**
   Update submac pan id: copy PIB value to the transiver
 */
#define ZB_UPDATE_PAN_ID() \
    (ZB_TRANSCEIVER_SET_PAN_ID(MAC_PIB().mac_pan_id))

/**
   Update submac short address: copy PIB value to the transiver
 */
#define ZB_UPDATE_SHORT_ADDR() zb_transceiver_update_short_addr( \
            MAC_PIB().mac_short_address)
#define ZB_CLEAR_SHORT_ADDR() zb_transceiver_update_short_addr(-1)

#endif  /* !ZB_NS_BUILD */

#endif /* !UBEC_SPECIFIC_INCLUDED */

#endif /* RIOT_SUBMAC_h */
