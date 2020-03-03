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
   PURPOSE: RIOT-OS specific
 */

#include "zb_common.h"
#include "zb_scheduler.h"
#include "zb_nwk.h"
#include "zb_mac.h"
#include "mac_internal.h"
#include "zb_mac_transport.h"
#include "zb_ubec24xx.h"
#include "zb_types.h"
#include "zb_config.h"
#include "zb_secur.h"
#include "mac_internal.h"

#include "net/gnrc/netapi.h"

/*! \addtogroup ZB_MAC */
/*! @{ */

#ifdef ZB_MAC_RIOT

#ifdef ZB_NS_BUILD
#error "NS build can't be defined in real transiver build"
#endif

#include "zb_bank_2.h"

extern pid_t _zb_iface_id;

void init_zu2400(void)
{}

void zb_set_trans_int(void)
{
    TRANS_CTX().interrupt_flag = 1;
}

void zb_ubec_check_int_status()
{


    if (ZB_UBEC_GET_TX_DATA_STATUS()) {
        MAC_CTX().tx_cnt++;
        TRACE_MSG(TRACE_MAC1, "TX counter: %hd", (FMT__H, MAC_CTX().tx_cnt));
//         ZB_READ_SHORT_REG(ZB_SREG_TXSR);
        TRACE_MSG(TRACE_COMMON3, "tx status: 0x%hx",
                  (FMT__H, ZB_MAC_GET_BYTE_VALUE()));
        TRANS_CTX().tx_status = ZB_MAC_GET_BYTE_VALUE();
    }
}


/* Access via spidev differs to another methods: it has registers and fifo
 * access implemented in the transport. */
#ifndef ZB_TRANSPORT_LINUX_SPIDEV


#elif defined ZB_TRANSPORT_LINUX_SPIDEV


/* spidev transport has its own registers read-write and fifo read-write */


#else

#error "PORT ME!!!!"

#endif  /* transports choice */


#if 0
void zb_uz24_write_long_reg_array(zb_uint16_t start_reg, zb_uint8_t *array,
                                  zb_uint8_t cnt)
{
    zb_ushort_t i;

    for (i = 0; i < cnt; i++) {
        ZB_WRITE_LONG_REG(start_reg + i, array[i]);
    }
}
#endif







#endif  /* ZB_MAC_RIOT */

/*! @} */






/*! \addtogroup ZB_MAC */
/*! @{ */

#if defined ZB_MAC_RIOT

extern void send_packet(uint8_t *payload, uint32_t length);


/*
   Puts MAC command to normal transmit FIFO and starts packet
   send. Command should be formmated and stored in the operation_buf
   @param header_length - mhr length in bytes
   @param fifo_addr - fifo address
   @param buf - buffer to send
   @param need_ack - if 1, retransmit until ACK recv
   @return RET_OK, RET_ERROR
 */
zb_ret_t zb_transceiver_send_fifo_packet(zb_uint8_t header_length,
                                         zb_int16_t fifo_addr,
                                         zb_buf_t *buf,
                                         zb_uint8_t need_tx) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_MAC1,
              ">> zb_transceiver_send_fifo_packet, %d, addr %x, buf %p, state %hd",
              (FMT__D_D_P,
               (
                   zb_uint16_t)header_length, fifo_addr, buf));

    send_packet(ZB_BUF_BEGIN(buf), ZB_BUF_LEN(buf));

    TRACE_MSG(TRACE_MAC1, "<< zb_transceiver_send_fifo_packet", (FMT__0));
    return RET_OK;
}


/*
   Set new active channel in transceiver
   @param channel_number - new channel number
   @return RET_OK on success, error code on fail
 */
void zb_transceiver_set_channel(zb_uint8_t channel_number)
{
    MAC_CTX().current_channel = channel_number;

    uint16_t channel = channel_number;
    gnrc_netapi_set(_zb_iface_id, NETOPT_CHANNEL, 0, &channel,
                    sizeof(uint16_t));
}

uint8_t zb_transceiver_get_channel(void)
{
    uint16_t channel;
    gnrc_netapi_get(_zb_iface_id, NETOPT_CHANNEL, 0, &channel,
                    sizeof(uint16_t));
    return channel;
}

void zb_transceiver_get_rssi(zb_uint8_t *rssi_value)
{
    TRACE_MSG(TRACE_MAC2, ">> zb_transceiver_get_rssi", (FMT__0));

    ZB_ASSERT(rssi_value);

    TRACE_MSG(TRACE_MAC2, "<< zb_transceiver_get_rssi rssi_value %hd",
              (FMT__H, *rssi_value));
}

void zb_transceiver_set_coord_ext_addr(zb_ieee_addr_t coord_addr_long)
{
    zb_uint8_t i = 0;

    while (i < sizeof(zb_ieee_addr_t)) {
        /* write one bye one 8 bytes of the extended address */
        ZB_WRITE_LONG_REG(ZB_LREG_ASSOEADR0 + i, coord_addr_long[i]);
        i++;
    }
}


extern void zb_transceiver_update_short_addr(uint16_t addr);
void zb_transceiver_set_coord_short_addr(zb_uint16_t coord_addr_short)
{
//     ZB_WRITE_LONG_REG(ZB_LREG_ASSOSADR0, ZB_GET_LOW_BYTE(coord_addr_short));
//     ZB_WRITE_LONG_REG(ZB_LREG_ASSOSADR1, ZB_GET_HI_BYTE(coord_addr_short));
    zb_transceiver_update_short_addr(coord_addr_short);
}

extern void zb_transceiver_update_long_addr(uint8_t *addr);
void zb_transceiver_update_long_mac()
{
    zb_ushort_t i;

    for (i = 0; i < 8; i++) {
//         ZB_WRITE_SHORT_REG(EADR0 + i, ZB_PIB_EXTENDED_ADDRESS()[i]);
    }
    zb_transceiver_update_long_addr(ZB_PIB_EXTENDED_ADDRESS());
}

void zb_mac_transport_init(zb_char_t *rpipe_path, zb_char_t *wpipe_path)
{}


/* @} */

#endif  /* ZB_MAC_RIOT */
