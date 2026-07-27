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
#include "zb_types.h"
#include "zb_config.h"
#include "zb_secur.h"
#include "mac_internal.h"
#include "zb_riot_submac.h"
#include "luid.h"
#include "net/eui_provider.h"

/*! \addtogroup ZB_MAC */
/*! @{ */

#ifdef ZB_MAC_RIOT

#ifdef ZB_NS_BUILD
#error "NS build can't be defined in real transiver build"
#endif

#include "zb_bank_2.h"

/* RIOT device specific includes */
#ifdef MODULE_CC2538_RF
#include "cc2538_rf.h"
#endif

#ifdef MODULE_ESP_IEEE802154
#include "esp_ieee802154_hal.h"
#endif

#ifdef MODULE_NRF802154
#include "nrf802154.h"
#endif

#ifdef MODULE_SOCKET_ZEP
#include "socket_zep.h"
#include "socket_zep_params.h"
#endif

#ifdef MODULE_KW2XRF
#include "kw2xrf.h"
#include "kw2xrf_params.h"
#define KW2XRF_NUM   ARRAY_SIZE(kw2xrf_params)
static kw2xrf_t kw2xrf_dev[KW2XRF_NUM];
static bhp_event_t kw2xrf_bhp[KW2XRF_NUM];
#endif

#ifdef MODULE_MRF24J40
#include "mrf24j40.h"
#include "mrf24j40_params.h"
#define MRF24J40_NUM    ARRAY_SIZE(mrf24j40_params)
static mrf24j40_t mrf24j40_dev[MRF24J40_NUM];
static bhp_event_t mrf24j40_bhp[MRF24J40_NUM];
#endif

/**
 * RIOT Submac specific functions
 */
/* Submac handler glue */
static void _tx_done_handler(zb_uint8_t param)
{
    (void)param;
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_submac_tx_done_cb(&TRANS_CTX().submac);
    // mutex_unlock(&TRANS_CTX().lock);
}

static void _rx_done_handler(zb_uint8_t param)
{
    (void)param;
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_submac_rx_done_cb(&TRANS_CTX().submac);
    // mutex_unlock(&TRANS_CTX().lock);
}

static void _crc_error_handler(zb_uint8_t param)
{
    (void)param;
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_submac_crc_error_cb(&TRANS_CTX().submac);
    // mutex_unlock(&TRANS_CTX().lock);
}

static void _bh_request_handler(zb_uint8_t param)
{
    (void)param;
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_submac_bh_process(&TRANS_CTX().submac);
    // mutex_unlock(&TRANS_CTX().lock);
}

static void _mac_ack_timeout(zb_uint8_t param)
{
    (void)param;
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_submac_ack_timeout_fired(&TRANS_CTX().submac);
    // mutex_unlock(&TRANS_CTX().lock);
    /* ZB_MAC_SET_ACK_TIMEOUT(); - but no one is interested */
}

static void _submac_task_finished(zb_uint8_t param)
{
    /* IEEE 802.15.4-2020 6.7.2 suprisingly not in zboss */
    /* On completion of each transceiver task,
     * the MAC sublayer shall request that the PHY
     * enables or disables its receiver,
     * depending on the values of macBeaconOrder and macRxOnWhenIdle.
     */
    if (MAC_PIB().mac_beacon_order < ZB_TURN_OFF_ORDER) {
        /* aka beacon enabled PAN, */
        /* ZB_PIB_RX_ON_WHEN_IDLE() considered only during idle period aka CAP*/
        /* */
    }
    else {
        /* ZB_PIB_RX_ON_WHEN_IDLE() always relevant */
    }
    /* for now just set it to rx (small brain move) */
    int res = ieee802154_set_rx(&TRANS_CTX().submac);
}

static void submac_rx_done(ieee802154_submac_t *submac)
{
    ieee802154_rx_info_t rx_info;
    zb_uint8_t buf[IEEE802154_FRAME_LEN_MAX];
    TRANS_CTX().b_size = ieee802154_get_frame_length(submac);
    ieee802154_read_frame(submac, TRANS_CTX().buffer,
                                TRANS_CTX().b_size, &rx_info);
    if (TRANS_CTX().b_size < 0) {
        puts("Couldn't read frame");
        return;
    }

    TRANS_CTX().buffer[TRANS_CTX().b_size] = rx_info.lqi;
    TRANS_CTX().buffer[TRANS_CTX().b_size + 1] = rx_info.rssi;
    TRANS_CTX().b_size += 2;
    /* need to send ack here, zboss uses mac_main_loop (too slow)*/
    if (TRANS_CTX().buffer[0] & 0x20) {
        ieee802154_set_idle(&TRANS_CTX().submac);
        zb_uint8_t ack[3];
        ack[0] = 0x02; // | 0x10 for pending data ;
        ack[1] = 0x00;
        ack[2] = TRANS_CTX().buffer[2];

        iolist_t pkt;
        pkt.iol_next = NULL;
        pkt.iol_base = &ack;
        pkt.iol_len = sizeof(ack);

        zb_uint8_t res = ieee802154_send(&TRANS_CTX().submac, &pkt);
    }
    ZB_UBEC_SET_RX_DATA_STATUS();
    ZB_SCHEDULE_CALLBACK(_submac_task_finished, 0);
}

static void submac_tx_done(ieee802154_submac_t *submac, int status,
                           ieee802154_tx_info_t *info)
{
    (void)info;
    (void)submac;
    switch (status) {
    case TX_STATUS_SUCCESS:
        ZB_CLEAR_TX_STATUS();
        ZB_MAC_SET_ACK_OK();
        ZB_MAC_CLEAR_PENDING_DATA();
        break;
    case TX_STATUS_FRAME_PENDING:
        ZB_MAC_SET_PENDING_DATA();
        break;
    case TX_STATUS_MEDIUM_BUSY:
        ZB_SET_TX_CHANNEL_BUSY();
        break;
    case TX_STATUS_NO_ACK:
        ZB_SET_MAC_STATUS(MAC_NO_ACK);
        break;
    default:
        break;
    }
    MAC_CTX().tx_cnt++;
    ZB_SCHEDULE_CALLBACK(_submac_task_finished, 0);

}

static const ieee802154_submac_cb_t _cb = {
    .rx_done = submac_rx_done,
    .tx_done = submac_tx_done,
};

void ieee802154_submac_ack_timer_set(ieee802154_submac_t *submac)
{
    (void)submac;
    /* do we need ACK_TIMEOUT(), ACK_FAIL()? - no
     * but we could use ACK_OK() in zb_mac_main_loop
     * no behaviour specified for ACK_FAIL()
     * ACK_TIMEOUT() only necessary if ZBOSS does retransmissions
     * but submac handles it already
     */
    ZB_MAC_CLEAR_ACK_OK();
    ZB_SCHEDULE_ALARM_CANCEL(_mac_ack_timeout, ZB_ALARM_ALL_CB);
    ZB_SCHEDULE_ALARM(_mac_ack_timeout, 0, ZB_MAC_PIB_ACK_WAIT_DURATION);
}

void ieee802154_submac_ack_timer_cancel(ieee802154_submac_t *submac)
{
    (void)submac;
    ZB_SCHEDULE_ALARM_CANCEL(_mac_ack_timeout, ZB_ALARM_ANY_PARAM);
}

void ieee802154_submac_bh_request(ieee802154_submac_t *submac)
{
    (void)submac;
    ZB_SCHEDULE_CALLBACK(_bh_request_handler, 0);
}

static void _hal_radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t status)
{
    (void)dev;
    /* no idea how this could be beneficial */
    switch (status) {
    case IEEE802154_RADIO_CONFIRM_TX_DONE:
        ZB_SCHEDULE_CALLBACK(_tx_done_handler, 0);
        break;
    case IEEE802154_RADIO_INDICATION_RX_DONE:
        ZB_SCHEDULE_CALLBACK(_rx_done_handler, 0);
        break;
    case IEEE802154_RADIO_INDICATION_CRC_ERROR:
        ZB_SCHEDULE_CALLBACK(_crc_error_handler, 0);
        break;
    default:
        break;
    }
}

void init_devs(ieee802154_dev_t *radio)
{
#ifdef MODULE_CC2538_RF
    if (radio){
        cc2538_rf_hal_setup(radio);
        cc2538_init();
    }
#endif

#ifdef MODULE_ESP_IEEE802154
    if (radio){
        esp_ieee802154_setup(radio);
        esp_ieee802154_init();
    }
#endif

#ifdef MODULE_NRF802154
    if (radio){
        nrf802154_hal_setup(radio);
        nrf802154_init();
    }
#endif

#ifdef MODULE_KW2XRF
    if (radio){
        for (unsigned i = 0; i < KW2XRF_NUM; i++) {
            const kw2xrf_params_t *p = &kw2xrf_params[i];
            bhp_event_init(&kw2xrf_bhp[i], EVENT_PRIO_HIGHEST, &kw2xrf_radio_hal_irq_handler, radio);
            kw2xrf_init(&kw2xrf_dev[i], p, radio, bhp_event_isr_cb, &kw2xrf_bhp[i]);
            break;
        }
    }
#endif

#ifdef MODULE_SOCKET_ZEP
    static socket_zep_t _socket_zeps[SOCKET_ZEP_MAX];
    if (radio){
        socket_zep_hal_setup(&_socket_zeps[0], radio);
        socket_zep_setup(&_socket_zeps[0], &socket_zep_params[0]);
    }
#endif

#ifdef MODULE_MRF24J40
    if (radio){
        for (unsigned i = 0; i < MRF24J40_NUM; i++) {
            const mrf24j40_params_t *p = &mrf24j40_params[i];
            bhp_event_init(&mrf24j40_bhp[i], EVENT_PRIO_HIGHEST, &mrf24j40_radio_irq_handler, radio);
            mrf24j40_init(&mrf24j40_dev[i], p, radio, bhp_event_isr_cb, &mrf24j40_bhp[i]);
            break;
        }
    }
#endif
}

 /**
  * General ZBOSS functions
  */
void init_submac(void)
{
    // mutex_init(&TRANS_CTX().lock);
    /* we do not use interrupts */
    ZB_CLEAR_TRANS_INT();
    TRANS_CTX().submac.cb = &_cb;

    TRANS_CTX().submac.dev.cb = _hal_radio_cb;

    eui64_t ext_addr;
    network_uint16_t short_addr;
    luid_base(&ext_addr, IEEE802154_LONG_ADDRESS_LEN);
    eui64_set_local(&ext_addr);
    eui64_clear_group(&ext_addr);
    eui_short_from_eui64(&ext_addr, &short_addr);

    init_devs(&(TRANS_CTX().submac.dev));

    int res = ieee802154_submac_init(&TRANS_CTX().submac, &short_addr, &ext_addr);
    
    ZB_ADDR_REALIGN(ZB_PIB_EXTENDED_ADDRESS(), &ext_addr.uint8[0]);
    ZB_SHORT_ADDR_REALIGN(&MAC_PIB().mac_short_address, &short_addr);

    LOG_INFO("got hw short address 0x%04x\n", MAC_PIB().mac_short_address);
    ZB_ASSERT(res == 0);

    TRANS_CTX().has_src_addr_match = 
            ieee802154_radio_has_capability(&TRANS_CTX().submac.dev,
                            IEEE802154_CAP_SRC_ADDR_MATCH);
    if (TRANS_CTX().has_src_addr_match) {
        /* Need to enable it */
        ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                    IEEE802154_SRC_MATCH_EN, &TRANS_CTX().has_src_addr_match);
    }
    // how to set these in submac?
    // netopt_enable_t set = NETOPT_ENABLE;
    // netopt_enable_t unset = NETOPT_DISABLE;
    // gnrc_netapi_set(_zb_iface_id, NETOPT_CSMA, 0, &set,
    //                 sizeof(netopt_enable_t));
    // gnrc_netapi_set(_zb_iface_id, NETOPT_RAWMODE, 0, &set,
    //                 sizeof(netopt_enable_t));
    // gnrc_netapi_set(_zb_iface_id, NETOPT_ACK_REQ, 0, &set,
    //                 sizeof(netopt_enable_t));
    // gnrc_netapi_set(_zb_iface_id, NETOPT_AUTOACK, 0, &set,
    //                 sizeof(netopt_enable_t));
}

zb_ret_t zb_transceiver_send_packet(zb_uint8_t header_length, zb_buf_t *buf) ZB_SDCC_REENTRANT
{
    ZVUNUSED(header_length);
    TRACE_MSG(TRACE_MAC1,
              ">> zb_transceiver_send_packet, buf %p",
              (FMT__P, buf));

    iolist_t pkt;
    pkt.iol_next = NULL;
    pkt.iol_base = ZB_BUF_BEGIN(buf);
    pkt.iol_len = ZB_BUF_LEN(buf);

    // mutex_lock(&TRANS_CTX().lock);
    /* this will automatically wake receiver */
    zb_uint8_t res = ieee802154_send(&TRANS_CTX().submac, &pkt);
    // mutex_unlock(&TRANS_CTX().lock);

    TRACE_MSG(TRACE_MAC1, "<< zb_transceiver_send_fifo_packet", (FMT__0));

    if (res < 0) {
        puts("Error: Frame couldn't be sent");
        return RET_ERROR;
    }
    
    return RET_OK;
}

void zb_transceiver_read(zb_buf_t *buf) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_MAC2, ">> zb_transceiver_read, buf %p", (FMT__P, buf));
    
    zb_uint8_t *data_ptr;
    ZB_BUF_INITIAL_ALLOC(buf, TRANS_CTX().b_size, data_ptr);
    ZB_MEMCPY(data_ptr, TRANS_CTX().buffer, TRANS_CTX().b_size);
    TRANS_CTX().b_size = 0;
    
    TRACE_MSG(TRACE_MAC1, "<< zb_transceiver_read", (FMT__0));
}

void zb_transceiver_set_channel(zb_uint8_t channel_number)
{
    MAC_CTX().current_channel = channel_number;
    // mutex_lock(&TRANS_CTX().lock);
    int ret = ieee802154_set_channel_number(&TRANS_CTX().submac, (uint16_t)channel_number);
    // mutex_unlock(&TRANS_CTX().lock);
}

uint8_t zb_transceiver_get_channel(void)
{
    return TRANS_CTX().submac.channel_num;
}

void zb_transceiver_update_short_addr(uint16_t addr)
{
    // mutex_lock(&TRANS_CTX().lock);
    network_uint16_t set_addr;
    ZB_SHORT_ADDR_REALIGN(&set_addr, &addr);
    ieee802154_set_short_addr(&TRANS_CTX().submac, &set_addr);
    // mutex_unlock(&TRANS_CTX().lock);
    MAC_PIB().mac_short_address = addr;
}

void zb_transceiver_set_pan_id(uint16_t pan_id)
{
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_set_panid(&TRANS_CTX().submac, &pan_id);
    // mutex_unlock(&TRANS_CTX().lock);
}

void zb_transceiver_update_long_addr(uint8_t *addr)
{
    eui64_t eui_addr;
    ZB_ADDR_REALIGN(&eui_addr, addr);
    // mutex_lock(&TRANS_CTX().lock);
    ieee802154_set_ext_addr(&TRANS_CTX().submac, &eui_addr);
    // mutex_unlock(&TRANS_CTX().lock);
}

void zb_clear_pending_bit(zb_uint8_t param)
{
    // mutex_lock(&TRANS_CTX().lock);
    zb_mac_pending_data_t *pend_data = &MAC_CTX().pending_data_queue[param];
    zb_bool_t en = ZB_FALSE;
    if (TRANS_CTX().has_src_addr_match) {
        if (pend_data->dst_addr_mode == ZB_ADDR_64BIT_DEV) {
            ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                IEEE802154_SRC_MATCH_EXT_CLEAR, pend_data->dst_addr.addr_long);
        }
        else {
            ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                IEEE802154_SRC_MATCH_SHORT_CLEAR, &(pend_data->dst_addr.addr_short));
        }
        /* clear after operation, we need contents of pending data */
        ZB_CLEAR_PENDING_QUEUE_SLOT(param);
    }
    else {
        /* clear before operation, we do not need pending data*/
        ZB_CLEAR_PENDING_QUEUE_SLOT(param);
        /* allows to check if queue is empty now */
        if (pending_queue_is_empty()) {
             ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                                    IEEE802154_SRC_MATCH_EN, &en);
        }  
    }
    // mutex_unlock(&TRANS_CTX().lock);   
}

void zb_set_pending_bit(zb_uint8_t param)
{
    // mutex_lock(&TRANS_CTX().lock);
    zb_mac_pending_data_t *pend_data = &MAC_CTX().pending_data_queue[param];
    zb_bool_t en = ZB_TRUE;
    if (TRANS_CTX().has_src_addr_match) {
        if (pend_data->dst_addr_mode == ZB_ADDR_64BIT_DEV) {
            ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                    IEEE802154_SRC_MATCH_EXT_ADD, pend_data->dst_addr.addr_long);
        }
        else {
            ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                    IEEE802154_SRC_MATCH_SHORT_ADD, &(pend_data->dst_addr.addr_short));
        }
    }
    else {
        ieee802154_radio_config_src_address_match(&TRANS_CTX().submac.dev,
                                    IEEE802154_SRC_MATCH_EN, &en);
    }

    // mutex_unlock(&TRANS_CTX().lock);   
}

/* unsupported dummy functions */
void zb_transceiver_get_rssi(zb_uint8_t *rssi_value)
{
    TRACE_MSG(TRACE_MAC2, ">> zb_transceiver_get_rssi", (FMT__0));
    /* typically used in energy density scan */
    ZB_ASSERT(rssi_value);

    TRACE_MSG(TRACE_MAC2, "<< zb_transceiver_get_rssi rssi_value %hd",
              (FMT__H, *rssi_value));
}

void zb_transceiver_set_coord_ext_addr(zb_ieee_addr_t coord_addr_long)
{
   TRACE_MSG(TRACE_MAC2, ">> zb_transceiver_set_coord_ext_addr, addr %i" 
              TRACE_FORMAT_64, (FMT__A, TRACE_ARG_64(coord_addr_long)));

    ZVUNUSED(coord_addr_long);

    TRACE_MSG(TRACE_MAC2, "<< zb_transceiver_set_coord_ext_addr", (FMT__0));
}

void zb_transceiver_set_coord_short_addr(zb_uint16_t coord_addr_short)
{
    TRACE_MSG(TRACE_MAC2, ">> zb_transceiver_set_coord_short_addr, addr %d" 
              (FMT__D, coord_addr_short));

    ZVUNUSED(coord_addr_short);

    TRACE_MSG(TRACE_MAC2, "<< zb_transceiver_set_coord_short_addr", (FMT__0));
}

void zb_mac_transport_init() ZB_SDCC_REENTRANT /* __reentrant for sdcc, to save DSEG space */
{
    TRACE_MSG(TRACE_MAC3, "nothing to do", (FMT__0));
}
/* @} */

#endif  /* ZB_MAC_RIOT */
