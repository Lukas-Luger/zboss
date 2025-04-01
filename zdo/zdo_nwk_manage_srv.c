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
   PURPOSE: ZDO network management functions, client side
 */

#include "zb_common.h"
#include "zb_scheduler.h"
#include "zb_bufpool.h"
#include "zb_hash.h"
#include "zb_nwk.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zdo_common.h"
#include "zb_secur.h"
#include "zb_zcl_groups.h"

void aes128(zb_uint8_t *key, zb_uint8_t *msg, zb_uint8_t *c);
void aes128d(const zb_uint8_t *c, const zb_uint8_t *key, zb_uint8_t *m);

#include "zb_bank_8.h"

#ifndef ZB_LIMITED_FEATURES
/*! \addtogroup ZB_ZDO */
/*! @{ */
void zb_zdo_new_channel_cb(zb_uint8_t param) ZB_CALLBACK;
void zb_nwk_do_leave_local(zb_uint8_t param) ZB_CALLBACK;

/* Handle nwk_update_req, 2.4.3.3.9 Mgmt_NWK_Update_req */
void zb_zdo_mgmt_nwk_update_handler(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_apsde_data_indication_t *ind;
    zb_zdo_mgmt_nwk_update_req_hdr_t *req_hdr;
    zb_uint8_t *aps_body;
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
//  zb_uint8_t update_id;
    zb_uint16_t manager_addr;
    zb_uint8_t send_resp = 0;
    zb_uint8_t status = ZB_ZDP_STATUS_SUCCESS;
    zb_uint32_t scan_channels;
    zb_uint8_t tsn;

    TRACE_MSG(TRACE_ZDO3, ">>mgmt_nwk_update_handler %hd", (FMT__H, param));

    aps_body = ZB_BUF_BEGIN(buf);
    ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);
    /*
       2.4.2.8 Transmission of ZDP Commands
     | Transaction sequence number (1byte) | Transaction data (variable) |
     */
    tsn = *aps_body;
    aps_body++;
    req_hdr = (zb_zdo_mgmt_nwk_update_req_hdr_t *)aps_body;
    aps_body += sizeof(zb_zdo_mgmt_nwk_update_req_hdr_t);
    ZB_LETOH32(&scan_channels, &req_hdr->scan_channels);

    TRACE_MSG(TRACE_ZDO2, "scan_duration %hx, scan_channels %d %d",
              (FMT__H_D_D, req_hdr->scan_duration,
               *((zb_uint16_t *)&req_hdr->scan_channels),
               *(((zb_uint16_t *)&req_hdr->scan_channels) + 1)));
    if (req_hdr->scan_duration == ZB_ZDO_NEW_ACTIVE_CHANNEL) {
        TRACE_MSG(TRACE_ZDO2, "new act ch %d",
                  (FMT__D, (zb_uint16_t)req_hdr->scan_channels));
        if (req_hdr->scan_channels >= (1l << ZB_MAC_START_CHANNEL_NUMBER) &&
            req_hdr->scan_channels <= (1l << ZB_MAC_MAX_CHANNEL_NUMBER)) {
            zb_uint8_t i = 11;
            /*
               start nwkNetworkBroadcastDeliveryTime timer On timer
               expiration, change channel to the new value, increment
               NIB.UpdateId and reset counters
             */
            while (!(req_hdr->scan_channels & (1l << i))) {
                i++;
            }
            ZB_SCHEDULE_ALARM(zb_zdo_new_channel_cb, i,
                              ZB_NWK_BROADCAST_DELIVERY_TIME());
        }
    }
    else if (req_hdr->scan_duration == ZB_ZDO_NEW_CHANNEL_MASK) {
        TRACE_MSG(TRACE_ZDO2, "new ch mask", (FMT__0));
        /* save channel mask in APS IB */
        ZB_AIB().aps_channel_mask = req_hdr->scan_channels;
        /* TODO: check, what should i do with update_id? */
//    update_id = *aps_body;
        aps_body++;
        ZB_LETOH16(&manager_addr, aps_body);

        /* store nwkManagerAddr in the NIB */
        ZB_NIB_NWK_MANAGER_ADDR() = manager_addr;
    }
    else if (req_hdr->scan_duration <= ZB_ZDO_MAX_SCAN_DURATION) {
        zb_uint8_t scan_count = *aps_body;

        /* Table 2.87 Fields of the Mgmt_NWK_Update_req Command
           ScanCount valid range: 0x00 - 0x05
           This field represents the number of energy scans to be
           conducted and reported.
         */
        TRACE_MSG(TRACE_ZDO2, "ed scan", (FMT__0));
        if (scan_count > 5) {
            send_resp = 1;
            status = ZB_ZDP_STATUS_INV_REQUESTTYPE;
            TRACE_MSG(TRACE_ZDO1,
                      "mgmt_nwk_update_handler, error incorrect scan_count %hd",
                      (FMT__H, scan_count));
        }
        else if (scan_count > 0) {
            ZG->zdo.zdo_ctx.nwk_upd_req.scan_channels = scan_channels;
            ZG->zdo.zdo_ctx.nwk_upd_req.scan_duration = req_hdr->scan_duration;
            ZG->zdo.zdo_ctx.nwk_upd_req.scan_count = scan_count;
            ZG->zdo.zdo_ctx.nwk_upd_req.dst_addr = ind->src_addr;
            ZG->zdo.zdo_ctx.nwk_upd_req.tsn = tsn;
            ZB_APS_SET_ZDO_ED_SCAN_FLAG();
            zb_start_ed_scan(param);
        }
        else {
            send_resp = 1;
        }
    }
    else {
        TRACE_MSG(TRACE_ZDO1,
                  "mgmt_nwk_update_handler, error incorrect scan_duration %hd",
                  (FMT__H, req_hdr->scan_duration));
        /* response with error if addr mode is not unicast */
        if (ZB_APS_FC_GET_DELIVERY_MODE(ind->fc) == ZB_APS_DELIVERY_UNICAST) {
            send_resp = 1;
            status = ZB_NWK_STATUS_INVALID_REQUEST;
        }
    }

    /* check if transmission was not broadcast */
    if (send_resp && ind->src_addr < ZB_NWK_BROADCAST_LOW_POWER_ROUTER) {
        zb_zdo_mgmt_nwk_update_notify_param_t *update_notify_param;
        zb_uint16_t dst_addr = ind->src_addr;

        update_notify_param = ZB_GET_BUF_PARAM(buf,
                                               zb_zdo_mgmt_nwk_update_notify_param_t);
        ZB_BZERO(update_notify_param,
                 sizeof(zb_zdo_mgmt_nwk_update_notify_param_t));
        update_notify_param->hdr.status = status;
        update_notify_param->tsn = tsn;
        update_notify_param->dst_addr = dst_addr;

        zb_zdo_nwk_upd_notify(param);
    }

    TRACE_MSG(TRACE_ZDO3, "<<mgmt_nwk_update_handler", (FMT__0));
}

/* sends 2.4.4.3.9 Mgmt_NWK_Update_notify */
void zb_zdo_nwk_upd_notify(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zdo_mgmt_nwk_update_notify_param_t *notify_param = ZB_GET_BUF_PARAM(buf,
                                                                           zb_zdo_mgmt_nwk_update_notify_param_t);
    zb_zdo_mgmt_nwk_update_notify_hdr_t *notify_resp;
    zb_uint8_t *ed_scan_values;

    TRACE_MSG(TRACE_ZDO3, ">>nwk_upd_notify %hd", (FMT__H, param));

    ZB_APS_CLEAR_ZDO_ED_SCAN_FLAG();
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zdo_mgmt_nwk_update_notify_hdr_t),
                         notify_resp);

    ZB_MEMCPY(notify_resp, &notify_param->hdr,
              sizeof(zb_zdo_mgmt_nwk_update_notify_hdr_t));
    ZB_HTOLE32(&notify_resp->scanned_channels,
               &notify_param->hdr.scanned_channels);

    if (notify_resp->scanned_channels_list_count) {
        /* Assert just to be sure that we have enough space for response */
        ZB_ASSERT((ZB_APS_PAYLOAD_MAX_LEN -
                   sizeof(zb_zdo_mgmt_nwk_update_notify_hdr_t)) >
                  notify_resp->scanned_channels_list_count);

        ZB_BUF_ALLOC_RIGHT(buf, notify_resp->scanned_channels_list_count,
                           ed_scan_values);
        ZB_MEMCPY(ed_scan_values, notify_param->energy_values,
                  notify_resp->scanned_channels_list_count);
        TRACE_MSG(TRACE_ZDO3, "ch count %hd, buf len %hd",
                  (FMT__H_H, notify_resp->scanned_channels_list_count,
                   ZB_BUF_LEN(buf)));
    }

    TRACE_MSG(TRACE_ZDO3, "total tr %hd, tr fail %hd, ack %hd",
              (FMT__H_H_H, notify_resp->total_transmissions,
               notify_resp->transmission_failures, ZB_ZDO_GET_SEND_WITH_ACK()));
    if (ZB_ZDO_GET_SEND_WITH_ACK()) {
        /* send update notify as request to set ack needed option */
        zdo_send_req_by_short(ZDO_MGMT_NWK_UPDATE_NOTIFY_CLID, param,
                              zb_zdo_channel_check_finish_cb,
                              notify_param->dst_addr, 1);

        ZB_ZDO_CLEAR_SEND_WITH_ACK();
    }
    else {
        zdo_send_resp_by_short(ZDO_MGMT_NWK_UPDATE_NOTIFY_CLID, param,
                               notify_param->tsn, notify_param->dst_addr);
    }

    if (notify_resp->status == ZB_ZDP_STATUS_SUCCESS &&
        ZG->zdo.zdo_ctx.nwk_upd_req.scan_count) {
        ZB_APS_SET_ZDO_ED_SCAN_FLAG();
        ZB_GET_OUT_BUF_DELAYED(zb_start_ed_scan);
    }

    TRACE_MSG(TRACE_ZDO3, "<<nwk_upd_notify", (FMT__0));
}

void zb_start_ed_scan(zb_uint8_t param) ZB_CALLBACK
{
    zb_nlme_ed_scan_request_t *rq;

    TRACE_MSG(TRACE_ZDO3, "zb_start_ed_scan, param %d", (FMT__D, param));
    rq = ZB_GET_BUF_PARAM(ZB_BUF_FROM_REF(param), zb_nlme_ed_scan_request_t);

    ZG->zdo.zdo_ctx.nwk_upd_req.scan_count--;
    rq->scan_channels = ZG->zdo.zdo_ctx.nwk_upd_req.scan_channels;
    rq->scan_duration = ZG->zdo.zdo_ctx.nwk_upd_req.scan_duration;

    ZB_SCHEDULE_CALLBACK(zb_nlme_ed_scan_request, param);
}

void zb_zdo_new_channel_cb(zb_uint8_t param) ZB_CALLBACK
{
    /* Upon receipt of a Mgmt_NWK_Update_req with a change of channels,
     * change channel to the new value, increment NIB.UpdateId and reset
     * counters */
    TRACE_MSG(TRACE_ZDO2, "new_channel_cb ch %hd", (FMT__H, param));

    ZB_TRANSCEIVER_SET_CHANNEL(param); /* ignore retcode */
    ZB_NIB_NWK_TX_TOTAL() = 0;
    ZB_NIB_NWK_TX_FAIL() = 0;
    ZB_NIB_UPDATE_ID()++;
}

void zdo_system_server_discovery_res(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body;
    zb_uint8_t tsn;
    zb_uint16_t server_mask;
    zb_zdo_system_server_discovery_resp_t *resp;
    zb_apsde_data_indication_t *ind;

    TRACE_MSG(TRACE_ZDO3, ">>zdo_system_server_discovery_res %hd",
              (FMT__H, param));

    aps_body = ZB_BUF_BEGIN(ZB_BUF_FROM_REF(param));
    ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);
    tsn = *aps_body;
    aps_body++;

    ZB_LETOH16(&server_mask, aps_body);

    TRACE_MSG(TRACE_ZDO3, "param server_mask %x, desc server_mask %x",
              (FMT__D_D, server_mask, ZB_ZDO_NODE_DESC()->server_mask));
    server_mask &= ZB_ZDO_NODE_DESC()->server_mask;
    if (server_mask) {
        TRACE_MSG(TRACE_ZDO3, "send response mask %x", (FMT__D, server_mask));
        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zdo_system_server_discovery_resp_t),
                             resp);
        resp->status = ZB_ZDP_STATUS_SUCCESS;
        ZB_HTOLE16(&resp->server_mask, &server_mask);
        TRACE_MSG(TRACE_ZDO3, "send response addr %x", (FMT__D, ind->src_addr));
        zdo_send_resp_by_short(ZDO_SYSTEM_SERVER_DISCOVERY_RESP_CLID, param,
                               tsn, ind->src_addr);
    }
    else {
        zb_free_buf(buf);
    }
    TRACE_MSG(TRACE_ZDO3, "<<zdo_system_server_discovery_res", (FMT__0));
}

void zb_zdo_mgmt_nwk_leave_res(zb_uint8_t param, zb_callback_t cb)
{
    TRACE_MSG(TRACE_ZDO3, ">>zb_zdo_mgmt_nwk_leave_req param %hd",
              (FMT__D, param));
    if (cb != NULL) {
        ZB_SCHEDULE_CALLBACK(cb, param);
    }

}

void zdo_lqi_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body;
    zb_uint8_t tsn;
    zb_zdo_mgmt_lqi_resp_t *resp;
    zb_apsde_data_indication_t *ind;

#ifdef ZB_ROUTER_ROLE
    zb_zdo_mgmt_lqi_req_t *req;
    zb_ushort_t i;
    zb_zdo_neighbor_table_record_t *record;
    zb_uint8_t max_records_num;
    zb_uint8_t records_num;
#endif

    TRACE_MSG(TRACE_ZDO3, ">>zdo_lqi_resp %hd", (FMT__H, param));

    aps_body = ZB_BUF_BEGIN(buf);
    ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);
    tsn = *aps_body;
    aps_body++;

#ifdef ZB_ROUTER_ROLE
    req = (zb_zdo_mgmt_lqi_req_t *)aps_body;
    /* calculate total header size */
    i = ZB_APS_HDR_SIZE(ZB_APS_FRAME_DATA)
#ifdef ZB_SECURITY
        + sizeof(zb_aps_nwk_aux_frame_hdr_t)
#endif
        + ZB_NWK_FULL_HDR_SIZE(1) + ZB_MAC_MAX_HEADER_SIZE(1, 1)
        + sizeof(zb_zdo_mgmt_lqi_resp_t) + ZB_TAIL_SIZE_FOR_SENDER_MAC_FRAME;
    max_records_num = ZB_IO_BUF_SIZE / i;

    records_num = (ZG->nwk.neighbor.base_neighbor_used > req->start_index) ?
                  ZG->nwk.neighbor.base_neighbor_used - req->start_index : 0;
    TRACE_MSG(TRACE_ZDO3, "max rec %hd, used %hd, start indx %hd",
              (FMT__H_H_H, max_records_num, ZG->nwk.neighbor.base_neighbor_used,
               req->start_index));

    records_num =
        (records_num < max_records_num) ? records_num : max_records_num;

    ZB_BUF_INITIAL_ALLOC(buf,
                         sizeof(zb_zdo_mgmt_lqi_resp_t) + records_num *
                         sizeof(zb_zdo_neighbor_table_record_t), resp);

    resp->status = ZB_ZDP_STATUS_SUCCESS;
    resp->neighbor_table_entries = ZG->nwk.neighbor.base_neighbor_used;
    resp->start_index = req->start_index;
    resp->neighbor_table_list_count = records_num;
    record = (zb_zdo_neighbor_table_record_t *)(resp + 1);

    TRACE_MSG(TRACE_ZDO3, "will add records %hd", (FMT__H, records_num));
    for (i = 0; i < ZG->nwk.neighbor.base_neighbor_size && records_num; ++i) {
        if (ZG->nwk.neighbor.base_neighbor[i].used) {
            ZB_MEMCPY(record->ext_pan_id, ZB_NIB_EXT_PAN_ID(),
                      sizeof(zb_ext_pan_id_t));
            zb_address_by_ref(record->ext_addr, &record->network_addr,
                              ZG->nwk.neighbor.base_neighbor[i].addr_ref);

            ZB_ZDO_RECORD_SET_DEVICE_TYPE(record->type_flags,
                                          ZG->nwk.neighbor.base_neighbor[i].device_type);
            ZB_ZDO_RECORD_SET_RX_ON_WHEN_IDLE(record->type_flags,
                                              ZG->nwk.neighbor.base_neighbor[i].rx_on_when_idle);
            ZB_ZDO_RECORD_SET_RELATIONSHIP(record->type_flags,
                                           ZG->nwk.neighbor.base_neighbor[i].relationship);
            record->permit_join =
                ZG->nwk.neighbor.base_neighbor[i].permit_joining;
            record->depth = ZG->nwk.neighbor.base_neighbor[i].depth;
            record->lqi = ZG->nwk.neighbor.base_neighbor[i].lqi;
            records_num--;
            record++;
        }
    }

#else
    /* end device case */
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zdo_mgmt_lqi_resp_t), resp);
    ZB_BZERO(resp, sizeof(zb_zdo_mgmt_lqi_resp_t));
    resp->status = ZB_ZDP_STATUS_NOT_SUPPORTED;
#endif

    zdo_send_resp_by_short(ZDO_MGMT_LQI_RESP_CLID, param, tsn, ind->src_addr);

    TRACE_MSG(TRACE_ZDO3, "<< zdo_lqi_resp", (FMT__0));
}

void zdo_zll_scan_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_zll_scan_resp %hd", (FMT__H, param));

    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body = ZB_BUF_BEGIN(buf);

    uint8_t lqi = ZB_MAC_GET_LQI(buf);
    int8_t rssi = ZB_MAC_GET_RSSI(buf);
    printf("received scan request (LQI: %u RSSI: %i)\n", lqi, rssi);

    /* only answer scan requests that are nearby */
    if (rssi < -60) {
        zb_free_buf(buf);
        return;
    }

    zb_apsde_data_indication_t *ind = ZB_GET_BUF_PARAM(buf,
                                                       zb_apsde_data_indication_t);

    zb_uint8_t fcf = *aps_body++;
    zb_uint8_t sequence_number = *aps_body++;
    zb_uint8_t command = *aps_body++;

    zb_uint32_t transaction_id;
    ZB_LETOH32(&transaction_id, aps_body);

    TRACE_MSG(TRACE_ZDO3, "fcf 0x%x", (FMT__D, fcf));
    TRACE_MSG(TRACE_ZDO3, "sequence_number %u", (FMT__D, sequence_number));
    TRACE_MSG(TRACE_ZDO3, "transaction_id 0x%08lx", (FMT__D, transaction_id));

    /* get long source address from mac header */
    zb_mac_mhr_t mac_hdr;
    zb_parse_mhr(&mac_hdr, buf->buf + buf->u.hdr.mac_hdr_offset);

//     zb_nlde_data_req_t nldereq;
//     nldereq.addr_mode = ZB_ADDR_64BIT_DEV;
//     nldereq.nonmember_radius = 0;
//     nldereq.discovery_route = 0;
//     nldereq.security_enable = 0;
//     nldereq.ndsu_handle = 0;
//
//     ZB_MEMCPY(
//         ZB_GET_BUF_TAIL(buf, sizeof(zb_nlde_data_req_t)),
//               &nldereq, sizeof(nldereq));

    zb_zdo_zll_scan_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zdo_zll_scan_resp_t), resp);
    ZB_BZERO(resp, sizeof(zb_zdo_zll_scan_resp_t));

    resp->zcl_command = 1;                  /* scan response */
    resp->transaction_id = transaction_id;
    resp->rssi_correction = 0x0;            /* maximum correction is 0x20 */
    resp->zigbee_information = 0x1 | 0x4;   /* router | rx_on_when_idle */
//     resp->touchlink_information = 0x1; /* factory new */
    resp->touchlink_information = 0x0;      /* not factory new */
    resp->key_bitmask = 0x10;               /* master key */
    resp->response_id = 0x55555555;
    ZB_IEEE_ADDR_COPY(resp->extended_pan_id, ZB_PIB_EXTENDED_ADDRESS());
    resp->network_update_id = 0;
    resp->logical_channel = zb_transceiver_get_channel();
//     resp->pan_id = ZB_PIB_SHORT_PAN_ID();
    resp->pan_id = 0x356b;
//     resp->network_address = ZB_PIB_SHORT_ADDRESS();
    resp->network_address = 0xffff;
    resp->subdevices = 2;
    resp->total_group_identifiers = 0;
    // resp->endpoint = 1;
    // resp->profile_id = 0xc05e;
    // resp->device_id = 0x200;
    // resp->version = 2;
    // resp->group_id_count = 0;

    zb_uint16_t custer_id = 0x1000; /* FIXME ZLL */

    zdo_send_resp_by_long(custer_id, param, ZDO_CTX().tsn++,
                          mac_hdr.src_addr.addr_long);

    TRACE_MSG(TRACE_ZDO3, "<< zdo_zll_scan_resp", (FMT__0));
}

static zb_uint8_t _tl_info;
static zb_uint8_t _zb_info;
static zb_uint32_t _transaction_id;
static zb_uint32_t _response_id;
static zb_ieee_addr_t _opponent_addr;
static zb_uint8_t _opponent_ep;
static zb_address_pan_id_ref_t _opponent_pan_ref;

typedef struct __attribute__((packed)) {
    zb_uint8_t fcf;
    zb_uint8_t seq;
    zb_uint8_t cmd;
    zb_uint32_t transaction_id;
    zb_uint8_t zigbee_information;
    zb_uint8_t touchlink_information;
} zb_zll_touchlink_scan_req_t;

typedef struct __attribute__((packed)) {
    zb_uint8_t fcf;
    zb_uint8_t seq;
    zb_uint8_t cmd;
    uint32_t transaction_id;
    zb_ieee_addr_t ext_pan_id;
    zb_uint8_t key_index;
    zb_uint8_t enc_network_key[16];
    zb_uint8_t channel;
    zb_uint16_t pan_id;
    zb_uint16_t network_address;
    zb_uint16_t group_id_begin;
    zb_uint16_t group_id_end;
    zb_uint16_t free_addr_begin;
    zb_uint16_t free_addr_end;
    zb_uint16_t free_group_begin;
    zb_uint16_t free_group_end;
    zb_ieee_addr_t initiator_addr;
    zb_uint16_t initiator_net_addr;

} zb_zll_touchlink_start_net_req_t;

typedef struct __attribute__((packed)) {
    zb_uint8_t fcf;
    zb_uint8_t seq;
    zb_uint8_t cmd;
    zb_uint32_t transaction_id;
    zb_uint8_t start_index;
} zb_zll_touchlink_dev_info_req_t;

void set_zb_info()
{
    zb_nwk_set_device_type(ZB_NWK_DEVICE_TYPE_COORDINATOR);
    _zb_info = (zb_uint8_t) 0;
    switch(ZB_NIB_DEVICE_TYPE()){
        case ZB_NWK_DEVICE_TYPE_COORDINATOR:
            _zb_info = 0x0;
            break;
        case ZB_NWK_DEVICE_TYPE_ROUTER:
            _zb_info = 0x1; 
            break;
        case ZB_NWK_DEVICE_TYPE_ED:
            _zb_info = 0x2;
            break;
        default:
            _zb_info = 0x2;
            break;
    }
    _zb_info |= (0x1 & ZB_PIB_RX_ON_WHEN_IDLE()) << 2;
}

void set_tl_info(zb_bool_t new, zb_bool_t addr_ass, zb_bool_t initiator)
{
    _tl_info = (zb_uint8_t) 0;
    if(new) _tl_info = 0x1;
    if(addr_ass) _tl_info |= 0x2;
    if(initiator) _tl_info |= 0x10;
    //Profile interop. = ZB 3.0
    _tl_info |= 0x80;

}

void get_enc_network_key(zb_uint8_t* enc_network_key)
{
    zb_uint8_t zll_master_key[16] =
    { 0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57, 0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B,
      0xC9, 0x3F, 0xEE, 0x31 };

    zb_uint8_t nonce[16];
    nonce[3] = (_transaction_id) & 0xff;
    nonce[2] = (_transaction_id >> 8) & 0xff;
    nonce[1] = (_transaction_id >> 16) & 0xff;
    nonce[0] = (_transaction_id >> 24) & 0xff;
    memcpy(nonce + 4, nonce + 0, 4);
    
    nonce[11] = (_response_id) & 0xff;
    nonce[10] = (_response_id >> 8) & 0xff;
    nonce[9]  = (_response_id >> 16) & 0xff;
    nonce[8]  = (_response_id >> 24) & 0xff;
    memcpy(nonce + 12, nonce + 8, 4);

    /* encrypt the network key */
    zb_uint8_t exchange_key[16];
    aes128(zll_master_key, nonce, exchange_key);
    aes128(exchange_key, ZG->nwk.nib.secur_material_set[0].key, enc_network_key);

    zb_uint8_t key[33];
    zb_pretty_key(key, sizeof(key), enc_network_key);
    printf("encrypted network key: %s\n", key);
    zb_pretty_key(key, sizeof(key), zll_master_key);
    printf("ZLL master key: %s\n", key);
    zb_pretty_key(key, sizeof(key), nonce);
    printf("nonce: %s\n", key);
    zb_pretty_key(key, sizeof(key), exchange_key);
    printf("exchange key: %s\n", key);
    zb_pretty_key(key, sizeof(key), ZG->nwk.nib.secur_material_set[0].key);
    printf("decrypted network key: %s\n", key);
}

void zb_mac_get_indirect_data_req(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_mlme_data_req_params_t req;
    req.src_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
    req.dst_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
    req.src_addr.addr_short = 1;
    req.dst_addr.addr_short = 4;
    req.cb_type = MAC_POLL_REQUEST_CALLBACK;
    zb_mac_get_indirect_data(&req);
}

void zdo_zll_dev_info_req(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_dev_info_req %hd", (FMT__H, param));
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
   
    zb_uint8_t *ptr = NULL;
    zb_zll_touchlink_dev_info_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_touchlink_dev_info_req_t), ptr);
    req = (zb_zll_touchlink_dev_info_req_t *)ptr;

    req->fcf = 0x11; //Cluster specific, disable default response
    //seq num: not the same as nwk, and we do not have access to zcl_seq found in zcl_groups
    req->seq = ZDO_CTX().tsn;//ZB_NIB_SEQUENCE_NUMBER() + 5;
    req->cmd = 0x02; //dev info request
    req->transaction_id = _transaction_id;
    req->start_index = 0; // needs to be determined from internal state
    
    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = 0x1000; //ZLL Commissioning
    intrp->profileid = 0xc05e; //ZLL
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, _opponent_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, ZB_REF_FROM_BUF(buf));
    
    TRACE_MSG(TRACE_ZDO3, "<< zdo_dev_info_req", (FMT__0));
}

void zdo_zll_touchlink_scan() ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_zll_scan_req %hd", (FMT__H, param));
    zb_buf_t *buf = zb_get_out_buf();

    set_zb_info();
    // fac. new, addr ass = 1, not initiator
    set_tl_info(ZB_TRUE, ZB_TRUE, ZB_TRUE);

    zb_uint8_t *ptr = NULL;
    zb_zll_touchlink_scan_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_touchlink_scan_req_t), ptr);
    req = (zb_zll_touchlink_scan_req_t *)ptr;
    ZDO_CTX().tsn++;
    req->fcf = 0x11; //Cluster specific, disable default response
    //seq num: not the same as nwk, and we do not have access to zcl_seq found in zcl_groups
    req->seq = ZDO_CTX().tsn;//ZB_NIB_SEQUENCE_NUMBER() + 5;
    req->cmd = 0x00; //scan request
    _transaction_id = 0x12345678; // should be random
    req->transaction_id = _transaction_id;
    req->zigbee_information = _zb_info;
    req->touchlink_information = _tl_info;

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = 0x1000; //ZLL Commissioning
    intrp->profileid = 0xc05e; //ZLL
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
    intrp->dst_addr.addr_short = 0xffff;
    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, ZB_REF_FROM_BUF(buf));

    TRACE_MSG(TRACE_ZDO3, "<< zdo_zll_scan_q", (FMT__0));
}

void zdo_zll_start_net_req(param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_start_net_req %hd", (FMT__H, param));
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
   
    zb_uint8_t *ptr = NULL;
    zb_zll_touchlink_start_net_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_touchlink_start_net_req_t), ptr);
    req = (zb_zll_touchlink_start_net_req_t *)ptr;

    req->fcf = 0x11; //Cluster specific, disable default response
    //seq num: not the same as nwk, and we do not have access to zcl_seq found in zcl_groups
    req->seq = ZDO_CTX().tsn;//ZB_NIB_SEQUENCE_NUMBER() + 5;
    req->cmd = 0x10; //start net request
    req->transaction_id = _transaction_id;
    //set it to zero; opponent has to choose
    ZB_IEEE_ADDR_ZERO(&req->ext_pan_id);

    req->key_index = 4; /* master key */
    zb_uint8_t enc_key[16];
    get_enc_network_key(enc_key);
    ZB_MEMCPY(&req->enc_network_key, &enc_key, sizeof(enc_key));

    // TODO: set this dynamically
    req->channel = zb_transceiver_get_channel();
    req->pan_id = 0x0000;
    req->network_address = 4;
    req->group_id_begin = 0;
    req->group_id_end= 0;
    req->free_addr_begin = 0x7ffc;
    req->free_addr_end = 0xfff7;
    req->free_group_begin = 0x7f80;
    req->free_group_end = 0xfeff;
    ZB_IEEE_ADDR_COPY(req->initiator_addr, ZB_PIB_EXTENDED_ADDRESS());
    req->initiator_net_addr = 1;
    
    ZB_PIB_SHORT_ADDRESS() = 0x0001;
    zb_transceiver_update_short_addr(0x0001);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = 0x1000; //ZLL Commissioning
    intrp->profileid = 0xc05e; //ZLL
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, _opponent_addr);
    
    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, ZB_REF_FROM_BUF(buf));
    TRACE_MSG(TRACE_ZDO3, "<< zdo_start_net_req", (FMT__0));
}

void zdo_zll_handle_dev_info_resp(zb_uint8_t param)
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_handle_dev_info_resp %hd", (FMT__H, param));
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);

    ptr++; //fcf
    ptr++; //snum
    
    zb_zdo_zll_dev_info_resp_t *resp = (zb_zdo_zll_dev_info_resp_t *)ptr;
    ptr += sizeof(zb_zdo_zll_dev_info_resp_t);
    zb_zdo_zll_dev_record_t *record;
    _opponent_ep = 1;
    for(zb_uint8_t i = 0; i < resp->count; i++){
        record = (zb_zdo_zll_dev_record_t *)ptr;
        if(record->profileid == 0x104){ // found ha profile
            _opponent_ep = record->endpoint;
        }
        ptr += sizeof(zb_zdo_zll_dev_record_t);
    }
    ZB_GET_OUT_BUF_DELAYED(zdo_zll_start_net_req);
    TRACE_MSG(TRACE_ZDO3, "<< zdo_handle_dev_info_resp", (FMT__0));
}

void zdo_zll_identify_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body = ZB_BUF_BEGIN(buf);

    zb_uint8_t fcf = *aps_body++;
    zb_uint8_t sequence_number = *aps_body++;
    zb_uint8_t command = *aps_body++;
    zb_uint32_t transaction_id;

    ZB_LETOH32(&transaction_id, aps_body);
    aps_body += 4;
    zb_uint16_t identify_duration;
    ZB_LETOH16(&identify_duration, aps_body);
    aps_body += 2;

    extern void zb_identify(int);
    zb_identify(identify_duration);
}

typedef struct __attribute__((packed)) {
    uint8_t fcf;
    uint8_t seq;
    uint8_t cmd;
    uint32_t transaction_id;
    zb_ieee_addr_t ext_pan_id;
    uint8_t key_index;
    uint8_t enc_network_key[16];
    uint8_t channel;
    uint16_t pan_id;
    uint16_t network_address;
    uint16_t group_id_begin;
    uint16_t group_id_end;
    uint16_t free_addr_begin;
    uint16_t free_addr_end;
    uint16_t free_group_begin;
    uint16_t free_group_end;
    zb_ieee_addr_t initator_ext_address;
    uint16_t initiator_network_address;
} zb_zll_start_network_request_t;

typedef  struct __attribute__((packed)) {
//     uint8_t fcf;
//     uint8_t seq;
    uint8_t cmd;
    uint32_t transaction_id;
    uint8_t status;
    zb_ieee_addr_t ext_pan_id;
    uint8_t network_update_id;
    uint8_t logical_channel;
    uint16_t pan_id;
} zb_zll_start_network_response_t;


static uint8_t _new_channel;

void change_channel(zb_uint8_t param)
{
    uint8_t channel = _new_channel;
    zb_transceiver_set_channel(channel);

    zb_free_buf(ZB_BUF_FROM_REF(param));
}

void zdo_zll_handle_scan_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_handle_tl_scan_resp %hd", (FMT__H, param));
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_mac_mhr_t mac_hdr;
    zb_parse_mhr(&mac_hdr, buf->buf + buf->u.hdr.mac_hdr_offset);
    ZB_IEEE_ADDR_COPY(_opponent_addr, mac_hdr.src_addr.addr_long);
    
    //scan_resp starts at ZCL FCF | SeqN | CMD | 4Byte Transaction ID
    zb_uint8_t *resp_ptr = ZB_BUF_BEGIN(buf);
    resp_ptr ++;//skip fcf
    resp_ptr ++;//skip seq number
    zb_zdo_zll_scan_resp_t *resp = (zb_zdo_zll_scan_resp_t *)resp_ptr;

    uint8_t tsn = ZDO_CTX().tsn++;
    if(resp->logical_channel != zb_transceiver_get_channel()) {
        printf("changing channel to %u", resp->logical_channel);
        _new_channel = resp->logical_channel;
        register_zdo_cb(tsn, change_channel, 1);
    }
    // adding opponent to neighbor tables
    zb_nwk_exneighbor_start();
    zb_address_set_pan_id(resp->pan_id, resp->extended_pan_id, &_opponent_pan_ref);
    zb_ext_neighbor_tbl_ent_t *nent;
    zb_nwk_exneighbor_by_short(_opponent_pan_ref, resp->network_address , &nent);
    
    nent->potential_parent = 1;
    nent->lqi = 240; // gets set internally - very good
    nent->update_id = ZB_NIB_UPDATE_ID();
    nent->logical_channel = resp->logical_channel;
    nent->stack_profile = 1;
    nent->permit_joining = 1;
    nent->router_capacity = 1;
    nent->end_device_capacity = 1;
    nent->potential_parent = 1;

    ZB_MEMCPY(&_response_id, &resp->response_id, sizeof(zb_uint32_t));

    if(resp->subdevices == 1){
        resp_ptr += sizeof(zb_zdo_zll_scan_resp_t);
        zb_zdo_zll_scan_resp_ext_t *ext_resp = (zb_zdo_zll_scan_resp_ext_t *)resp_ptr;
        _opponent_ep = ext_resp->endpoint;
        ZB_GET_OUT_BUF_DELAYED(zdo_zll_start_net_req);
    }else{
        _opponent_ep = 1;
        ZB_GET_OUT_BUF_DELAYED(zdo_zll_dev_info_req);
    }

    zb_free_buf(buf);
    TRACE_MSG(TRACE_ZDO3, "<<zdo_handle_tl_scan_resp", (FMT__0));
}

void zdo_zll_handle_start_network_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_handle_start_net_resp %hd", (FMT__H, param));

    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr =  ZB_BUF_BEGIN(buf);
    ptr += 2; //skip fcf and seq
    zb_zll_start_network_response_t *resp = (zb_zll_start_network_response_t *)ptr;
    if(resp->status != 0){
        puts("Target failed to start network");
        return;
    }
    if(resp->logical_channel != zb_transceiver_get_channel()) {
        uint8_t tsn = ZDO_CTX().tsn++;
        printf("changing channel to %u", resp->logical_channel);
        _new_channel = resp->logical_channel;
        register_zdo_cb(tsn, change_channel, 1);
    }
    if(!ZB_IEEE_ADDR_CMP(resp->ext_pan_id, ZB_AIB().aps_use_extended_pan_id)){
        ZB_IEEE_ADDR_COPY(&ZB_AIB().aps_use_extended_pan_id, resp->ext_pan_id);
    }
    if(resp->pan_id != ZB_PIB_SHORT_PAN_ID()){
        ZB_PIB_SHORT_PAN_ID() = resp->pan_id;
        zb_transceiver_set_pan_id(resp->pan_id);
    }
    ZG->nwk.nib.outgoing_frame_counter = 0;

    zb_nwk_neighbor_clear();
    zb_nwk_exneighbor_start();

    zb_address_ieee_ref_t addr_ref;
    zb_ieee_addr_t zeros;
    ZB_IEEE_ADDR_ZERO(zeros);
    zb_address_update(zeros, 4, ZB_FALSE, &addr_ref);

    zb_neighbor_tbl_ent_t *ne;
    zb_nwk_neighbor_get(addr_ref, ZB_TRUE, &ne);
    ne->rx_on_when_idle = 1;

    zb_address_pan_id_ref_t pan_ref;
    zb_address_set_pan_id(ZB_PIB_SHORT_PAN_ID(), ZB_AIB().aps_use_extended_pan_id, &pan_ref);

    zb_ext_neighbor_tbl_ent_t *nent;
    zb_nwk_exneighbor_by_ieee(pan_ref, _opponent_addr, &nent);
    nent->potential_parent = 1;
    nent->short_addr = 4;
    ZB_IEEE_ADDR_ZERO(&nent->long_addr);
    nent->update_id = ZB_NIB_UPDATE_ID();
    nent->logical_channel = resp->logical_channel;
    nent->stack_profile = 1;
    nent->permit_joining = 1;
    nent->router_capacity = 1;
    nent->end_device_capacity = 1;
    nent->potential_parent = 1;

    ZG->nwk.nib.security_level = 5;

    ZB_BUF_REUSE(buf);
    
    ZG->nwk.nib.outgoing_frame_counter = -1;

    zb_nlme_join_request_t *request = ZB_GET_BUF_PARAM(buf, zb_nlme_join_request_t);
    ZB_IEEE_ADDR_COPY(request->extended_pan_id, ZB_AIB().aps_use_extended_pan_id);
    request->scan_channels = 0x00000000;
    request->capability_information = 0x80; // as seen on wireshark
    request->rejoin_network = ZB_NLME_REJOIN_METHOD_REJOIN;//zb_nlme_rejoin_method
    request->scan_duration = 0x00;
    request->security_enabled = ZB_TRUE;
    ZB_SCHEDULE_ALARM(zb_nlme_join_request, ZB_REF_FROM_BUF(buf), ZB_MILLISECONDS_TO_BEACON_INTERVAL(4000));

    
    ZB_SCHEDULE_ALARM(zb_mac_get_indirect_data_req, 0, ZB_MILLISECONDS_TO_BEACON_INTERVAL(4100));

    zb_address_by_short(4, ZB_TRUE, ZB_FALSE, &ZG->nwk.handle.parent);
    TRACE_MSG(TRACE_ZDO3, "<< zdo_handle_start_net_resp", (FMT__0));
}

void zcl_onoff_toggle()
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_toggle_opponent %hd", (FMT__H, param));

    zb_buf_t *buf = zb_get_out_buf();
    zb_uint8_t *ptr;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zcl_hdr_t), ptr);
    zcl_hdr_t *req;
    req = (zcl_hdr_t *)ptr;

    req->fcf = 0x01; //cluster specific
    req->sequence_number = ZDO_CTX().tsn;
    req->cmd = 0x02; // toggles
    zb_apsde_data_req_t *dreq = ZB_GET_BUF_TAIL(buf,
                                            sizeof(zb_apsde_data_req_t));
    ZB_BZERO(dreq, sizeof(*dreq));
    dreq->dst_addr = 0x4;
    dreq->dst_endpoint = _opponent_ep;
    dreq->src_endpoint = 1;
    dreq->clusterid = 6;
    dreq->profileid = 0x0104;
    dreq->tx_options = 3;
    dreq->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;

    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, ZB_REF_FROM_BUF(buf));

    TRACE_MSG(TRACE_ZDO3, "<< zdo_toggle_opponent", (FMT__0));
    
}

void zdo_zll_start_network_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_buf_t *zbbuf = ZB_BUF_FROM_REF(param);

    zb_uint8_t *aps_body = ZB_BUF_BEGIN(zbbuf);
    zb_zll_start_network_request_t *req =
                                    (zb_zll_start_network_request_t *)aps_body;

    _new_channel = req->channel;

    zb_uint32_t transaction_id;
    ZB_LETOH32(&transaction_id, &req->transaction_id);

    zb_uint8_t enc_network_key[16];
    ZB_MEMCPY(enc_network_key, req->enc_network_key, 16);

    zb_ieee_addr_t initiator_addr;
    ZB_IEEE_ADDR_COPY(initiator_addr, req->initator_ext_address);

    zb_ieee_addr_t ext_pan_id;
    ZB_IEEE_ADDR_COPY(ext_pan_id, req->ext_pan_id);
    if (ZB_IEEE_ADDR_IS_ZERO(ext_pan_id)) {
        ZB_IEEE_ADDR_COPY(ext_pan_id, ZB_PIB_EXTENDED_ADDRESS());
    }

    uint16_t pan_id;
    ZB_LETOH16(&pan_id, &req->pan_id);
    if (pan_id == 0x0000) {
        pan_id = ZB_RANDOM();
//         pan_id = 0x0023;

        ZB_PIB_SHORT_PAN_ID() = pan_id;
        zb_transceiver_set_pan_id(pan_id);
    }

    printf("transaction_id: 0x%08lx\n", transaction_id);

    zb_uint8_t zll_master_key[16] =
    { 0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57, 0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B,
      0xC9, 0x3F, 0xEE, 0x31 };

    zb_uint8_t nonce[16];
    nonce[3] = (transaction_id) & 0xff;
    nonce[2] = (transaction_id >> 8) & 0xff;
    nonce[1] = (transaction_id >> 16) & 0xff;
    nonce[0] = (transaction_id >> 24) & 0xff;
    memcpy(nonce + 4, nonce, 4);

    uint32_t response_id = 0x55555555; /* FIXME should be random */
    ZB_MEMCPY(nonce + 8, &response_id, 4);
    ZB_MEMCPY(nonce + 12, &response_id, 4);

    /* decrypt the network key */
    zb_uint8_t exchange_key[16];
    aes128(zll_master_key, nonce, exchange_key);
    zb_uint8_t network_key[16];
    aes128d(enc_network_key, exchange_key, network_key);

    zb_uint8_t key[33];
    zb_pretty_key(key, sizeof(key), enc_network_key);
    printf("encrypted network key: %s\n", key);
    zb_pretty_key(key, sizeof(key), zll_master_key);
    printf("ZLL master key: %s\n", key);
    zb_pretty_key(key, sizeof(key), nonce);
    printf("nonce: %s\n", key);
    zb_pretty_key(key, sizeof(key), exchange_key);
    printf("exchange key: %s\n", key);
    zb_pretty_key(key, sizeof(key), network_key);
    printf("decrypted network key: %s\n", key);

    ZB_HTOLE16(&ZB_PIB_SHORT_ADDRESS(), &req->network_address);
    printf("short address: 0x%04x\n", ZB_PIB_SHORT_ADDRESS());
    zb_transceiver_update_short_addr(ZB_PIB_SHORT_ADDRESS());

    ZB_PIB_SHORT_PAN_ID() = pan_id;
    zb_transceiver_set_pan_id(pan_id);

    ZB_EXTPANID_COPY(ZG->nwk.nib.extended_pan_id, ext_pan_id);
    ZB_EXTPANID_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, ext_pan_id);
    ZB_EXTPANID_COPY(ZB_AIB().aps_use_extended_pan_id, ext_pan_id);

//     zb_schedule_alarm(change_channel, channel, 1);
//     zb_transceiver_set_channel(channel);
    uint8_t tsn = ZDO_CTX().tsn++;
    register_zdo_cb(tsn, change_channel, 1);

    printf("save parameters to nonvolatile storage\n");
    /* save parameters in nonvolatile storage */
    zb_secur_setup_preconfigured_key(network_key, 0);
    printf("zb_write_security_key\n");
    zb_write_security_key();
    printf("zb_save_nvram_config\n");
    zb_save_nvram_config();
    printf("zb_save_formdesc_data\n");
    zb_save_formdesc_data();



    zb_zll_start_network_response_t *resp;
    ZB_BUF_INITIAL_ALLOC(zbbuf, sizeof(zb_zll_start_network_response_t), resp);
    ZB_BZERO(resp, sizeof(zb_zll_start_network_response_t));

//     resp->fcf = 0x19;
//     resp->seq = 7;
    resp->cmd = 0x11;
    ZB_HTOLE32(&resp->transaction_id, &transaction_id);
    resp->status = 0x00;
    resp->network_update_id = 0;
    resp->logical_channel = _new_channel;

    ZB_HTOLE16(&resp->pan_id, &pan_id);
    ZB_IEEE_ADDR_COPY(resp->ext_pan_id, ext_pan_id);

    zb_uint16_t cluster_id = 0x1000;

    zdo_send_resp_by_long(cluster_id, param, tsn, initiator_addr);
}

void zdo_zll_join_router_resp(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    TRACE_MSG(TRACE_ZDO3, ">>zdo_zll_join_router_resp %hd", (FMT__H, param));

    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body = ZB_BUF_BEGIN(buf);

    zb_uint8_t fcf = *aps_body++;
    zb_uint8_t sequence_number = *aps_body++;
    zb_uint8_t command = *aps_body++;

    zb_uint32_t transaction_id;
    ZB_LETOH32(&transaction_id, aps_body);
    aps_body += 4;

    zb_ieee_addr_t extended_pan_id;
    ZB_IEEE_ADDR_COPY(extended_pan_id, (zb_ieee_addr_t *)aps_body);
    aps_body += 8;

    zb_uint8_t key_index = *aps_body++;
    zb_uint8_t encrypted_network_key[16];
    ZB_MEMCPY(encrypted_network_key, aps_body, 16);
    aps_body += 16;

    zb_uint8_t network_update_id = *aps_body++;
    zb_uint8_t logical_channel = *aps_body++;

    zb_uint16_t pan_id;
    ZB_LETOH16(&pan_id, aps_body);
    aps_body += 2;

    zb_uint16_t network_address;
    ZB_LETOH16(&network_address, aps_body);
    aps_body += 2;

    zb_uint16_t group_id_begin;
    ZB_LETOH16(&group_id_begin, aps_body);
    aps_body += 2;

    zb_uint16_t group_id_end;
    ZB_LETOH16(&group_id_end, aps_body);
    aps_body += 2;

    zb_uint16_t free_address_range_begin;
    ZB_LETOH16(&free_address_range_begin, aps_body);
    aps_body += 2;

    zb_uint16_t free_address_range_end;
    ZB_LETOH16(&free_address_range_end, aps_body);
    aps_body += 2;

    zb_uint16_t free_group_id_range_begin;
    ZB_LETOH16(&free_group_id_range_begin, aps_body);
    aps_body += 2;

    zb_uint16_t free_group_id_range_end;
    ZB_LETOH16(&free_group_id_range_end, aps_body);
    aps_body += 2;

    /* get long source address from mac header */
    zb_mac_mhr_t mac_hdr;
    zb_parse_mhr(&mac_hdr, buf->buf + buf->u.hdr.mac_hdr_offset);
    zb_ieee_addr_t initiator_addr;
    ZB_IEEE_ADDR_COPY(initiator_addr, mac_hdr.src_addr.addr_long);

    zb_uint8_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, 6, resp);
    ZB_BZERO(resp, 6);

    *resp++ = 0x13; /* join router response */
    ZB_HTOLE32(resp, &transaction_id);
    resp += 4;
    *resp = 0x0; /* success status */

    printf("transaction_id: 0x%08lx\n", transaction_id);

    zb_uint8_t zll_master_key[16] =
    { 0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57, 0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B,
      0xC9, 0x3F, 0xEE, 0x31 };

    zb_uint8_t nonce[16];
    nonce[3] = (transaction_id) & 0xff;
    nonce[2] = (transaction_id >> 8) & 0xff;
    nonce[1] = (transaction_id >> 16) & 0xff;
    nonce[0] = (transaction_id >> 24) & 0xff;
    memcpy(nonce + 4, nonce, 4);

    uint32_t response_id = 0x55555555; /* FIXME should be random */
    ZB_MEMCPY(nonce + 8, &response_id, 4);
    ZB_MEMCPY(nonce + 12, &response_id, 4);

    /* decrypt the network key */
    zb_uint8_t exchange_key[16];
    aes128(zll_master_key, nonce, exchange_key);
    zb_uint8_t network_key[16];
    aes128d(encrypted_network_key, exchange_key, network_key);

    zb_uint8_t key[33];
    zb_pretty_key(key, sizeof(key), encrypted_network_key);
    printf("encrypted network key: %s\n", key);
    zb_pretty_key(key, sizeof(key), zll_master_key);
    printf("ZLL master key: %s\n", key);
    zb_pretty_key(key, sizeof(key), nonce);
    printf("nonce: %s\n", key);
    zb_pretty_key(key, sizeof(key), exchange_key);
    printf("exchange key: %s\n", key);
    zb_pretty_key(key, sizeof(key), network_key);
    printf("decrypted network key: %s\n", key);

    printf("short address: 0x%04x\n", network_address);
    ZB_PIB_SHORT_ADDRESS() = network_address;
    zb_transceiver_update_short_addr(network_address);

    ZB_PIB_SHORT_PAN_ID() = pan_id;
    zb_transceiver_set_pan_id(pan_id);

    ZB_EXTPANID_COPY(ZG->nwk.nib.extended_pan_id, extended_pan_id);
    ZB_EXTPANID_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, extended_pan_id);
    ZB_EXTPANID_COPY(ZB_AIB().aps_use_extended_pan_id, extended_pan_id);

    _new_channel = logical_channel;
//     zb_transceiver_set_channel(logical_channel);
//     zb_schedule_alarm(change_channel, logical_channel, 5);
    uint8_t tsn = ZDO_CTX().tsn++;
    register_zdo_cb(tsn, change_channel, 1);

//     ZG->nwk.handle.joined = 1;
//     ZG->nwk.nib.device_type = ZB_NWK_DEVICE_TYPE_ROUTER;
//     ZG->nwk.handle.is_tc = 1;
//     ZG->aps.authenticated = 1;
//     ZG->nwk.handle.router_started = 1;
//
//     zb_nwk_update_beacon_payload();

    printf("save parameters to nonvolatile storage\n");
    /* save parameters in nonvolatile storage */
    zb_secur_setup_preconfigured_key(network_key, 0);
    printf("zb_write_security_key\n");
    zb_write_security_key();
    printf("zb_save_nvram_config\n");
    zb_save_nvram_config();
    printf("zb_save_formdesc_data\n");
    zb_save_formdesc_data();

    zb_uint16_t cluster_id = 0x1000;

    zdo_send_resp_by_long(cluster_id, param, tsn, initiator_addr);
}

void zdo_mgmt_leave_srv(zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_ushort_t i;
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zdo_mgmt_leave_req_t req;
    zb_uint8_t *aps_body;
    zb_apsde_data_indication_t *ind;

    TRACE_MSG(TRACE_ZDO3, ">>zdo_leave_srv %hd", (FMT__H, param));

    /*
       We are here because we got mgmt_leave_req from the remote (or locally, but
       thru aps & nwk).
     */

    /**
       \par Notes about LEAVE

       - when got mgmt_leave_req, fill pending list and call nlme.leave.request

       - nlme.leave.request either :
       - uincasts to its child, call leave.confirm at packet send complete
       - if its leave for us, broadcasts LEAVE command, call leave.confirm at packet send complete

       - when got LEAVE command from the net:
       - from child with 'request' = 0 and we are not TC, send UPDATE-DEVICE
       to TC, then forget this child
       - from parent with 'request' or 'remove child' == 1, send broadcast LEAVE
       with same 'remove child' and 'request' = 0
       call leave.confirm at packet send complete
       - else - from any device with request = 0 - forget this device

       - leave.confirm called when LEAVE command has sent, from mcps-data.confirm
       (not when LEAVE procedure complete - see later)

       - if LEAVE was caused by mgmt_leave_req receive, we must send send mgmt_leave_rsp.
       We can do it only if we did not leave network yet.
       Means, we must remember somehow address of device which issued mgmt_leave_req and,
       if it not empty, send resp to it.
       Need a list of pending mgmt_leave_req. It holds address ref (1b) and buffer id (1b).
       Do not clear entry in this list now - we still need it.

       If no entry in this list, there was no mgmt_leave_req, so can call "leave finish" now.

       - when mgmt_leave_rsp successfuly sent (means - from aps-data.confirm), we must check:
       do we need to leave network and rejoin after it?
       We use here, again, same buffer, so can use same list of pending mgmt_leave_req.
       If it was leave rsp, call call "leave finish" now.
     */

    /* add entry to the leave req table */
    for (i = 0;
         i < ZB_ZDO_PENDING_LEAVE_SIZE
         && ZG->nwk.leave_context.pending_list[i].used;
         ++i) {}

    aps_body = ZB_BUF_BEGIN(ZB_BUF_FROM_REF(param));
    ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);

    if (i == ZB_ZDO_PENDING_LEAVE_SIZE) {
        zb_uint8_t *status_p;

        TRACE_MSG(TRACE_ERROR, "out of pending leave list send resp now.!",
                  (FMT__0));
        /* send resp just now. */

        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint8_t), status_p);
        *status_p = ZB_ZDP_STATUS_INSUFFICIENT_SPACE;
        zdo_send_resp_by_short(ZDO_MGMT_LEAVE_RESP_CLID, param, *aps_body,
                               ind->src_addr);
    }
    else {
        if (i + 1 > ZG->nwk.leave_context.pending_list_size) {
            ZG->nwk.leave_context.pending_list_size = i + 1;
        }

        ZG->nwk.leave_context.pending_list[i].tsn = *aps_body;
        ZB_MEMCPY(&req, (aps_body + 1), sizeof(zb_zdo_mgmt_leave_req_t));
        ZG->nwk.leave_context.pending_list[i].src_addr = ind->src_addr;
        ZG->nwk.leave_context.pending_list[i].buf_ref = param;
        ZG->nwk.leave_context.pending_list[i].used = 1;
        TRACE_MSG(TRACE_ZDO3,
                  "remember mgmt_leave at i %hd, tsn %hd, addr %d, buf_ref %hd",
                  (FMT__H_H_D_H, i, ZG->nwk.leave_context.pending_list[i].tsn,
                   ZG->nwk.leave_context.pending_list[i].src_addr,
                   ZG->nwk.leave_context.pending_list[i].buf_ref));

        /* Now locally call LEAVE.request */
        {
            zb_nlme_leave_request_t *lr = NULL;

            lr = ZB_GET_BUF_PARAM(buf, zb_nlme_leave_request_t);
            ZB_IEEE_ADDR_COPY(lr->device_address, req.device_address);
            lr->remove_children = req.remove_children;
            lr->rejoin = req.rejoin;
            ZB_SCHEDULE_CALLBACK(zb_nlme_leave_request, param);
        }
    }
    TRACE_MSG(TRACE_ZDO3, "<<zdo_mgmt_leave_srv", (FMT__0));
}

#ifndef ZB_LIMITED_FEATURES
zb_bool_t zdo_try_send_mgmt_leave_rsp(zb_uint8_t param, zb_uint8_t status,
                                      zb_uint8_t will_leave) ZB_SDCC_REENTRANT
{
    zb_ushort_t i;

    for (i = 0; i < ZG->nwk.leave_context.pending_list_size; ++i) {
        if (ZG->nwk.leave_context.pending_list[i].used
            && ZG->nwk.leave_context.pending_list[i].buf_ref == param) {
            zb_uint8_t *status_p;
            TRACE_MSG(TRACE_ZDO3,
                      "sending mgmt_leave_rsp i %hd, tsn %hd, addr %d, buf_ref %hd",
                      (FMT__H_H_D_H, i,
                       ZG->nwk.leave_context.pending_list[i].tsn,
                       ZG->nwk.leave_context.pending_list[i].src_addr,
                       ZG->nwk.leave_context.pending_list[i].buf_ref));

            ZB_BUF_INITIAL_ALLOC(ZB_BUF_FROM_REF(
                                     param), sizeof(zb_uint8_t), status_p);
            *status_p = status;
            if (ZG->nwk.leave_context.pending_list[i].src_addr ==
                ZB_PIB_SHORT_ADDRESS()) {
                zb_ret_t ret = ZB_ZDP_STATUS_SUCCESS;
                zb_uint8_t *tsn_p;

                ZB_BUF_ALLOC_LEFT(ZB_BUF_FROM_REF(param), 1, tsn_p);
                *tsn_p = ZG->nwk.leave_context.pending_list[i].tsn;
                ret = zdo_af_resp(param);
                if (ret == ZB_ZDP_STATUS_SUCCESS) {
                    ret = zdo_try_mgmt_leave_complete(param);
                }
                TRACE_MSG(TRACE_ZDO3, "ret %hd", (FMT__H, ret));
            }
            else {
                zdo_send_resp_by_short(ZDO_MGMT_LEAVE_RESP_CLID, param,
                                       ZG->nwk.leave_context.pending_list[i].tsn,
                                       ZG->nwk.leave_context.pending_list[i].src_addr);
            }

            if (status != 0 || !will_leave) {
                ZG->nwk.leave_context.pending_list[i].used = 0;
                if (ZG->nwk.leave_context.pending_list_size == i + 1) {
                    ZG->nwk.leave_context.pending_list_size = i;
                }
            }
            return ZB_TRUE;
        }
    }
    return ZB_FALSE;
}
#endif

zb_bool_t zdo_try_mgmt_leave_complete(zb_uint8_t param)
{
    zb_ushort_t i;

    for (i = 0; i < ZG->nwk.leave_context.pending_list_size; ++i) {
        if (ZG->nwk.leave_context.pending_list[i].used
            && ZG->nwk.leave_context.pending_list[i].buf_ref == param) {
            ZG->nwk.leave_context.pending_list[i].used = 0;
            if (ZG->nwk.leave_context.pending_list_size == i + 1) {
                ZG->nwk.leave_context.pending_list_size = i;
            }
            TRACE_MSG(TRACE_ZDO1, "complete LEAVE after msmt_leave_rsp confirm",
                      (FMT__0));
            if (ZG->nwk.leave_context.pending_list[i].src_addr ==
                ZB_PIB_SHORT_ADDRESS()) {
                /* local leave mgmt request */
                TRACE_MSG(TRACE_ZDO3, "local leave mgmt leave complete",
                          (FMT__0));
                ZB_GET_OUT_BUF_DELAYED(zb_nwk_do_leave_local);
            }
            else {
                zb_nwk_do_leave(param,
                                ZG->nwk.leave_context.rejoin_after_leave);
            }
            return ZB_TRUE;
        }
    }
    return ZB_FALSE;
}

void zb_nwk_do_leave_local(zb_uint8_t param) ZB_CALLBACK
{
    zb_nwk_do_leave(param, ZG->nwk.leave_context.rejoin_after_leave);
}

#ifdef ZB_ROUTER_ROLE
void zb_zdo_mgmt_permit_joining_handle(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *aps_body = ZB_BUF_BEGIN(buf);
    zb_zdo_mgmt_permit_joining_req_t *req;
    zb_nlme_permit_joining_request_t *req_param;

    TRACE_MSG(TRACE_ZDO3, ">>mgmt_nwk_update_handler %hd", (FMT__H, param));

    aps_body++;
    req = (zb_zdo_mgmt_permit_joining_req_t *)aps_body;

    TRACE_MSG(TRACE_ZDO3, "permit_duration %hd tc_significance %hd",
              (FMT__H_H, req->permit_duration, req->tc_significance));
    req_param = (zb_nlme_permit_joining_request_t *)ZB_GET_BUF_PARAM(buf,
                                                                     zb_nlme_permit_joining_request_t);
    req_param->permit_duration = req->permit_duration;
    ZB_SCHEDULE_CALLBACK(zb_nlme_permit_joining_request, param);

#if defined ZB_SECURITY && defined ZB_COORDINATOR_ROLE
    if (ZB_NIB_DEVICE_TYPE() == ZB_NWK_DEVICE_TYPE_COORDINATOR
        && req->tc_significance) {
        if (req->permit_duration) {
            ZDO_CTX().handle.allow_auth = 1;
        }
        else {
            ZDO_CTX().handle.allow_auth = 0;
        }
    }
#endif

    TRACE_MSG(TRACE_ZDO3, "<<mgmt_nwk_update_handler", (FMT__0));
}
#endif  /* ZB_ROUTER_ROLE */

#endif  /* ZB_LIMITED_FEATURES */
/*! @} */
