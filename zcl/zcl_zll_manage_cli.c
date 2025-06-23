/**
 * PURPOSE: ZLL management functions, server side, target
 */
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_zdo.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zb_secur_api.h"
#include "zcl_zll_internal.h"
#include "zb_osif.h"
#include "od.h"
#ifndef ZB_LIMITED_FEATURES
/*! \addtogroup ZB_ZCL */
/*! @{ */
void zll_start_router(zb_uint8_t param);
void zll_nwk_start_router_conf_cb();
void aes128(zb_uint8_t *key, zb_uint8_t *msg, zb_uint8_t *c);
void aes128d(const zb_uint8_t *c, const zb_uint8_t *key, zb_uint8_t *m);

static const zb_uint8_t zll_master_key[16] = { 0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57,
                                               0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B, 0xC9, 0x3F, 0xEE, 0x31 };
void set_enc_network_key(zb_uint8_t *enc_network_key)
{
    zb_uint8_t nonce[16];
    nonce[3] = (ZG->aps.transaction_id) & 0xff;
    nonce[2] = (ZG->aps.transaction_id >> 8) & 0xff;
    nonce[1] = (ZG->aps.transaction_id >> 16) & 0xff;
    nonce[0] = (ZG->aps.transaction_id >> 24) & 0xff;
    memcpy(nonce + 4, nonce + 0, 4);

    nonce[11] = (ZLL_COMM().scan_response.response_id) & 0xff;
    nonce[10] = (ZLL_COMM().scan_response.response_id >> 8) & 0xff;
    nonce[9] = (ZLL_COMM().scan_response.response_id >> 16) & 0xff;
    nonce[8] = (ZLL_COMM().scan_response.response_id >> 24) & 0xff;
    memcpy(nonce + 12, nonce + 8, 4);

    /* encrypt the network key */
    zb_uint8_t exchange_key[16];
    zb_uint8_t network_key[16];
    aes128(zll_master_key, nonce, exchange_key);
    aes128d(enc_network_key, exchange_key, network_key);
    zb_secur_setup_preconfigured_key(network_key, 0);
    ZG->nwk.nib.security_level = 5;
}
/* ----- REQ/RESP HANDLING -------*/
void zll_send_scan_resp(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_scan_resp_t resp;
    ZB_BZERO(&resp, sizeof(zb_zll_scan_resp_t));
    resp.transaction_id = ZG->aps.transaction_id;
    resp.rssi_correction = 0x20;
    resp.zigbee_information = ZLL_COMM().zigbee_info;
    resp.touchlink_information = ZLL_COMM().touchlink_info;
    resp.key_bitmask = 0x0010;
    resp.response_id = ZB_RANDOM() | ZB_RANDOM() << 16;
    resp.logical_channel = zb_transceiver_get_channel();
       
    if (BDB_CTX().node_is_on_net && ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) == ZB_ROUTER) {
        ZB_EXTPANID_COPY(resp.extended_pan_id, ZB_NIB_EXT_PAN_ID());
        resp.network_update_id = ZB_NIB_UPDATE_ID();    
        resp.network_address = ZB_PIB_SHORT_ADDRESS();
    }
    else {
        /* propose new net params; no need to store them (ZCL 13.3.2.2.1) */
        zb_uint16_t rand;
        for (zb_uint8_t i = 0; i < 7; i += 2) {
            rand = ZB_RANDOM();
            ZB_MEMCPY(&resp.extended_pan_id[i], &rand, sizeof(zb_uint16_t));
        }
    }
     if (ZB_NIB_PAN_ID() == 0xffff || ZB_PIB_SHORT_PAN_ID() == 0xffff) {
        /* to avoid pan id compression, as we are not on any network */
        ZB_PIB_SHORT_PAN_ID() = ZB_RANDOM();
        ZB_NIB_PAN_ID() = ZB_PIB_SHORT_PAN_ID();
        zb_transceiver_set_pan_id(ZB_PIB_SHORT_PAN_ID());
        ZB_UPDATE_PAN_ID();
    }

    resp.pan_id = ZB_NIB_PAN_ID();
    resp.subdevices = ZB_ZDO_SIMPLE_DESC_NUMBER();
    resp.total_group_identifiers = 0; // ?
    zb_zll_scan_resp_t *ptr;
    zb_ushort_t size = sizeof(zb_zll_scan_resp_t) - sizeof(zb_uint8_t) * 7;
    if (ZB_ZDO_SIMPLE_DESC_NUMBER() == 1) {
        resp.endpoint = ZB_ZDO_SIMPLE_DESC_LIST()[0]->endpoint;
        resp.profile_id = ZB_ZDO_SIMPLE_DESC_LIST()[0]->app_profile_id;
        resp.device_id = ZB_ZDO_SIMPLE_DESC_LIST()[0]->app_device_id;
        resp.version = ZB_ZDO_SIMPLE_DESC_LIST()[0]->app_device_version;
        resp.group_id_count = 0; // ?
        size = sizeof(zb_zll_scan_resp_t);
    }
    ZB_BUF_INITIAL_ALLOC(buf, size, ptr);
    ZB_MEMCPY(ptr, &resp, size);
    ZB_MEMCPY(&ZLL_COMM().scan_response, &resp, size);
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_CMD_READ_ATTRIB_RESP);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, &ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_handle_scan_req(zb_uint8_t param, zb_ieee_addr_t source)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zll_scan_req_t *req = (zb_zll_scan_req_t *)ZB_BUF_BEGIN(buf);
    /* BDB TL Target Step 2 */
    ZG->aps.transaction_id = req->transaction_id;
    ZB_IEEE_ADDR_COPY(ZLL_COMM().responder_addr, source);
    /* only answer scan requests that are nearby */
    if (ZB_MAC_GET_RSSI(buf) <= -60 || ZB_ZLL_TL_INFO_GET_LINK_INITIATOR(req->touchlink_information) == 0) {
        zb_free_buf(buf);
        return;
    }
    ZLL_COMM().initiator_tl_info = req->touchlink_information;
    ZLL_COMM().initiator_zb_info = req->zigbee_information;
    zb_free_buf(buf);
    /* BDB TL Target Step 3 */
    /* TODO start timer */
    ZB_GET_OUT_BUF_DELAYED(zll_send_scan_resp);
    ZLL_COMM().state = ZB_ZLL_COMM_INIT_NET;

}

void zll_send_dev_info_resp(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_dev_info_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf,  sizeof(zb_zll_dev_info_resp_t) + 
        sizeof(zb_zll_dev_record_t) * ZB_ZDO_SIMPLE_DESC_NUMBER(), resp);
    
    resp->transaction_id = ZG->aps.transaction_id;
    resp->start = ZLL_COMM().dev_info_start;
    resp->count = ZB_ZDO_SIMPLE_DESC_NUMBER();
    zb_zll_dev_record_t *record;
    resp += sizeof(zb_zll_dev_info_resp_t);
    for (zb_uint8_t i = 0; i < ZB_ZDO_SIMPLE_DESC_NUMBER(); i++) {
        record = (zb_zll_dev_record_t *)resp;
        ZB_IEEE_ADDR_COPY(record->addr, ZB_PIB_EXTENDED_ADDRESS());
        record->endpoint = ZB_ZDO_SIMPLE_DESC_LIST()[i]->endpoint;
        record->profileid = ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_profile_id;
        record->deviceid = ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_device_id;
        record->version = ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_device_version;
        record->groupid_count = 0; // ?
        record->sort = 0; // no sorting required
        resp += sizeof(zb_zll_dev_record_t);
    }

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, &ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_handle_dev_info_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_dev_info_req_t *req = (zb_zll_dev_info_req_t *)ZB_BUF_BEGIN(buf);
    ZLL_COMM().dev_info_start = req->start_index;
    zb_free_buf(buf);
    /* BDB TL Target Step 5 */
    ZB_GET_OUT_BUF_DELAYED(zll_send_dev_info_resp);
}

void zll_send_net_start_resp(zb_uint8_t param)
{
    /* BDB TL Target Step 11 */
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_net_start_req_t *req = (zb_zll_net_start_req_t *)ZB_BUF_BEGIN(ZLL_COMM().net_p_buf);
    zb_zll_net_start_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_net_start_resp_t), resp);
    ZB_BZERO(resp, sizeof(resp));
    resp->transaction_id = ZG->aps.transaction_id;
    resp->status = 0; // BDB has no condition for failure
    ZB_IEEE_ADDR_COPY(resp->ext_pan_id, req->ext_pan_id);
    resp->net_update_id = ZB_NIB_UPDATE_ID();
    resp->channel = req->channel;        
    resp->pan_id = req->pan_id;    

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_CMD_DISC_CMDS_REC);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(intrp->dst_addr.addr_long, ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);

}

void zll_handle_net_start_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    /* BDB TL Target Step 8 */
    if (ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) != ZB_ROUTER && ZB_FALSE) {
        zb_free_buf(buf);
        return;
    }
    /* clear pending buffer, why do we have to do this here? */
    if ((MAC_CTX().tx_wait_cb) && (!MAC_CTX().tx_cnt)) {
        ZB_WAIT_FOR_TX();
    }
    zb_mac_main_loop();
    
    ZB_BUF_COPY(ZLL_COMM().net_p_buf, buf);
    zb_zll_net_start_req_t *req = (zb_zll_net_start_req_t *)ZB_BUF_BEGIN(buf);
    /* BDB TL Target Step 9 - decide if we want a new network (skip)*/
    /* BDB TL Target Step 10 - NLME-NET-DISCOVERY */
    zb_buf_t *buf2 = zb_get_out_buf();
    zb_nlme_network_discovery_request_t *req2 = ZB_GET_BUF_PARAM(buf2,
                                                zb_nlme_network_discovery_request_t);
    
    req2->scan_channels = (req->channel == 0) ? BDB_TL_PRIMARY_CHANNEL_SET :
                                    1l << req->channel;
    req2->scan_duration = BDB_CTX().scan_duration;
    ZB_SCHEDULE_CALLBACK(zb_nlme_network_discovery_request,
                                        ZB_REF_FROM_BUF(buf2));
    zb_free_buf(buf);

}

void zll_send_net_join_resp(zb_uint8_t cmd)
{
    /* BDB TL Target Step 17 */
    zb_buf_t *buf = zb_get_out_buf();
    zb_zll_net_join_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_net_join_resp_t), resp);
    resp->transaction_id = ZG->aps.transaction_id;
    resp->status = 0;

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, cmd);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(intrp->dst_addr.addr_long, ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, ZB_REF_FROM_BUF(buf));

}

void zll_handle_net_join_req(zb_uint8_t param, zb_uint8_t cmd)
{
    /* BDB TL Target Step 15 */
    if ((cmd == ZB_ZCL_CMD_DISC_CMDS_REC_RESP && ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) != ZB_ROUTER) ||
        (cmd == ZB_ZCL_CMD_DISC_CMDS_GEN_RESP && ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) != ZB_END_DEVICE)) {
        return;
    }
    ZLL_COMM().received_join_net = ZB_TRUE;

    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    ZB_BUF_COPY(ZLL_COMM().net_p_buf, buf);
    zb_free_buf(buf);
    /* BDB TL Target Step 16 - reject network by app specific means (skip) */
    zll_send_net_join_resp(cmd+1);
    /* part of step 17 */
    BDB_CTX().node_join_linkkey_type = 0x03;

    /* BDB TL Target Step 18 (same as 12)*/
    if (BDB_CTX().node_is_on_net) {
        zb_buf_t *buf = zb_get_out_buf();
        zb_nlme_leave_request_t *lr = ZB_GET_BUF_PARAM(buf, zb_nlme_leave_request_t);
        ZB_IEEE_ADDR_ZERO(&lr->device_address);
        lr->remove_children = ZB_FALSE;
        lr->rejoin = ZB_FALSE;
        ZB_SCHEDULE_CALLBACK(zb_nlme_leave_request, ZB_REF_FROM_BUF(buf));
    }
    else {
        ZB_GET_OUT_BUF_DELAYED(zll_start_router);
    }

}

void zll_handle_net_update_req(zb_uint8_t param)
{
    /* BDB TL Target Step 7 */
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_net_update_req_t *req = (zb_zll_net_update_req_t *)ZB_BUF_BEGIN(buf);
    if (ZB_IEEE_ADDR_CMP(req->ext_pan_id, ZB_NIB_EXT_PAN_ID()) ||
        req->pan_id != ZB_NIB_PAN_ID() ||
        req->net_update_id <= ZB_NIB_UPDATE_ID()) {
        zb_free_buf(buf);
        return;
    }
    ZB_NIB_UPDATE_ID() = req->net_update_id;
    ZB_TRANSCEIVER_SET_CHANNEL(req->channel);
    /* not in spec but this should be net addr of target - just making sure */
    ZB_PIB_SHORT_ADDRESS() = req->network_address;
    zb_transceiver_update_short_addr(req->network_address);

}

void zll_start_router(zb_uint8_t param)
{
    /* BDB TL Target Step 13 - start router */
    if (ZLL_COMM().received_join_net) {
        zb_zll_net_join_req_t *req = (zb_zll_net_join_req_t *)ZB_BUF_BEGIN(ZLL_COMM().net_p_buf);
        ZB_IEEE_ADDR_COPY(ZB_NIB_EXT_PAN_ID(), req->ext_pan_id);
        /* unclear what to do with req->key_index */
        set_enc_network_key(req->enc_network_key);
        ZB_NIB_UPDATE_ID() = req->net_update_id;
        ZB_TRANSCEIVER_SET_CHANNEL(req->channel);
        MAC_PIB().mac_pan_id = req->pan_id;
        ZB_PIB_SHORT_ADDRESS() = req->network_address;
        /* TODO: APSME-ADD-GROUP.request to assign endpoints */
        // req->group_id_begin;
        // req->group_id_end;
        APL_CTX().free_addr_range_begin = req->free_addr_begin;
        APL_CTX().free_addr_range_end = req->free_addr_end;
        APL_CTX().free_gr_id_range_begin = req->free_group_begin;
        APL_CTX().free_gr_id_range_end = req->free_group_end;
    }
    else {
        zb_zll_net_start_req_t *req = (zb_zll_net_start_req_t *)ZB_BUF_BEGIN(ZLL_COMM().net_p_buf);
        ZB_IEEE_ADDR_COPY(ZB_NIB_EXT_PAN_ID(), req->ext_pan_id);
        /* unclear what to do with req->key_index */
        set_enc_network_key(req->enc_network_key);
        ZB_TRANSCEIVER_SET_CHANNEL(req->channel);
        MAC_PIB().mac_pan_id = req->pan_id;
        ZB_PIB_SHORT_ADDRESS() = req->network_address;
        /* TODO: APSME-ADD-GROUP.request to assign endpoints */
        // req->group_id_begin;
        // req->group_id_end;
        APL_CTX().free_addr_range_begin = req->free_addr_begin;
        APL_CTX().free_addr_range_end = req->free_addr_end;
        APL_CTX().free_gr_id_range_begin = req->free_group_begin;
        APL_CTX().free_gr_id_range_end = req->free_group_end;
        /* lets just add it to our addresses */
        zb_address_ieee_ref_t addr_ref;
        zb_address_update(req->initiator_addr, req->initiator_net_addr, ZB_FALSE, &addr_ref);

    }
    ZB_UPDATE_PAN_ID();
    zb_transceiver_update_short_addr(ZB_PIB_SHORT_ADDRESS());
    /* BDB Step 19 (from join net req) - also start router, but only if we are no ED */
    if (ZLL_COMM().received_join_net &&
        ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) == ZB_END_DEVICE) {
        printf("not starting router\n");
        zb_free_buf(ZB_BUF_FROM_REF(param));
        zll_nwk_start_router_conf_cb();
        return;
    }
    
    /* avoid coord realignment for now */
    ZG->nwk.handle.router_started = 0;

    zb_nlme_start_router_request_t *request;
    request = ZB_GET_BUF_PARAM((zb_buf_t *)ZB_BUF_FROM_REF(param),
                                zb_nlme_start_router_request_t);
    request->beacon_order = ZB_TURN_OFF_ORDER; // 0x0f
    request->superframe_order = 0x00;
    request->battery_life_extension = 0;
    ZB_SCHEDULE_CALLBACK(zb_nlme_start_router_request, param);
}

void zll_nwk_disc_conf_cb(zb_uint8_t param)
{
    /* continue on step 10 */
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_nlme_network_discovery_confirm_t *cnf;
    cnf = (zb_nlme_network_discovery_confirm_t *)ZB_BUF_BEGIN(buf);
    /* populate net parameter buffer with new values (only for discovery)*/
    zb_zll_net_start_req_t *req = (zb_zll_net_start_req_t *)ZB_BUF_BEGIN(ZLL_COMM().net_p_buf);
    /* fix this mess! What to do with disc result? we cannot respond with this anyway */
    req->pan_id = ZB_PIB_SHORT_PAN_ID();
    if (cnf->status != MAC_SUCCESS || cnf->network_count == 0) {
        req->channel = zb_transceiver_get_channel();
        if (ZB_IEEE_ADDR_IS_ZERO(req->ext_pan_id)) {
            zb_uint16_t rand;
            for (zb_uint8_t i = 0; i < 7; i += 2) {
                rand = ZB_RANDOM();
                ZB_MEMCPY(&req->ext_pan_id[i], &rand, sizeof(zb_uint16_t));
            }
        }
        if (req->pan_id == 0x0000) {
            req->pan_id = ZB_RANDOM();
        }
    }
    else {
        /* cnf + 1 == cnf + sizeof(zb_nlme_network_discovery_confirm_t) */
        zb_nlme_network_descriptor_t *dsc = (zb_nlme_network_descriptor_t *)(cnf + 1);
        /* start at one, because dsc is already our first net */
        for (zb_uint8_t i = 1; i < cnf->network_count &&  dsc->permit_joining != 1; i++) {
            dsc++;
        }
        ZB_IEEE_ADDR_COPY(req->ext_pan_id, dsc->extended_pan_id);
        req->channel = dsc->logical_channel;
        zb_address_pan_id_ref_t pan_ref;
        if (zb_address_get_pan_id_ref(dsc->extended_pan_id, &pan_ref) == RET_OK) {
            zb_address_get_short_pan_id(pan_ref, &req->pan_id);
        }
        else {
            req->pan_id = ZB_PIB_SHORT_PAN_ID();
        }
    }
     
    zb_free_buf(buf);
    ZB_GET_OUT_BUF_DELAYED(zll_send_net_start_resp);
    /* BDB TL Target Step 12 - leave old network */
    if (BDB_CTX().node_is_on_net) {
        buf = zb_get_out_buf();
        zb_nlme_leave_request_t *lr = ZB_GET_BUF_PARAM(buf, zb_nlme_leave_request_t);
        ZB_IEEE_ADDR_ZERO(&lr->device_address);
        lr->remove_children = ZB_FALSE;
        lr->rejoin = ZB_FALSE;
        ZB_SCHEDULE_CALLBACK(zb_nlme_leave_request, ZB_REF_FROM_BUF(buf));
    }
    else {
        ZB_GET_OUT_BUF_DELAYED(zll_start_router);
    }
}

void zll_nwk_leave_conf_cb()
{
    /* should this only happen when leave or generally? */
    zb_erase_nvram(0);
    zb_write_up_counter();
    ZB_GET_OUT_BUF_DELAYED(zll_start_router);
    
}

void zll_finish()
{
    /* BDB TL Target Step 20 */
    BDB_CTX().node_is_on_net = ZB_TRUE;
    ZB_IEEE_ADDR_COPY(ZB_AIB().trust_center_address, &ZB_IEEE_ADDR_BROADCAST);
    ZG->nwk.handle.joined = ZB_TRUE;
    ZB_MAC_SET_INDIRECT_DATA_REQUEST();
    ZB_GET_OUT_BUF_DELAYED(zdo_send_device_annce);
    zb_buf_t *buf = zb_get_out_buf();
    ZB_SCHEDULE_TX_CB(zb_nlme_send_link_status, ZB_REF_FROM_BUF(buf));
    /* apsDeviceKeyPairset not present - skip */
}

void zll_nwk_start_router_conf_cb()
{
    if (ZLL_COMM().received_join_net) {
        /* continue Step 20 */
        zll_finish();

    }
    /* BDB TL Target Step 14 - add device to neighbortable */
    zb_nlme_direct_join_request_t *req;
    zb_buf_t *buf = zb_get_in_buf();
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_nlme_direct_join_request_t), req);
    ZB_IEEE_ADDR_COPY(req->device_address, ZLL_COMM().responder_addr);
    ZB_SCHEDULE_CALLBACK(zb_nlme_direct_join_request, ZB_REF_FROM_BUF(buf));
}

void zll_nwk_direct_join_cb()
{
    /* continue Step 20 */
    zll_finish();
}
/* ----- ZLL COMMISSIONING LOGIC -------*/
void handle_zll_srv(zb_uint16_t src_addr, zb_uint8_t src_ep,
                    zb_uint16_t profile_id, zb_uint8_t param,
                    zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);
    zb_zcl_cmd_t cmd = ZB_ZCL_FRAME_HDR_GET_COMMAND_ID(ptr);
    zb_ushort_t hdr_size = ZB_ZCL_FRAME_HDR_GET_SIZE(ptr);
    /* during touchlink commissioning, only ieee addr are present! */
    zb_mac_mhr_t mac_hdr;
    zb_parse_mhr(&mac_hdr, buf->buf + buf->u.hdr.mac_hdr_offset);
    zb_ieee_addr_t source;
    ZB_IEEE_ADDR_COPY(&source, &mac_hdr.src_addr.addr_long);

    ZB_BUF_CUT_LEFT2(buf, hdr_size);
    zb_uint32_t *trans_id = (zb_uint32_t *)ZB_BUF_BEGIN(buf);
    /* BDB TL Target Step 4 */
    if (cmd != ZB_ZCL_CMD_READ_ATTRIB && *trans_id != ZG->aps.transaction_id) {
        puts("wrong transaction id");
        zb_free_buf(buf);
        return;
    }
    /* commands received */
    switch (cmd) {
        case ZB_ZCL_CMD_READ_ATTRIB: /* scan request */
            zll_handle_scan_req(param, source);
            break;
        case ZB_ZCL_CMD_WRITE_ATTRIB: /* dev info request */
            zll_handle_dev_info_req(param);
            break;
        case ZB_ZCL_CMD_CONFIG_REPORT: /* identify request */
            /* BDB TL Target Step 6 */
            zb_free_buf(buf);
            break;
        case ZB_ZCL_CMD_CONFIG_REPORT_RESP: /* reset to factory new request */
            zb_free_buf(buf);
            break;
        case ZB_ZCL_CMD_WRITE_ATTRIB_STRUCT_RESP: /* network start request */
            zll_handle_net_start_req(param);
            break;
        case ZB_ZCL_CMD_DISC_CMDS_REC_RESP: /* network join router request */
            zll_handle_net_join_req(param, cmd);
            break;
        case ZB_ZCL_CMD_DISC_CMDS_GEN_RESP: /* network join ed request */
            zll_handle_net_join_req(param, cmd);
            break;
        case ZB_ZCL_CMD_DISC_ATTRIB_EXT_RESP: /* network update request */
            zll_handle_net_update_req(param);
            break;
        default:
            zb_free_buf(buf);
    }
}

void zb_zcl_zll_target_setup()
{
    ZLL_COMM().zigbee_info = (zb_uint8_t)0;
    /* enums do not work */
    switch ((zb_uint8_t)ZB_NIB_DEVICE_TYPE()) {
    case 2: /* ZB_NWK_DEVICE_TYPE_COORDINATOR */
        ZLL_COMM().zigbee_info = ZB_ZCL_ZB_DEV_TYPE_COORD;
        break;
    case 1: /* ZB_NWK_DEVICE_TYPE_ROUTER */
        ZLL_COMM().zigbee_info = ZB_ZCL_ZB_DEV_TYPE_ROUTER;
        break;
    case 0: /* ZB_NWK_DEVICE_TYPE_ED */
        ZLL_COMM().zigbee_info = ZB_ZCL_ZB_DEV_TYPE_ED;
        break;
    default:
        ZLL_COMM().zigbee_info = ZB_ZCL_ZB_DEV_TYPE_ROUTER;
        break;
    }
    ZLL_COMM().zigbee_info |= (0x1 & ZB_PIB_RX_ON_WHEN_IDLE()) << 2;
    /* 0x00 we are not initiator */
    ZLL_COMM().touchlink_info = 0x00;
    if (ZB_TOUCHLINK_FACT_NEW) {
        ZLL_COMM().touchlink_info |= 1;
        ZB_NIB_UPDATE_ID() = 0;
        ZB_PIB_SHORT_ADDRESS() = 0xffff;
        zb_transceiver_update_short_addr(0xffff);
    } else {
        ZB_PIB_SHORT_ADDRESS() = 0x0002;
        zb_transceiver_update_short_addr(0x0002);
    }
   
    /* 0x02 addr assignment capable */
    if (ZB_MAC_CAP_GET_ALLOCATE_ADDRESS(ZB_ZDO_NODE_DESC()->mac_capability_flags)) {
        ZLL_COMM().touchlink_info |= 2;
    }
    /* 0x80 we can do ZB 3.0 (correct?) */
    if (ZB_PROTOCOL_VERSION > 1) {
        ZLL_COMM().touchlink_info |= 0x80;
    }
    ZLL_COMM().received_join_net = ZB_FALSE;
    ZB_BZERO(&ZLL_COMM().scan_response, sizeof(ZLL_COMM().scan_response));
    ZLL_COMM().state = ZB_ZLL_COMM_SCAN;
    ZLL_COMM().net_p_buf = zb_get_in_buf();
    (void)zb_zcl_register_cluster(1 /* EP 1 */, ZB_ZLL_CLUSTER_ID /* TL Cluster */,
                                  NULL /* attr list */, handle_zll_srv, NULL /* action */);
    /**
     * from BDB 10.2.2: if TC is not known - commissionig process should set it to broadcast
     * TODO: move this to BDB logic when possible 
     */
    if (ZB_IEEE_ADDR_IS_ZERO(ZB_AIB().trust_center_address)) {
        ZB_IEEE_ADDR_COPY(ZB_AIB().trust_center_address, ZB_IEEE_ADDR_BROADCAST);
    }
}
#endif /* ZB_LIMITED_FEATURES */
/*! @} */
