/**
 * PURPOSE: ZLL management functions, client side, initiator
 */
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zb_secur_api.h"
#include "zcl_zll_internal.h"
#include "od.h"
#ifndef ZB_LIMITED_FEATURES
/*! \addtogroup ZB_ZCL */
/*! @{ */
/**
 * ZLL Touchlink Client Side
 *
 * BACKLOG in this file:
 * verify net update id
 * unified state-change using function (less spaghetti)
 *  -> including BDB
 * implement ROUTER based network init functions
 * anyway to set information dynamically - done
 * Followup procedure?
 */
/* ----- HELPER FUNCTIONS -------*/
void zll_comm_signal(zb_zll_comm_state_t state);
void zll_timeout(zb_uint8_t param);
void aes128(zb_uint8_t *key, zb_uint8_t *msg, zb_uint8_t *c);
void aes128d(const zb_uint8_t *c, const zb_uint8_t *key, zb_uint8_t *m);

static const zb_uint8_t zll_master_key[16] = { 0x9F, 0x55, 0x95, 0xF1, 0x02, 0x57,
                                               0xC8, 0xA4, 0x69, 0xCB, 0xF4, 0x2B, 0xC9, 0x3F, 0xEE, 0x31 };

void get_enc_network_key(zb_uint8_t *enc_network_key)
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
    aes128(zll_master_key, nonce, exchange_key);
    aes128(exchange_key, ZG->nwk.nib.secur_material_set[0].key, enc_network_key);
}

void zll_change_channel(zb_uint8_t param)
{
    ZB_TRANSCEIVER_SET_CHANNEL(param);
}

zb_bool_t get_free_addr_and_group_range(zb_uint16_t *addr_begin, zb_uint16_t *addr_end,
                zb_uint16_t *group_begin, zb_uint16_t *group_end)
{
   
    if (APL_CTX().free_addr_range_end - APL_CTX().free_addr_range_begin < 2620) {
        return ZB_FALSE;
    }
    if (APL_CTX().free_gr_id_range_end - APL_CTX().free_gr_id_range_begin < 2620) {
        return ZB_FALSE;
    }
    /* we provide the target with a 10th of address space */
    *addr_begin = APL_CTX().free_addr_range_end - 1310;
    *addr_end = APL_CTX().free_addr_range_end;
    /* these addresses should no longer be available to us */
    APL_CTX().free_addr_range_end = *addr_begin - 1;
    /* same for groups */
    *group_begin = APL_CTX().free_gr_id_range_end - 1310;
    *group_end = APL_CTX().free_gr_id_range_end;
    APL_CTX().free_gr_id_range_end = *group_begin - 1;
    return ZB_TRUE;

}
/* ----- REQ/RESP HANDLING -------*/
void zll_send_net_start_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zll_net_start_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_net_start_req_t), req);
    req->transaction_id = ZG->aps.transaction_id;
    ZB_IEEE_ADDR_ZERO(&req->ext_pan_id);
    req->key_index = 4;
    get_enc_network_key(req->enc_network_key);
    req->channel = zb_transceiver_get_channel();
    req->pan_id = 0x0000;
    req->network_address = ZLL_COMM().responder_addr_short;
    req->group_id_begin = APL_CTX().free_gr_id_range_begin;
    req->group_id_end = APL_CTX().free_gr_id_range_begin + ZLL_COMM().scan_response.subdevices - 1;
    APL_CTX().free_gr_id_range_begin += ZLL_COMM().scan_response.subdevices;
    /**
     * ranges that recipient can use to allocate new devices etc.
     * only applies if recipient has addr assign capability
     */
    if (ZB_ZCL_GET_ADDR_ASS_CAP(ZLL_COMM().scan_response.touchlink_information)) {
        if (!get_free_addr_and_group_range(&req->free_addr_begin, &req->free_addr_end,
                &req->free_group_begin, &req->free_group_end)) {
            zb_free_buf(buf);
            BDB_CTX().comm_status = NOT_PERMITTED;
            return;
        }
    }
    else {
        req->free_addr_begin = 0;
        req->free_addr_end = 0;
        req->free_group_begin = 0;
        req->free_group_end = 0;
    }
    ZB_IEEE_ADDR_COPY(req->initiator_addr, ZB_PIB_EXTENDED_ADDRESS());
    req->initiator_net_addr = ZB_PIB_SHORT_ADDRESS();

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZLL_NET_START_REQ_CMD_ID);
    /* Update address map */
    zb_address_ieee_ref_t addr_ref;
    zb_address_update(ZLL_COMM().responder_addr, ZLL_COMM().responder_addr_short, ZB_FALSE, &addr_ref);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, &ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_handle_net_start_resp(zb_uint8_t param, zb_ieee_addr_t source)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_net_start_resp_t *resp = (zb_zll_net_start_resp_t *)ZB_BUF_BEGIN(buf);
    if (resp->status != 0) {
        BDB_CTX().comm_status = NO_NETWORK;
        zb_free_buf(buf);
        puts("Target failed to start network");
        return;
    }
    /* TODO Step 17 */
    if (resp->channel != zb_transceiver_get_channel()) {
        ZB_TRANSCEIVER_SET_CHANNEL(resp->channel);
    }
    if (!ZB_IEEE_ADDR_CMP(resp->ext_pan_id, ZB_AIB().aps_use_extended_pan_id)) {
        ZB_IEEE_ADDR_COPY(&ZB_AIB().aps_use_extended_pan_id, resp->ext_pan_id);
    }
    if (resp->pan_id != ZB_PIB_SHORT_PAN_ID()) {
        ZB_PIB_SHORT_PAN_ID() = resp->pan_id;
        zb_transceiver_set_pan_id(resp->pan_id);
    }
    ZB_SCHEDULE_ALARM_CANCEL(zll_timeout, 0);
    /* BDB TL Init Step 19 finish if not ED */
    if (ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) == ZB_END_DEVICE) {
        /* continue Step 26 */
        ZG->nwk.handle.joined = 1;
        zb_address_update(source, ZLL_COMM().responder_addr_short, ZB_TRUE,
                &ZG->nwk.handle.parent);
        zb_free_buf(buf);
        zll_comm_signal(ZB_ZLL_COMM_SUCCESS);
        return;
    }
    /** 
     * BDB TL Init Step 18 schedule "start network" timeout
     * since we only have a rejoin callback and no other indication that a
     * network has started, we do this after step 19
     */
    ZB_SCHEDULE_ALARM(zll_timeout, 1, BDB_TL_MIN_STARTUP_DELAY_TIME);
    /* prepare rejoin */
#if defined ZB_ROUTER_ROLE || defined ZB_COORDINATOR_ROLE
    zb_nwk_exneighbor_start();
#endif
    /* adding device to neighbor table */
    zb_ext_neighbor_tbl_ent_t *enbt = NULL; /* shutup sdcc */

    zb_address_pan_id_ref_t panid_ref;
    zb_ret_t ret = zb_address_set_pan_id(resp->pan_id, resp->ext_pan_id, &panid_ref);
    if (ret == RET_ALREADY_EXISTS) {
        ret = RET_OK;
    }
    if (ret == RET_OK) {
        ret = zb_nwk_exneighbor_by_ieee(panid_ref, source, &enbt);
    }
    if (ret == RET_OK) {
        enbt->lqi = ZB_MAC_GET_LQI(buf);
        enbt->potential_parent = 1;
        enbt->short_addr = ZLL_COMM().responder_addr_short;
        zb_ieee_addr_compress(ZLL_COMM().responder_addr, &enbt->long_addr);
        enbt->panid_ref = panid_ref;
        enbt->logical_channel = resp->channel;
        TRACE_MSG(TRACE_NWK2, "ch %hd", (FMT__H, enbt->logical_channel));
        enbt->permit_joining = 1;
        /* fields for the Network Descriptor - table 3.8 */
        enbt->stack_profile = 1;
        enbt->router_capacity = 1;
        enbt->end_device_capacity = 1;
        enbt->device_type = ZB_ZCL_GET_ZB_DEV_TYPE(ZLL_COMM().scan_response.zigbee_information);
        enbt->update_id = ZB_NIB_UPDATE_ID();
    }
    zb_free_buf(buf);
    zll_comm_signal(ZB_ZLL_COMM_REJOIN);
}

void zll_send_net_update(zb_uint8_t param)
{
    /* TODO */
    (void)param;
}

void zll_send_net_join(zb_uint8_t param)
{
    /* BDB TL Init Step 23  */
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zll_net_join_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_net_join_req_t), req);
    req->transaction_id = ZG->aps.transaction_id;
    ZB_EXTPANID_COPY(req->ext_pan_id, ZB_NIB_EXT_PAN_ID());
    req->key_index = 4;
    get_enc_network_key(req->enc_network_key);
    req->net_update_id = ZB_NIB_UPDATE_ID();
    if (BDB_CTX().node_is_on_net) {
        req->channel = ZLL_COMM().prev_channel;
        ZB_SCHEDULE_TX_CB(zll_change_channel, ZLL_COMM().prev_channel);
    }
    else {
        req->channel = zb_transceiver_get_channel();
    }
    req->pan_id = ZB_NIB_PAN_ID();
    req->network_address = ZLL_COMM().responder_addr_short;
    req->group_id_begin = APL_CTX().free_gr_id_range_begin;
    req->group_id_end = APL_CTX().free_gr_id_range_begin + ZLL_COMM().scan_response.subdevices - 1;
    APL_CTX().free_gr_id_range_begin += ZLL_COMM().scan_response.subdevices;
    if (ZB_ZCL_GET_ADDR_ASS_CAP(ZLL_COMM().scan_response.touchlink_information)) {
        if (!get_free_addr_and_group_range(&req->free_addr_begin, &req->free_addr_end,
                &req->free_group_begin, &req->free_group_end)) {
            zb_free_buf(buf);
            BDB_CTX().comm_status = NOT_PERMITTED;
            return;
        }
    }
    else {
        req->free_addr_begin = 0;
        req->free_addr_end = 0;
        req->free_group_begin = 0;
        req->free_group_end = 0;
    }

    zb_zcl_cmd_t cmd = ZB_ZCL_GET_ZB_DEV_TYPE(ZLL_COMM().scan_response.zigbee_information) ==
                               ZB_ZCL_ZB_DEV_TYPE_ED ?
                           ZB_ZLL_NET_JOIN_ED_REQ_CMD_ID : ZB_ZLL_NET_JOIN_R_REQ_CMD_ID;

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, cmd);
    /* Update address map */
    zb_address_ieee_ref_t addr_ref;
    zb_address_update(ZLL_COMM().responder_addr, ZLL_COMM().responder_addr_short, ZB_FALSE, &addr_ref);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(&intrp->dst_addr.addr_long, &ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);

    /* BDB TL Init Step 24 */
    ZB_SCHEDULE_ALARM(zll_timeout, 1, BDB_RX_WINDOW_DURATION);
}

void zll_handle_net_join_resp(zb_uint8_t param)
{
    ZB_SCHEDULE_ALARM_CANCEL(zll_timeout, 1);

    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_net_join_resp_t *resp = (zb_zll_net_join_resp_t *)ZB_BUF_BEGIN(buf);
    if (resp->transaction_id != ZG->aps.transaction_id) {
        zb_free_buf(buf);
        return;
    }
    if (resp->status != 0) {
        BDB_CTX().comm_status = TARGET_FAILURE;
        zb_free_buf(buf);
        return;
    }
    zb_free_buf(buf);
    /* correct or rejoin expected? BDB says no! */
    zll_comm_signal(ZB_ZLL_COMM_SUCCESS);

    /**
     * TODO Step 25
     *  - wait for network start
     */
}

void zll_send_dev_info_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    zb_zll_dev_info_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_dev_info_req_t), req);
    req->transaction_id = ZG->aps.transaction_id;
    req->start_index = APL_CTX().dev_info_used; // needs to be determined from internal state

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZLL_DEV_INFO_REQ_CMD_ID);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_64BIT_DEV;
    ZB_IEEE_ADDR_COPY(intrp->dst_addr.addr_long, ZLL_COMM().responder_addr);

    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_handle_dev_info_resp(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);
    zb_zll_dev_info_resp_t *resp = (zb_zll_dev_info_resp_t *)ptr;
    ptr += sizeof(zb_zll_dev_info_resp_t);
    /* we receive multiple device records */
    /* can we trust "start" value? better not do that */
    zb_zll_dev_record_t *record;
    zb_apl_dev_info_ent_t *ent;
    for (zb_uint8_t i = 0; i < resp->count; i++) {
        record = (zb_zll_dev_record_t *)ptr;
        ent = &APL_CTX().dev_info_tbl[APL_CTX().dev_info_used];
        /* questionable */
        ZB_MEMCPY(ent, record, sizeof(zb_zll_dev_record_t));
        APL_CTX().dev_info_used++;
        ptr += sizeof(zb_zll_dev_record_t);
    }
    zb_free_buf(buf);
    zll_comm_signal(ZB_ZLL_COMM_INIT_NET);
}

void zll_send_scan_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_scan_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zll_scan_req_t), req);
    req->transaction_id = ZG->aps.transaction_id;
    req->zigbee_information = ZLL_COMM().zigbee_info;
    req->touchlink_information = ZLL_COMM().touchlink_info;

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZLL_SCAN_REQ_CMD_ID);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
    intrp->dst_addr.addr_short = 0xffff;
    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_handle_scan_resp(zb_uint8_t param, zb_ieee_addr_t source)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zll_scan_resp_t *resp = (zb_zll_scan_resp_t *)ZB_BUF_BEGIN(buf);
    zb_ushort_t frame_size = ZB_ZLL_TL_GET_SCAN_RESP_SIZE(resp);
    ZB_MEMCPY(&ZLL_COMM().scan_response, resp, frame_size);
    ZB_IEEE_ADDR_COPY(ZLL_COMM().responder_addr, source);
    ZB_BZERO(&ZLL_COMM().v_scan_channels, sizeof(zb_uint32_t));
    zb_free_buf(buf);
}

void zll_send_reset_fac_new_req(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    ZB_BUF_REUSE(buf);
    zb_uint32_t *transaction_id;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint32_t), transaction_id);
    *transaction_id = ZG->aps.transaction_id;

    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                 ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZLL_RESET_REQ_CMD_ID);

    zb_intrp_data_req_params_t *intrp;
    intrp = ZB_GET_BUF_TAIL(buf, sizeof(zb_intrp_data_req_params_t));
    intrp->clusterid = ZB_ZLL_CLUSTER_ID;
    intrp->profileid = ZB_ZLL_PROFILE_ID;
    intrp->src_addr_mode = ZB_ADDR_64BIT_DEV;
    intrp->dst_addr_mode = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
    intrp->dst_addr.addr_short = 0xffff;
    ZB_SCHEDULE_CALLBACK(zb_intrp_data_request, param);
}

void zll_nwk_rejoin()
{
    /* BDB TL Init Step 20 */
    ZG->nwk.nib.security_level = 5;

    zb_buf_t *buf = zb_get_out_buf();
    zb_nlme_join_request_t *request = ZB_GET_BUF_PARAM(buf, zb_nlme_join_request_t);
    ZB_IEEE_ADDR_COPY(request->extended_pan_id, ZB_AIB().aps_use_extended_pan_id);
    request->scan_channels = 0x00000000;
    ZB_MAC_CAP_SET_ALLOCATE_ADDRESS(request->capability_information, 1); //FIXME
    request->rejoin_network = ZB_NLME_REJOIN_METHOD_REJOIN;
    request->scan_duration = 0x00;
    request->security_enabled = ZB_TRUE;
    ZB_SCHEDULE_CALLBACK(zb_nlme_join_request, ZB_REF_FROM_BUF(buf));
}

void zll_nwk_rejoin_cb()
{
    ZB_SCHEDULE_ALARM_CANCEL(zll_timeout, 1);
    /* continue Step 26 */
    zll_comm_signal(ZB_ZLL_COMM_SUCCESS);
}

/* ----- ZLL COMMISSIONING LOGIC -------*/
void zll_scan_step(zb_uint8_t param)
{
    (void)param;
    if (ZLL_COMM().state != ZB_ZLL_COMM_SCAN) {
        return;
    }
    if (ZLL_COMM().v_scan_channels == 0x00000000) {
        /* BDB TL Init Step 4 */
        if (ZLL_COMM().v_do_prim_scan && BDB_CTX().secondary_channel_set != 0x00000000) {
            ZLL_COMM().v_do_prim_scan = ZB_FALSE;
            ZLL_COMM().v_scan_channels = BDB_CTX().secondary_channel_set;
            ZB_SCHEDULE_CALLBACK(zll_scan_step, 0);
            return;
        }
        zll_comm_signal(ZB_ZLL_COMM_SCAN_DONE);
        return;
    }
    zb_uint8_t channel;
    /* find next channel */
    for (channel = ZB_MAC_START_CHANNEL_NUMBER; channel <= ZB_MAC_MAX_CHANNEL_NUMBER;
         channel++) {
        if (ZLL_COMM().v_scan_channels & (1l << channel)) {
            break;
        }
    }
    /* BDB TL Init Step 3 (incomplete)*/
    ZLL_COMM().v_scan_channels &= ~(1l << channel);
    ZB_TRANSCEIVER_SET_CHANNEL(channel);
    if (ZLL_COMM().v_is_first_ch) {
        ZLL_COMM().v_is_first_ch = ZB_FALSE;
        for (zb_ushort_t i = 0; i < 4; i++) {
            ZB_GET_OUT_BUF_DELAYED(zll_send_scan_req);
        }
    }
    ZB_GET_OUT_BUF_DELAYED(zll_send_scan_req);
    ZB_SCHEDULE_ALARM(zll_scan_step, 0, BDB_TL_SCAN_TIME_DURATION);
}

void zll_start_tl_scan()
{
    zll_comm_signal(ZB_ZLL_COMM_SCAN);
}

void zll_finish_scan()
{
    /* BDB TL Init Step 5 */
    if (ZLL_COMM().scan_response.transaction_id != ZG->aps.transaction_id) {
        puts("no device found during tl scan");
        BDB_CTX().comm_status = NO_SCAN_RESPONSE;
        zll_comm_signal(ZB_ZLL_COMM_FAIL);
        return;
    }
    /**
     *  BDB TL Init Step 6 - choose a target
     * omitted, only take one response, terminate scan, ignore others
     */
    /* BDB TL Init Step 7 */
    if (ZB_ZLL_TL_DEV_INFO_REQ_REQUIRED(&(ZLL_COMM().scan_response))) {
        ZB_GET_OUT_BUF_DELAYED(zll_send_dev_info_req);
        return;
    }
    /* add info to dev_info_tbl */
    zb_apl_dev_info_ent_t *ent = &APL_CTX().dev_info_tbl[APL_CTX().dev_info_used];
    ZB_IEEE_ADDR_COPY(ent->long_addr, ZLL_COMM().responder_addr);
    ent->endpoint = ZLL_COMM().scan_response.endpoint;
    ent->profile_id = ZLL_COMM().scan_response.profile_id;
    ent->device_id = ZLL_COMM().scan_response.device_id;
    ent->version = ZLL_COMM().scan_response.version;
    ent->group_id_count = ZLL_COMM().scan_response.group_id_count;
    ent->sort = 0;
    APL_CTX().dev_info_used++;
    zll_comm_signal(ZB_ZLL_COMM_INIT_NET);
}

void zll_initiate_network()
{
    /* BDB TL Init Step 8: check if he opponent is on our network*/
    if (!ZB_MEMCMP(ZLL_COMM().scan_response.extended_pan_id, ZB_AIB().aps_use_extended_pan_id,
                   sizeof(zb_ieee_addr_t))) {
        /* BDB TL Init Step 9 */
        if (ZLL_COMM().scan_response.network_update_id < ZB_NIB_UPDATE_ID()) {
            ZB_GET_OUT_BUF_DELAYED(zll_send_net_update);
        }
        else {
            /* updating addresses */
            zb_address_ieee_ref_t addr_ref;
            zb_address_update(ZLL_COMM().responder_addr, ZLL_COMM().scan_response.network_address,
                              ZB_FALSE, &addr_ref);
        }
        if (ZLL_COMM().scan_response.network_update_id > ZB_NIB_UPDATE_ID()) {
            ZB_NIB_UPDATE_ID() = ZLL_COMM().scan_response.network_update_id;
            ZB_TRANSCEIVER_SET_CHANNEL(ZLL_COMM().scan_response.logical_channel);
        }
        puts("responder is on the same pan");
        /* continue Step 26 */
        zll_comm_signal(ZB_ZLL_COMM_SUCCESS);
        return;
    }
    /* BDB TL Init Step 10 check for centralized network */
    if (!ZB_MEMCMP(ZB_AIB().trust_center_address, &ZB_IEEE_ADDR_BROADCAST, sizeof(zb_ieee_addr_t))) {
        BDB_CTX().comm_status = NOT_PERMITTED;
        puts("part of centralized net");
        /* TODO add BDB-Handle? */
        return;
    }
    /* BDB TL Init Step 11 check addr assignment capability */
    if (!ZB_MAC_CAP_GET_ALLOCATE_ADDRESS(ZB_ZDO_NODE_DESC()->mac_capability_flags)) {
        BDB_CTX().comm_status = NOT_AA_CAPABLE;
        puts("unable to assign addresses");
        return;
    }
    /* lets assing an address to target which can be used in requests */
    ZLL_COMM().responder_addr_short = APL_CTX().free_addr_range_begin;
    APL_CTX().free_addr_range_begin++;
    /* BDB TL Init Step 12 */
    if (BDB_CTX().node_is_on_net) {
        puts("we are already on a network");
        /* continue from Step 23 */
        ZB_GET_OUT_BUF_DELAYED(zll_send_net_join);
        return;
    }
    /* BDB TL Init Step 13 */
    if (ZB_GET_NODE_DESC_LOGICAL_TYPE(ZB_ZDO_NODE_DESC()) == ZB_ROUTER) {
        puts("we must do router things");
        /** 
         * TODO Step 21 
         *  - NLME-NETWORK-DISCOVERY.request
         * TODO Step 22
         *  - NLME-START_ROUTER.request
         */
        ZB_GET_OUT_BUF_DELAYED(zll_send_net_join);
        return;
    }

    zb_uint8_t zb_info = ZLL_COMM().scan_response.zigbee_information;
    /* BDB TL Init Step 14 */
    if (ZB_ZCL_GET_ZB_DEV_TYPE(zb_info) != ZB_ZCL_ZB_DEV_TYPE_ROUTER) {
        BDB_CTX().comm_status = NO_NETWORK;
        puts("opponent is no router");
        return;
    }
    /* BDB TL Init Step 16 */
    ZB_GET_OUT_BUF_DELAYED(zll_send_net_start_req);
    ZB_SCHEDULE_ALARM(zll_timeout, 0, BDB_RX_WINDOW_DURATION);
}

void zll_timeout(zb_uint8_t param)
{
    switch (param) {
    case 0:
        BDB_CTX().comm_status = NO_NETWORK;
        break;
    case 1:
        BDB_CTX().comm_status = TARGET_FAILURE;
        break;
    default:
        break;
    }
}

void zll_comm_signal(zb_zll_comm_state_t state)
{
    ZLL_COMM().state = state;
    switch (state) {
    case ZB_ZLL_COMM_SCAN:
        ZLL_COMM().prev_channel = zb_transceiver_get_channel();
        /* BDB TL Init Step 1 */
        BDB_CTX().comm_status = IN_PROGRESS;
        /* BDB TL Init Step 2 */
        ZG->aps.transaction_id = (zb_uint32_t)ZB_RANDOM() | (ZB_RANDOM() << 16);
        ZLL_COMM().v_scan_channels = BDB_CTX().primary_channel_set;
        ZLL_COMM().v_is_first_ch = ZB_TRUE;
        ZB_SCHEDULE_CALLBACK(zll_scan_step, 0);
        return;
    case ZB_ZLL_COMM_SCAN_DONE:
        zll_finish_scan();
        return;
    case ZB_ZLL_COMM_INIT_NET:
        zll_initiate_network();
        return;
    case ZB_ZLL_COMM_REJOIN:
        return;
    case ZB_ZLL_COMM_FAIL:
        return;
    case ZB_ZLL_COMM_SUCCESS:
        puts("saving config");
        /** BDB TL Init Step 26 
         * TODO: binding links
         */
        ZB_NIB_SECURITY_LEVEL() = 5;
        BDB_CTX().node_is_on_net = ZB_TRUE;
        BDB_CTX().comm_status = SUCCESS;
        /* save everything now */
        zb_write_security_key();
        zb_save_formdesc_data();
        zb_save_nvram_config();
        return;
    default:
        return;
    }
}

void handle_zll_cli(zb_uint16_t src_addr, zb_uint8_t src_ep,
                zb_uint16_t profile_id, zb_uint8_t param,
                zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);
    zb_zcl_parsed_hdr_t *hdr = ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t);
    /* during touchlink commissioning, only ieee addr are present! */
    /* move this to zcl_parse_hdr maybe? */
    zb_mac_mhr_t mac_hdr;
    zb_parse_mhr(&mac_hdr, buf->buf + buf->u.hdr.mac_hdr_offset);
    zb_ieee_addr_t source;
    ZB_IEEE_ADDR_COPY(&source, &mac_hdr.src_addr.addr_long);

    /* commands received */
    switch (hdr->cmd_id) {
    case ZB_ZLL_SCAN_RESP_CMD_ID: /* scan response */
        zll_handle_scan_resp(param, source);
        break;
    case ZB_ZLL_DEV_INFO_RESP_CMD_ID: /* dev info response */
        zll_handle_dev_info_resp(param);
        break;
    case ZB_ZLL_NET_START_RESP_CMD_ID: /* network start response */
        zll_handle_net_start_resp(param, source);
        break;
    case ZB_ZLL_NET_JOIN_R_RESP_CMD_ID: /* network join router response */
        zll_handle_net_join_resp(param);
        break;
    case ZB_ZLL_NET_JOIN_ED_RESP_CMD_ID: /* network join end device response */
        zll_handle_net_join_resp(param);
        break;
    default:
        zb_free_buf(buf);
    }
}

void zb_zcl_zll_initiator_setup()
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
        ZLL_COMM().zigbee_info = ZB_ZCL_ZB_DEV_TYPE_ED;
        break;
    }
    ZLL_COMM().zigbee_info |= (0x1 & ZB_PIB_RX_ON_WHEN_IDLE()) << 2;
    /* 0x10 we are initiator */
    ZLL_COMM().touchlink_info = 0x10;
    if (ZB_TOUCHLINK_FACT_NEW) {
        ZLL_COMM().touchlink_info |= 1;
    }
    /* 0x02 addr assignment capable */
    if (ZB_MAC_CAP_GET_ALLOCATE_ADDRESS(ZB_ZDO_NODE_DESC()->mac_capability_flags)) {
        ZLL_COMM().touchlink_info |= 2;
    }
    /* 0x80 we can do ZB 3.0 (correct?) */
    if (ZB_PROTOCOL_VERSION > 1) {
        ZLL_COMM().touchlink_info |= 0x80;
    }

    ZB_BZERO(&ZLL_COMM().scan_response, sizeof(ZLL_COMM().scan_response));
    ZLL_COMM().state = ZB_ZLL_COMM_SCAN;
    /**
     * Lets assign ourelves the address of 1
     */
    if (ZB_PIB_SHORT_ADDRESS() != 1) { // FIXME
        ZB_PIB_SHORT_ADDRESS() = APL_CTX().free_addr_range_begin;
        zb_transceiver_update_short_addr(APL_CTX().free_addr_range_begin);
        APL_CTX().free_addr_range_begin++;
    }
    (void)zb_zcl_register_cluster(1 /* EP 1 */, ZB_ZLL_CLUSTER_ID /* TL Cluster */,
                                  ZB_ZCL_CLIENT_ROLE, handle_zll_cli, NULL /* action */);
    /**
     * from BDB 10.2.2: if TC is not known - commissionig process should set it to broadcast
     * TODO: move this to BDB logic when possible 
     */
    ZB_AIB().trust_center_address[0] = 1;
    if (ZB_IEEE_ADDR_IS_ZERO(ZB_AIB().trust_center_address)) {
        ZB_IEEE_ADDR_COPY(ZB_AIB().trust_center_address, ZB_IEEE_ADDR_BROADCAST);
    }
    if (ZB_NIB_PAN_ID() == 0xffff || ZB_PIB_SHORT_PAN_ID() == 0xffff) {
        /* to avoid pan id compression, as we are not on any network */
        ZB_PIB_SHORT_PAN_ID() = ZB_RANDOM();
        ZB_NIB_PAN_ID() = ZB_PIB_SHORT_PAN_ID();
        zb_transceiver_set_pan_id(ZB_PIB_SHORT_PAN_ID());
        ZB_UPDATE_PAN_ID();
    }
}
#endif /* ZB_LIMITED_FEATURES */
/*! @} */
