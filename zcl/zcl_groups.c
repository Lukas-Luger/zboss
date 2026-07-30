#include "zb_common.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zb_zcl_groups.h"
#include "zcl_internal.h"
#include "log.h"

zb_zcl_global_attrs_t groups_global_attrs;
/**
 * Server Side
 */
static void send_add_group_resp(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsme_add_group_conf_t conf;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&conf, ZB_GET_BUF_PARAM(buf, zb_apsme_add_group_conf_t), sizeof(zb_apsme_add_group_conf_t));
    ZB_MEMCPY(&zcl_hdr, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_zcl_groups_add_group_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_add_group_resp_t), resp);
    resp->status = conf.status;
    resp->group_id = conf.group_address;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_GROUPS_ADD_GROUP);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = ZB_GROUPS_CLUSTER_ID;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void handle_add_group(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_groups_add_group_req_t req;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&req, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_groups_add_group_req_t));
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_zcl_parsed_hdr_t *zcl_hdr2;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_parsed_hdr_t), zcl_hdr2);
    ZB_MEMCPY(zcl_hdr2, &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    zb_apsme_add_group_req_t *req_ptr = ZB_GET_BUF_PARAM(buf, zb_apsme_add_group_req_t);
    req_ptr->group_address = req.group_id;
    req_ptr->endpoint = zcl_hdr.dst_endpoint;
    req_ptr->confirm_cb = send_add_group_resp;
    ZB_SCHEDULE_CALLBACK(zb_zdo_add_group_req, param);
}

static void send_view_group_resp(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsme_get_group_membership_conf_t conf;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&conf, ZB_GET_BUF_PARAM(buf, zb_apsme_get_group_membership_conf_t),
                            sizeof(zb_apsme_get_group_membership_conf_t));
    ZB_MEMCPY(&zcl_hdr, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_zcl_groups_view_group_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_view_group_resp_t), resp);
    resp->status = (conf.n_groups == 0) ? ZB_ZCL_STATUS_NOT_FOUND : ZB_ZCL_STATUS_SUCCESS;
    resp->group_id = conf.groups[0];
    resp->length = 0; // we do not support names currently (length of following string)
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_GROUPS_VIEW_GROUP);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = ZB_GROUPS_CLUSTER_ID;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void handle_view_group(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_groups_view_group_req_t req;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&req, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_groups_view_group_req_t));
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));

    zb_buf_reuse(buf);
    zb_zcl_parsed_hdr_t *zcl_hdr2;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_parsed_hdr_t), zcl_hdr2);
    ZB_MEMCPY(zcl_hdr2, &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    zb_apsme_get_group_membership_req_t *get_req = ZB_GET_BUF_PARAM(buf, zb_apsme_get_group_membership_req_t);
    get_req->n_groups = 1;
    get_req->groups[0] = req.group_id;
    get_req->endpoint = zcl_hdr.dst_endpoint;
    get_req->confirm_cb = send_view_group_resp;
    ZB_SCHEDULE_CALLBACK(zb_zdo_get_group_membership_req, param);
}

static void send_get_group_membership_resp(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsme_get_group_membership_conf_t conf;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&conf, ZB_GET_BUF_PARAM(buf, zb_apsme_get_group_membership_conf_t),
                            sizeof(zb_apsme_get_group_membership_conf_t));
    ZB_MEMCPY(&zcl_hdr, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_zcl_groups_get_group_membership_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint8_t)*2 + sizeof(zb_uint16_t)*conf.n_groups, resp);
    resp->group_capacity = conf.capacity;
    resp->group_count = conf.n_groups;
    ZB_MEMCPY(resp->group_list, conf.groups, sizeof(zb_uint16_t)*conf.n_groups);
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_GROUPS_GET_GR_MEMBERSHIP);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = ZB_GROUPS_CLUSTER_ID;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void handle_get_group_membership(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_groups_get_group_membership_req_t req;
    zb_zcl_groups_get_group_membership_req_t *ptr = (zb_zcl_groups_get_group_membership_req_t *)ZB_BUF_BEGIN(buf);
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&req, ptr, sizeof(zb_uint8_t) + ptr->group_count*sizeof(zb_uint16_t));
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));

    zb_buf_reuse(buf);
    zb_zcl_parsed_hdr_t *zcl_hdr2;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_parsed_hdr_t), zcl_hdr2);
    ZB_MEMCPY(zcl_hdr2, &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    zb_apsme_get_group_membership_req_t *get_req = ZB_GET_BUF_PARAM(buf, zb_apsme_get_group_membership_req_t);
    get_req->n_groups = req.group_count;
    ZB_MEMCPY(get_req->groups, req.group_list, sizeof(zb_uint16_t)*req.group_count);
    get_req->endpoint = zcl_hdr.dst_endpoint;
    get_req->confirm_cb = send_get_group_membership_resp;
    ZB_SCHEDULE_CALLBACK(zb_zdo_get_group_membership_req, param);
}

static void send_remove_group_resp(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsme_remove_group_conf_t conf;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&conf, ZB_GET_BUF_PARAM(buf, zb_apsme_remove_group_conf_t),
            sizeof(zb_apsme_remove_group_conf_t));
    ZB_MEMCPY(&zcl_hdr, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_zcl_groups_remove_group_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_remove_group_resp_t), resp);
    resp->status = conf.status;
    resp->group_id = conf.group_address;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_GROUPS_REMOVE_GROUP);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = ZB_GROUPS_CLUSTER_ID;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void handle_remove_group(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_groups_remove_group_req_t req;
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&req, ZB_BUF_BEGIN(buf), sizeof(zb_zcl_groups_remove_group_req_t));
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));

    zb_buf_reuse(buf);
    zb_zcl_parsed_hdr_t *zcl_hdr2;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_parsed_hdr_t), zcl_hdr2);
    ZB_MEMCPY(zcl_hdr2, &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    zb_apsme_remove_group_req_t *rem_req = ZB_GET_BUF_PARAM(buf, zb_apsme_remove_group_req_t);
    rem_req->group_address = req.group_id;
    rem_req->endpoint =  zcl_hdr.dst_endpoint;
    rem_req->confirm_cb = send_remove_group_resp;
    ZB_SCHEDULE_CALLBACK(zb_zdo_remove_group_req, param);
}

static void send_remove_all_groups_resp(zb_uint8_t param) ZB_CALLBACK
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_free_buf(buf);
}

void handle_remove_all_groups(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));

    zb_buf_reuse(buf);
    zb_zcl_parsed_hdr_t *zcl_hdr2;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_parsed_hdr_t), zcl_hdr2);
    ZB_MEMCPY(zcl_hdr2, &zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));
    zb_apsme_remove_all_groups_req_t *rem_req = ZB_GET_BUF_PARAM(buf, zb_apsme_remove_all_groups_req_t);
    rem_req->endpoint = zcl_hdr.dst_endpoint;
    rem_req->confirm_cb = send_remove_all_groups_resp;
    ZB_SCHEDULE_CALLBACK(zb_zdo_remove_all_groups_req, param);
}

zb_bool_t handle_groups_srv(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t *zcl_hdr = ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t);
    zb_bool_t is_handled = ZB_TRUE;
    switch (zcl_hdr->cmd_id) {
    case ZB_ZCL_GROUPS_ADD_GROUP: /* add group */
        puts("adding group");
        handle_add_group(param);
        break;
    case ZB_ZCL_GROUPS_VIEW_GROUP: /* view group */
        handle_view_group(param);
        break;
    case ZB_ZCL_GROUPS_GET_GR_MEMBERSHIP: /* get group membership */
        handle_get_group_membership(param);
        break;
    case ZB_ZCL_GROUPS_REMOVE_GROUP: /* remove group */
        handle_remove_group(param);
        break;
    case ZB_ZCL_GROUPS_REMOVE_ALL_GROUPS: /* remove all groups */
        puts("remove all groups");
        handle_remove_all_groups(param);
        break;
    case ZB_ZCL_GROUPS_ADD_GR_IF_ID: /* FIXME add group if identifying */
        handle_add_group(param);
        break;
    default:
        is_handled = ZB_FALSE;
        break;
    }
    return is_handled;
}

void zb_zcl_groups_srv_setup(zb_zcl_cluster_t *cluster)
{
    zb_zcl_reg_cl_handlers(ZB_GROUPS_CLUSTER_ID, ZB_ZCL_SERVER_ROLE, handle_groups_srv);
    zb_zcl_groups_srv_attr_t *attrs = (zb_zcl_groups_srv_attr_t *)cluster->data;
    groups_global_attrs.cluster_revision = ZB_ZCL_DEFAULT_CLUSTER_REVISION();
    groups_global_attrs.reporting_status = ZB_ZCL_ATTR_REPORTING_COMPLETE;
    zb_zcl_add_attribute(cluster, 0xfffd, ZB_ZCL_ATTR_TYPE_U16, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(groups_global_attrs.cluster_revision));
    zb_zcl_add_attribute(cluster, 0xfffe, ZB_ZCL_ATTR_TYPE_ENUM8, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(groups_global_attrs.reporting_status));
    zb_zcl_add_attribute(cluster, 0, ZB_ZCL_ATTR_TYPE_8BITMAP, ZB_ZCL_ATTR_ACCESS_READ_ONLY, &(attrs->name_support));
}

/**
 * Client Side (Called by application)
 * TODO: handle responses from server!
 */
void zb_zcl_groups_send_add_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    zb_zcl_groups_add_group_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_add_group_req_t), req);
    req->group_id = group_id;
    req->length = 0;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_ADD_GROUP);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_send_view_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    zb_zcl_groups_view_group_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_view_group_req_t), req);
    req->group_id = group_id;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_VIEW_GROUP);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_send_get_group_membership(zb_uint8_t param, zb_uint16_t profile_id, zb_uint8_t n_groups,
                                    zb_uint16_t group_list[ZB_APS_GROUP_TABLE_SIZE],
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    zb_zcl_groups_get_group_membership_req_t *req;
    zb_ushort_t group_size = sizeof(zb_uint16_t) * n_groups;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint8_t) + group_size, req);
    req->group_count = n_groups;
    ZB_MEMCPY(req->group_list, group_list, group_size);
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_GET_GR_MEMBERSHIP);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_send_remove_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    zb_zcl_groups_remove_group_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_remove_group_req_t), req);
    req->group_id = group_id;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_REMOVE_GROUP);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_send_remove_all_groups(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                                        zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    //ZB_BUF_INITIAL_ALLOC(buf, 0, NULL);
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_REMOVE_ALL_GROUPS);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_send_add_group_iid(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_buf_reuse(buf);
    zb_zcl_groups_add_group_iid_req_t *req;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_groups_add_group_iid_req_t), req);
    req->group_id = group_id;
    req->length = 0;
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED,
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV, ZB_TRUE, ZB_ZCL_GROUPS_ADD_GR_IF_ID);

    zb_apsde_data_req_t *aps_req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    aps_req->dst_addr = dst_addr;
    aps_req->profileid = profile_id;
    aps_req->clusterid = ZB_GROUPS_CLUSTER_ID;
    aps_req->dst_endpoint = dst_ep;
    aps_req->src_endpoint = src_ep;
    aps_req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    aps_req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_groups_cli_setup(zb_zcl_cluster_t *cluster)
{
    (void)cluster;
    zb_zcl_reg_cl_handlers(ZB_GROUPS_CLUSTER_ID,
                                ZB_ZCL_CLIENT_ROLE, NULL);
}
