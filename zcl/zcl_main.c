
#include "zb_common.h"
#include "zb_zcl.h"
#include "zb_zcl_groups.h"
#include "zb_aps.h"
#include "zcl_internal.h"
#include "zcl_zll_internal.h"

void zb_zcl_cib_init();
zb_zcl_attr_t *zb_zcl_find_attribute(zb_zcl_cluster_t *cluster,
                                     zb_uint16_t attribute_id);
zb_uint8_t zb_zcl_get_attribute_size(zb_zcl_attr_t *attr);
void zb_zcl_init()
{
    TRACE_MSG(TRACE_ZCL1, "+zcl_init", (FMT__0));

    zb_zcl_cib_init();

    TRACE_MSG(TRACE_ZCL1, "-zcl_init", (FMT__0));
}

void zb_zcl_cib_init()
{
    TRACE_MSG(TRACE_ZCL1, ">>cib_init", (FMT__0));
    /* initialize params here using ZG->zcl */
    ZG->zcl.seq_number = 0;
    ZB_BZERO(&ZG->zcl.device_ctx, sizeof(zb_zcl_globals_t)*ZB_MAX_EP_NUMBER);

    TRACE_MSG(TRACE_ZCL1, "<<cib_init", (FMT__0));
}

/*
    Alloc and fill full zcl hdr, return pointer to the allocated hdr
 */
zb_zcl_hdr_full_t *zcl_alloc_and_fill_full_hdr(zb_buf_t *buf,
                                               zb_zcl_frame_type_t type,
                                               zb_zcl_frame_direction_t direction,
                                               zb_bool_t default_resp,
                                               zb_uint8_t cmd,
                                               zb_uint16_t man_code)
{
    zb_zcl_hdr_full_t *zchdr;
    zb_ushort_t hdr_size = sizeof(zb_zcl_hdr_full_t);

    ZB_BUF_ALLOC_LEFT(buf, hdr_size, zchdr);

    zchdr->frame_control.frame_type = type;
    zchdr->frame_control.manufacturer = 0x1;
    zchdr->frame_control.direction = direction;
    zchdr->frame_control.disable_def_resp = default_resp;
    zchdr->frame_control.reserved = 0x0;
    zchdr->manufacturer_code = man_code;
    zchdr->seq_number = ZB_ZCL_GET_SEQ_NUM();
    zchdr->command_id = cmd;

    return zchdr;
}
/*
    Alloc and fill zcl hdr, return pointer to the allocated hdr
 */
zb_zcl_hdr_t *zcl_alloc_and_fill_hdr(zb_buf_t *buf,
                                     zb_zcl_frame_type_t type,
                                     zb_zcl_frame_direction_t direction,
                                     zb_bool_t default_resp,
                                     zb_uint8_t cmd)
{
    zb_zcl_hdr_t *zchdr;
    zb_ushort_t hdr_size = sizeof(zb_zcl_hdr_t);

    ZB_BUF_ALLOC_LEFT(buf, hdr_size, zchdr);

    zchdr->frame_control.frame_type = type & 0x3;
    zchdr->frame_control.manufacturer = 0x0;
    zchdr->frame_control.direction = direction & 0x1;
    zchdr->frame_control.disable_def_resp = default_resp & 0x1;
    zchdr->frame_control.reserved = 0x0;
    zchdr->seq_number = ZB_ZCL_GET_SEQ_NUM();
    zchdr->command_id = cmd;

    return zchdr;
}
void zb_zcl_send_default_resp(zb_uint8_t param, zb_zcl_parsed_hdr_t hdr, zb_zcl_status_t status)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_default_resp_t *resp;
    ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_default_resp_t), resp);
    resp->resp_cmd = hdr.cmd_id;
    resp->status = (zb_uint8_t) status;
    
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_COMMON,
                                1 - hdr.direction, ZB_TRUE, ZB_ZCL_DEFAULT_RESPONSE_CMD_ID);

    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = hdr.src_addr;
    req->profileid = hdr.profile_id;
    req->clusterid = hdr.cluster_id;
    req->dst_endpoint = hdr.src_endpoint;
    req->src_endpoint = hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}
/* TODO: reporting logic */

/* GENERAL COMMANDS */
void zb_zcl_handle_read_attr(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    if (ZB_BUF_LEN(buf) % 2 != 0) {
        zb_free_buf(buf);
        return;
    }
    zb_ushort_t i;
    zb_zcl_attr_t *attr;
    zb_uint16_t *ptr = (zb_uint16_t *) ZB_BUF_BEGIN(buf);
    zb_ushort_t tmp_size;
    zb_uint8_t records[128];
    zb_uint8_t j = 0;
    for (i = 0; i < ZB_BUF_LEN(buf)/2; ++i) {
        attr = zb_zcl_find_attribute(cluster, *(zb_uint16_t *)ptr);
        zb_zcl_read_attr_record_t record;
        if (attr) {
            record.attr_id = attr->id;
            record.status = ZB_ZCL_STATUS_SUCCESS;
            record.type = attr->type;
            ZB_MEMCPY(&records[j], &record, sizeof(zb_zcl_read_attr_record_t));
            j += sizeof(zb_zcl_read_attr_record_t);
            tmp_size = zb_zcl_get_attribute_size(attr);
            ZB_MEMCPY(&records[j], attr->data_p, tmp_size);
            j += tmp_size;
        }
        else {
            record.attr_id = *(zb_uint16_t *)ptr;
            record.status = ZB_ZCL_STATUS_UNSUP_ATTRIB;
            tmp_size =  sizeof(zb_zcl_read_attr_record_t) - sizeof(zb_zcl_attr_type_t);
            ZB_MEMCPY(&records[j], &record, tmp_size);
            j += tmp_size;
        }
        ptr++;

    }
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_uint8_t *resp_ptr;
    ZB_BUF_INITIAL_ALLOC(buf, j, resp_ptr);
    ZB_MEMCPY(resp_ptr, records, j);
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_COMMON,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_CMD_READ_ATTRIB_RESP);
                                
    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = cluster->cluster_id;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_handle_write_attr(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    
    zb_zcl_attr_t *attr;
    zb_uint8_t *ptr = (zb_uint8_t *) ZB_BUF_BEGIN(buf);
    zb_ushort_t tmp_size;
    zb_zcl_write_attr_resp_record_t records[16];
    zb_uint8_t i = 0;
    while ((ptr - ZB_BUF_BEGIN(buf)) < ZB_BUF_LEN(buf) && i < 16) {
        attr = zb_zcl_find_attribute(cluster, *(zb_uint16_t *)ptr);
        records[i].attr_id = *(zb_uint16_t *)ptr;
        ptr += sizeof(zb_uint16_t);        
        if (attr) {
            records[i].status = ZB_ZCL_STATUS_SUCCESS;
            if (*ptr != attr->type) {
                records[i].status = ZB_ZCL_STATUS_INVALID_TYPE;
            }
            if (attr->access == ZB_ZCL_ATTR_ACCESS_READ_ONLY) {
                records[i].status = ZB_ZCL_STATUS_READ_ONLY;
            }
            if (/* TODO: out of range*/ ZB_FALSE) {
                records[i].status = ZB_ZCL_STATUS_INVALID_VALUE;
            }
            tmp_size = zb_zcl_get_attribute_size(attr);
            ZB_MEMCPY(attr->data_p, ptr, tmp_size);
        }
        else {
            records[i].status = ZB_ZCL_STATUS_UNSUP_ATTRIB;
        }
        ptr++; // type
        ptr += tmp_size; // value size
        /* only save unsuccessful ones to save bandwidth */
        if (records[i].status != ZB_ZCL_STATUS_SUCCESS) {
            i++;
        }

    }
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));
    
    zb_buf_reuse(buf);
    zb_uint8_t *resp_ptr;
    /* all attributes got written successfully */
    if (i == 0) {
        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint8_t), resp_ptr);
        *resp_ptr = ZB_ZCL_STATUS_SUCCESS;
    }
    else {
    /* some attributes failed */
        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_write_attr_resp_record_t) * i, resp_ptr);
        ZB_MEMCPY(resp_ptr, records, sizeof(zb_zcl_write_attr_resp_record_t) * i);
    }
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_COMMON,
                                ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE, ZB_ZCL_CMD_WRITE_ATTRIB_RESP);
                                
    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = cluster->cluster_id;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
}

void zb_zcl_handle_conf_reporting(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_uint8_t *ptr = (zb_uint8_t *) ZB_BUF_BEGIN(buf);
    
    zb_uint8_t direction;
    zb_zcl_attr_t attr;
    zb_zcl_attr_t *local_attr;
    zb_uint8_t i = 0;
    zb_zcl_attr_status_record_t status_records[16];
    while ((ptr - ZB_BUF_BEGIN(buf)) < ZB_BUF_LEN(buf) && i < 16) {
        direction = *ptr;
        ptr++;
        attr.id = *(zb_uint16_t *)ptr;
        ptr += 2;
        status_records[i].attr_id = attr.id;
        status_records[i].direction = direction;
        if (direction == 0) {
            /* we have to send reports */
            attr.type = *ptr; //attr type field
            ptr++;
            zb_uint16_t min_interval = *(zb_uint16_t *)ptr;//minimum reporting interval field (seconds)
            ptr += 2;
            zb_uint16_t max_interval = *(zb_uint16_t *)ptr; //maximum reporting interval field (seconds)
            ptr += 2;
            local_attr = zb_zcl_find_attribute(cluster, attr.id);
            if (!local_attr) {
                status_records[i].status = ZB_ZCL_STATUS_UNSUP_ATTRIB;
                i++;
            }
            else if (attr.type == ZB_ZCL_ATTR_TYPE_ARRAY || attr.type == ZB_ZCL_ATTR_TYPE_STRUCT ||
                     attr.type ==  ZB_ZCL_ATTR_TYPE_SET || attr.type == ZB_ZCL_ATTR_TYPE_BAG) {
                status_records[i].status = ZB_ZCL_STATUS_UNREPORTABLE_ATTRIB;
                i++;
            }
            else if (/* TODO: check if it can not be reported */ ZB_TRUE) {
                /* Complex reporting logic needed (also accessible from APP) */
                status_records[i].status = ZB_ZCL_STATUS_UNREPORTABLE_ATTRIB;
                i++;
            }
            else if (attr.type != local_attr->type) {
                status_records[i].status = ZB_ZCL_STATUS_INVALID_TYPE;
                i++;
            }
            else if (/* TODO: check min/max value >/< specified min/max */ ZB_FALSE) {
                status_records[i].status = ZB_ZCL_STATUS_INVALID_VALUE;
                i++;
            }
            else {
                /* set interval/value change */
                /* do not increase i on success, only store failed attrs! */
                /* functionality see: 2.5.11.2.[1-4] */
                if (max_interval == 0x0000) {
                    if (min_interval != 0xffff) {
                        /* attr change based reporting */
                        attr.data_p = ptr; //the reportable change field <sizeof attrib type>
                        ptr += zb_zcl_get_attribute_size(&attr);
                    }
                    else {
                        /* revert reporting config */
                    }
                }
                if (max_interval == 0xffff) {
                    /* no reporting */
                    continue;
                }
            }
        }
        else {
            /* we will receive reports */
            zb_uint16_t timeout = *(zb_uint16_t *)ptr; // timeout period field is included in the payload
            ptr += 2;
            /* we do not support timeouts currently */
            status_records[i].status = ZB_ZCL_STATUS_UNREPORTABLE_ATTRIB;
            i++;
        }
    }
    zb_zcl_parsed_hdr_t zcl_hdr;
    ZB_MEMCPY(&zcl_hdr, ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t), sizeof(zb_zcl_parsed_hdr_t));
    zb_buf_reuse(buf);
    zb_uint8_t *resp_ptr;
    if (i == 0) {
        /* everything went smoothly */
        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_uint8_t), resp_ptr);
        *resp_ptr = ZB_ZCL_STATUS_SUCCESS;
    }
    else {
        /* got some errors */
        ZB_BUF_INITIAL_ALLOC(buf, sizeof(zb_zcl_attr_status_record_t) * i, resp_ptr);
        ZB_MEMCPY(resp_ptr, status_records, sizeof(zb_zcl_attr_status_record_t) * i);
    }
    (void)zcl_alloc_and_fill_hdr(buf, ZB_ZCL_FRAME_TYPE_COMMON,
                             1 - zcl_hdr.direction, ZB_TRUE, ZB_ZCL_CMD_CONFIG_REPORT_RESP);
                                
    zb_apsde_data_req_t *req = ZB_GET_BUF_TAIL(buf, sizeof(zb_apsde_data_req_t));
    ZB_BZERO(req, sizeof(zb_apsde_data_req_t));
    req->dst_addr = zcl_hdr.src_addr;
    req->profileid = zcl_hdr.profile_id;
    req->clusterid = cluster->cluster_id;
    req->dst_endpoint = zcl_hdr.src_endpoint;
    req->src_endpoint = zcl_hdr.dst_endpoint;
    req->addr_mode = ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req->tx_options = ZB_APSDE_TX_OPT_ACK_TX;
    ZB_SCHEDULE_CALLBACK(zb_apsde_data_request, param);
    
}
zb_zcl_status_t zb_zcl_handle_general_cmd(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_status_t ret = ZB_ZCL_STATUS_SUCCESS;
    zb_zcl_parsed_hdr_t *zcl_hdr = ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t);
    switch (zcl_hdr->cmd_id) {
    case ZB_ZCL_CMD_READ_ATTRIB:
        zb_zcl_handle_read_attr(param, cluster);
        break;
    case ZB_ZCL_CMD_WRITE_ATTRIB:
        zb_zcl_handle_write_attr(param, cluster);
        break;
    case ZB_ZCL_CMD_CONFIG_REPORT:
        zb_zcl_handle_conf_reporting(param, cluster);
        break;
    /* TODO: all others! (zb_zcl_cmd_t)*/
    default:
        printf("Not implemented command: %x\n", zcl_hdr->cmd_id);
        zb_free_buf(buf);
        ret = ZB_ZCL_STATUS_FAIL;
        break;
    }
    return ret;

}

zb_zcl_cluster_handler_t zb_zcl_get_cluster_handler(zb_uint16_t cluster_id,
                                                    zb_zcl_cluster_role_t role)
{
    zb_uint8_t i;
    zb_zcl_cluster_handler_t ret = NULL;
    for (i = 0; i < ZG->zcl.handler_count; i++) {
        if (ZG->zcl.handlers[i].cluster_id == cluster_id &&
            ZG->zcl.handlers[i].role == role)
        {
            ret = ZG->zcl.handlers[i].handle;
            break;
        }
    }
    return ret;
}

zb_zcl_status_t zb_zcl_handle(zb_uint8_t param, zb_zcl_cluster_t *cluster)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t *zcl_hdr;
    zb_zcl_status_t status = ZB_ZCL_STATUS_SUCCESS;
    zcl_hdr = ZB_GET_BUF_PARAM(buf, zb_zcl_parsed_hdr_t);
    
    zb_ushort_t hdr_size = ZB_ZCL_FRAME_HDR_GET_SIZE(ZB_BUF_BEGIN(buf));
    ZB_BUF_CUT_LEFT2(buf, hdr_size);
   
    zb_zcl_cluster_handler_t handler = zb_zcl_get_cluster_handler(zcl_hdr->cluster_id,
            (zcl_hdr->direction == ZB_ZCL_FRAME_DIRECTION_TO_SRV) ?
                                  ZB_ZCL_SERVER_ROLE : ZB_ZCL_CLIENT_ROLE);
    // here we have to decide if its a common command or should be handled by the cluster itself
    if (handler && zcl_hdr->type == ZB_ZCL_FRAME_TYPE_CLUSTER_SPECIFIED) {
        (void)handler(param);
    }
    if (zcl_hdr->type == ZB_ZCL_FRAME_TYPE_COMMON) {
        status = zb_zcl_handle_general_cmd(param, cluster);
    }
    return status;
}

zb_af_ep_desc_t *zb_af_get_ep_desc(zb_uint8_t ep)
{
    zb_uint8_t i;
    zb_af_ep_desc_t *ret = NULL;
    for (i = 0; i < ZCL_CTX().device_ctx.ep_count; i++) {
        if (ZCL_CTX().device_ctx.ep_list[i]->ep_id == ep) {
            ret = ZCL_CTX().device_ctx.ep_list[i];
            break;
        }
    }
    return ret;
}

zb_zcl_cluster_t *zb_get_cluster_desc(zb_af_ep_desc_t *endpoint, zb_uint16_t cluster_id,
                                      zb_zcl_cluster_role_t role)
{
    zb_uint8_t i;
    zb_zcl_cluster_t *ret = NULL;
    for (i = 0; i < endpoint->cluster_count; i++) {
        
        if (endpoint->clusters[i].role == role && 
            endpoint->clusters[i].cluster_id == cluster_id)
        {
            ret = &(endpoint->clusters[i]);
            break;
        }
    }
    return ret;
}

zb_af_ep_desc_t *zb_get_ep_by_cluster(zb_uint16_t cluster_id, zb_zcl_cluster_role_t role)
{
    zb_uint8_t i,j;
    for (i = 0; i < ZCL_CTX().device_ctx.ep_count; i++) {
        for (j = 0; j < ZCL_CTX().device_ctx.ep_list[i]->cluster_count; j++) {
            if (ZCL_CTX().device_ctx.ep_list[i]->clusters[j].cluster_id == cluster_id &&
                ZCL_CTX().device_ctx.ep_list[i]->clusters[j].role == role)
                {
                    return ZCL_CTX().device_ctx.ep_list[i];
                }
        }
    }
    return NULL;
}

void zb_zcl_rx(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_zcl_parsed_hdr_t zcl_hdr;
    zb_zcl_status_t status = ZB_ZCL_STATUS_FAIL;
    zb_af_ep_desc_t *ep;

    zcl_parse_hdr(param, &zcl_hdr);
    /* handle broadcast EP */
    if (zcl_hdr.dst_endpoint == 0xFF) {
        /* find fitting cluster */
        ep = zb_get_ep_by_cluster(zcl_hdr.cluster_id, (zcl_hdr.direction ==
                                ZB_ZCL_FRAME_DIRECTION_TO_SRV) ?
                                ZB_ZCL_SERVER_ROLE : ZB_ZCL_CLIENT_ROLE);
        /* overwrite endpoint in hdr for later use */
        zcl_hdr.dst_endpoint = ep->ep_id;
    }
    else {
        ep = zb_af_get_ep_desc(zcl_hdr.dst_endpoint);
    }
    
    zb_buf_assign_param(buf, (zb_uint8_t *)&zcl_hdr, sizeof(zb_zcl_parsed_hdr_t));

    if (!ep) {
        zb_free_buf(buf);
        status = ZB_ZCL_STATUS_NOT_FOUND;
        goto send_response;
    }
    zb_zcl_cluster_t *cl = zb_get_cluster_desc(ep, zcl_hdr.cluster_id,
                                (zcl_hdr.direction == ZB_ZCL_FRAME_DIRECTION_TO_SRV) ?
                                  ZB_ZCL_SERVER_ROLE : ZB_ZCL_CLIENT_ROLE);
    if (!cl) {
        zb_free_buf(buf);
        status = ZB_ZCL_STATUS_NOT_FOUND;
        goto send_response;
    }
    status = zb_zcl_handle(param, cl);

send_response:
    if (status != ZB_ZCL_STATUS_SUCCESS || !zcl_hdr.disable_default_resp) {
        zb_buf_t *sec_buf = zb_get_out_buf();
        //ZB_ASSERT(sec_buf);
        zb_zcl_send_default_resp(ZB_REF_FROM_BUF(sec_buf), zcl_hdr, status);
    }
}

void zb_zcl_init_ep(zb_af_ep_desc_t *ep)
{
    zb_uint8_t i;
    for (i = 0; i < ep->cluster_count; i++) {
        ep->clusters[i].init(&(ep->clusters[i]));
    }
    ZCL_CTX().device_ctx.ep_list[ZCL_CTX().device_ctx.ep_count] = ep;
    ZCL_CTX().device_ctx.ep_count++;
    zb_add_simple_descriptor(ep->simple_desc);
}

/* rewrite to register EP */
void zb_zcl_reg_cl_handlers(zb_uint16_t cluster_id,
                             zb_zcl_cluster_role_t role,
                             zb_zcl_cluster_handler_t handle)
{
    ZB_ASSERT(ZB_ZCL_CLUSTER_NUM > ZG->zcl.handler_count);

    zcl_cluster_handlers_t *cl = &ZG->zcl.handlers[ZG->zcl.handler_count];
    cl->cluster_id = cluster_id;
    cl->role = role;
    cl->handle = handle;

    ZG->zcl.handler_count++;
}

zb_zcl_attr_t *zb_zcl_find_attribute(zb_zcl_cluster_t *cluster,
                                     zb_uint16_t attribute_id)
{
    zb_zcl_attr_t *attr_desc = cluster->attr_list;
    zb_uint8_t i = 0;
    while (attr_desc != NULL) {
        if (attr_desc->id == attribute_id) {
            break;
        }
        i++;
        attr_desc++;
        if (i >= cluster->attr_count) {
            attr_desc = NULL;
            break;
        }
    }
    return attr_desc;
}

void zb_zcl_format_string(zb_uint8_t *arr, zb_uint8_t len)
{
    zb_uint8_t tmp[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    /* because sizeof(char[]) is always 1 byte longer */
    len = (len > 0) ? len - 1 : 0;
    tmp[0] = len;
    ZB_MEMCPY(&tmp[1], arr, len);
    ZB_MEMCPY(arr, tmp, len + 1);
}

void zb_zcl_format_array(zb_uint8_t *arr, zb_uint8_t len)
{
    zb_uint8_t tmp[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    /* because sizeof(char[]) is always 1 byte longer */
    tmp[0] = len;
    ZB_MEMCPY(&tmp[1], arr, len);
    ZB_MEMCPY(arr, tmp, len + 1);
}

void zb_zcl_add_attribute(zb_zcl_cluster_t *cluster, zb_uint16_t attr_id,
                          zb_zcl_attr_type_t type, zb_zcl_attr_access_t access,
                          zb_voidp_t data_p)
{
    static zb_zcl_attr_t new_attr;
    new_attr.id = attr_id;
    new_attr.type = type;
    new_attr.access = access;
    new_attr.data_p = data_p;
    cluster->attr_list[cluster->attr_count] = new_attr;
    cluster->attr_count++;
}
zb_uint8_t zb_zcl_get_attribute_size(zb_zcl_attr_t *attr)
{
    switch (attr->type) {
    case ZB_ZCL_ATTR_TYPE_NULL:
    case ZB_ZCL_ATTR_TYPE_INVALID:
        return 0;
    case ZB_ZCL_ATTR_TYPE_8BIT:
    case ZB_ZCL_ATTR_TYPE_BOOL:
    case ZB_ZCL_ATTR_TYPE_8BITMAP:
    case ZB_ZCL_ATTR_TYPE_U8:
    case ZB_ZCL_ATTR_TYPE_S8:
    case ZB_ZCL_ATTR_TYPE_ENUM8:
        return sizeof(zb_uint8_t);
    case ZB_ZCL_ATTR_TYPE_16BIT:
    case ZB_ZCL_ATTR_TYPE_16BITMAP:
    case ZB_ZCL_ATTR_TYPE_U16:
    case ZB_ZCL_ATTR_TYPE_S16:
    case ZB_ZCL_ATTR_TYPE_ENUM16:
    case ZB_ZCL_ATTR_TYPE_FLOAT16:
    case ZB_ZCL_ATTR_TYPE_CLUSTER_ID:
    case ZB_ZCL_ATTR_TYPE_ATTR_ID:
        return sizeof(zb_uint16_t);
    case ZB_ZCL_ATTR_TYPE_24BIT:
    case ZB_ZCL_ATTR_TYPE_24BITMAP:
    case ZB_ZCL_ATTR_TYPE_U24:
    case ZB_ZCL_ATTR_TYPE_S24:
        return sizeof(zb_uint8_t)*3;
    case ZB_ZCL_ATTR_TYPE_32BIT:
    case ZB_ZCL_ATTR_TYPE_32BITMAP:
    case ZB_ZCL_ATTR_TYPE_U32:
    case ZB_ZCL_ATTR_TYPE_S32:
    case ZB_ZCL_ATTR_TYPE_FLOAT32:
    case ZB_ZCL_ATTR_TYPE_TOD:
    case ZB_ZCL_ATTR_TYPE_DATE:
    case ZB_ZCL_ATTR_TYPE_UTC:
    case ZB_ZCL_ATTR_TYPE_BAC_OID:
        return sizeof(zb_uint32_t);
    case ZB_ZCL_ATTR_TYPE_40BIT:
    case ZB_ZCL_ATTR_TYPE_40BITMAP:
    case ZB_ZCL_ATTR_TYPE_U40:
    case ZB_ZCL_ATTR_TYPE_S40:
        return sizeof(zb_uint8_t)*5;
    case ZB_ZCL_ATTR_TYPE_48BIT:
    case ZB_ZCL_ATTR_TYPE_48BITMAP:
    case ZB_ZCL_ATTR_TYPE_U48:
    case ZB_ZCL_ATTR_TYPE_S48:
        return sizeof(zb_uint16_t)*3;
    case ZB_ZCL_ATTR_TYPE_56BIT:
    case ZB_ZCL_ATTR_TYPE_56BITMAP:
    case ZB_ZCL_ATTR_TYPE_U56:
    case ZB_ZCL_ATTR_TYPE_S56:
        return sizeof(zb_uint8_t)*7;
    case ZB_ZCL_ATTR_TYPE_64BIT:
    case ZB_ZCL_ATTR_TYPE_64BITMAP:
    case ZB_ZCL_ATTR_TYPE_U64:
    case ZB_ZCL_ATTR_TYPE_S64:
    case ZB_ZCL_ATTR_TYPE_FLOAT64:
    case ZB_ZCL_ATTR_TYPE_IEEE_ADDR:
        return sizeof(zb_ieee_addr_t);
    case ZB_ZCL_ATTR_TYPE_SEC_KEY:
        return sizeof(zb_ieee_addr_t)*2;
    case ZB_ZCL_ATTR_TYPE_BYTE_ARRAY:
    case ZB_ZCL_ATTR_TYPE_CHAR_STRING:
        return (*(zb_uint8_t*)attr->data_p) + 1;
    case ZB_ZCL_ATTR_TYPE_LONG_ARRAY:
    case ZB_ZCL_ATTR_TYPE_LONG_STRING:
        if (ZB_MEMCMP(attr->data_p, 0x00, sizeof(zb_uint8_t)) == 0) {
            return (*(zb_uint8_t*)(attr->data_p + 1)) + 2;
        }
        else {
            return 0xff;
        }
    default:
        return 0xff;
    
    }
}

void zcl_parse_hdr(zb_uint8_t param, zb_zcl_parsed_hdr_t *zcl_hdr)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);
    zb_apsde_data_indication_t *ind = ZB_GET_BUF_PARAM(buf, zb_apsde_data_indication_t);
    if (ZB_APS_FC_GET_FRAME_TYPE(ind->fc) != ZB_APS_FRAME_INTERPAN) {
        zcl_hdr->src_addr = ind->src_addr;
        zcl_hdr->dst_addr = ind->dst_addr; // choose ind->group_addr
        zcl_hdr->src_endpoint = ind->src_endpoint;
        zcl_hdr->dst_endpoint = ind->dst_endpoint;
    }
    else {
        zcl_hdr->dst_endpoint = 0xFF;
    }
    zcl_hdr->cluster_id = ind->clusterid;
    zcl_hdr->profile_id = ind->profileid;
    ZB_APS_HDR_CUT(buf);
    zb_uint8_t *ptr = ZB_BUF_BEGIN(buf);
    zb_zcl_frame_ctrl_t *fc = (zb_zcl_frame_ctrl_t *)ptr;
    zcl_hdr->type = (zb_zcl_frame_type_t)fc->frame_type;
    zcl_hdr->cmd_id = ZB_ZCL_FRAME_HDR_GET_COMMAND_ID(ptr);
    zcl_hdr->direction = (zb_bool_t)fc->direction;
    zcl_hdr->disable_default_resp = (zb_bool_t)fc->disable_def_resp;
}
