/*
    PURPOSE: ZCL ZLL internals
*/
#ifndef ZCL_ZLL_INTERNAL_H
#define ZCL_ZLL_INTERNAL_H              1

/*! \addgroup ZB_ZCL */
/*! @{ */

/**
 * sets the default factory new status, can be reset using factory reset command
 * 00 = False; 01 = True
 */
#define ZB_TOUCHLINK_FACT_NEW           0x01
/**
 * parse ZigBee Information field
 * Bit 0-1: Logical device type
 * Bit 3: Rx-on-when-idle
 */
#define ZB_ZCL_ZB_DEV_TYPE_COORD        0
#define ZB_ZCL_ZB_DEV_TYPE_ROUTER       1
#define ZB_ZCL_ZB_DEV_TYPE_ED           2

#define ZB_ZCL_GET_ZB_DEV_TYPE(info)    (info & 3)

#define ZB_ZCL_GET_ADDR_ASS_CAP(tl_cap) (tl_cap & 2)

#define ZB_IEEE_ADDR_BROADCAST          ((zb_ieee_addr_t){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })

/**
 * Touchlink Command IDs
 */
typedef enum zb_zll_cmd_e {
    ZB_ZLL_SCAN_REQ_CMD_ID          = 0x00,
    ZB_ZLL_SCAN_RESP_CMD_ID         = 0x01,
    ZB_ZLL_DEV_INFO_REQ_CMD_ID      = 0x02,
    ZB_ZLL_DEV_INFO_RESP_CMD_ID     = 0x03,
    ZB_ZLL_IDENTIFY_REQ_CMD_ID      = 0x06,
    ZB_ZLL_RESET_REQ_CMD_ID         = 0x07,
    ZB_ZLL_NET_START_REQ_CMD_ID     = 0x10,
    ZB_ZLL_NET_START_RESP_CMD_ID    = 0x11,
    ZB_ZLL_NET_JOIN_R_REQ_CMD_ID    = 0x12,
    ZB_ZLL_NET_JOIN_R_RESP_CMD_ID   = 0x13,
    ZB_ZLL_NET_JOIN_ED_REQ_CMD_ID   = 0x14,
    ZB_ZLL_NET_JOIN_ED_RESP_CMD_ID  = 0x15,
    ZB_ZLL_NET_UPDATE_REQ_CMD_ID    = 0x16,
} zb_zll_cmd_t;

typedef struct zb_zll_scan_req_s {
    zb_uint32_t transaction_id;
    zb_uint8_t zigbee_information;
    zb_uint8_t touchlink_information;
} ZB_PACKED_STRUCT
    zb_zll_scan_req_t;

/**
 * Data structure for dev info
 */
typedef struct zb_zll_dev_info_req_s {
    zb_uint32_t transaction_id;
    zb_uint8_t start_index;
} ZB_PACKED_STRUCT
    zb_zll_dev_info_req_t;

typedef struct zb_zll_dev_record_s {
    zb_ieee_addr_t addr;
    zb_uint8_t endpoint;
    zb_uint16_t profileid;
    zb_uint16_t deviceid;
    zb_uint8_t version;
    zb_uint8_t groupid_count;
    zb_uint8_t sort;
} ZB_PACKED_STRUCT
    zb_zll_dev_record_t;

typedef struct zb_zll_dev_info_resp_s {
    zb_uint32_t transaction_id;
    zb_uint8_t subdevices;
    zb_uint8_t start; /* this should be equal to to the start index we receive */
    zb_uint8_t count;
} ZB_PACKED_STRUCT
    zb_zll_dev_info_resp_t;
/**
 * Data structure for network start req and resp
 */
typedef struct zb_zll_net_start_req_s {
    zb_uint32_t transaction_id;
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
} ZB_PACKED_STRUCT
    zb_zll_net_start_req_t;

typedef struct zb_zll_net_start_resp_s {
    zb_uint32_t transaction_id;
    zb_uint8_t status;
    zb_ieee_addr_t ext_pan_id;
    zb_uint8_t net_update_id;
    zb_uint8_t channel;
    zb_uint16_t pan_id;
} ZB_PACKED_STRUCT
    zb_zll_net_start_resp_t;

typedef struct zb_zll_net_update_req_s {
    zb_uint32_t transaction_id;
    zb_ieee_addr_t ext_pan_id;
    zb_uint8_t net_update_id;
    zb_uint8_t channel;
    zb_uint16_t pan_id;
    zb_uint16_t network_address;
} ZB_PACKED_STRUCT
    zb_zll_net_update_req_t;

/**
 * Data structure for network join router and end device req and resp
 */
typedef struct zb_zll_net_join_req_s {
    zb_uint32_t transaction_id;
    zb_ieee_addr_t ext_pan_id;
    zb_uint8_t key_index;
    zb_uint8_t enc_network_key[16];
    zb_uint8_t net_update_id;
    zb_uint8_t channel;
    zb_uint16_t pan_id;
    zb_uint16_t network_address;
    zb_uint16_t group_id_begin;
    zb_uint16_t group_id_end;
    zb_uint16_t free_addr_begin;
    zb_uint16_t free_addr_end;
    zb_uint16_t free_group_begin;
    zb_uint16_t free_group_end;
} ZB_PACKED_STRUCT
    zb_zll_net_join_req_t;

typedef struct zb_zll_net_join_resp_s {
    zb_uint32_t transaction_id;
    zb_uint8_t status;
} ZB_PACKED_STRUCT
    zb_zll_net_join_resp_t;

/**
 * returns true if no device information is present in scan response aka need to send dev info req
 */
#define ZB_ZLL_TL_DEV_INFO_REQ_REQUIRED(frame) (((zb_zll_scan_resp_t *)frame)->subdevices != 1)

/**
 * returns size of scan response
 */
#define ZB_ZLL_TL_GET_SCAN_RESP_SIZE(frame)    (ZB_ZLL_TL_DEV_INFO_REQ_REQUIRED(frame) ? \
                                                 sizeof(zb_zll_scan_resp_t) - 7 :        \
                                                 sizeof(zb_zll_scan_resp_t))
/**
 * returns true if touchlink info has initiator set
 */
#define ZB_ZLL_TL_INFO_GET_LINK_INITIATOR(info) (info & 0x10)
#endif /* ZCL_ZLL_H */
