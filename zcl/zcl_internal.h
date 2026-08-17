/*
    PURPOSE: ZCL layer internals
*/
#ifndef ZCL_INTERNAL_H
#define ZCL_INTERNAL_H       1

/*! \addgroup ZB_ZCL */
/*! @{ */
#define ZB_ZCL_DEFAULT_RESPONSE_CMD_ID  0x0b
typedef struct zb_zcl_parsed_hdr_s {
    zb_uint16_t src_addr;
    zb_uint16_t dst_addr;
    zb_uint8_t  src_endpoint;
    zb_uint8_t  dst_endpoint;
    zb_uint16_t cluster_id;
    zb_uint16_t profile_id;
    zb_uint8_t cmd_id;
    zb_zcl_frame_type_t type;
    zb_zcl_frame_direction_t direction;
    zb_bool_t disable_default_resp;
} ZB_PACKED_STRUCT zb_zcl_parsed_hdr_t;

typedef struct zb_zcl_default_resp_s {
    zb_uint8_t resp_cmd;
    zb_uint8_t status;
} ZB_PACKED_STRUCT zb_zcl_default_resp_t;

/* General Commands */
typedef struct zb_zcl_read_attr_record_s {
    zb_uint16_t attr_id;
    zb_zcl_status_t status;
    zb_zcl_attr_type_t type;
} ZB_PACKED_STRUCT zb_zcl_read_attr_record_t;

typedef struct zb_zcl_write_attr_record_s {
    zb_uint16_t attr_id;
    zb_zcl_attr_type_t type;
} ZB_PACKED_STRUCT zb_zcl_write_attr_record_t;

typedef struct zb_zcl_write_attr_resp_record_s {
    zb_zcl_status_t status;
    zb_uint16_t attr_id;
} ZB_PACKED_STRUCT zb_zcl_write_attr_resp_record_t;

typedef struct zb_zcl_attr_status_record_s {
    zb_zcl_status_t status;
    zb_uint8_t direction;
    zb_uint16_t attr_id;
} ZB_PACKED_STRUCT zb_zcl_attr_status_record_t;

/**
 * fills zcl hdr
 */
zb_zcl_hdr_t *zcl_alloc_and_fill_hdr(zb_buf_t *buf,
                                     zb_zcl_frame_type_t type,
                                     zb_zcl_frame_direction_t direction,
                                     zb_bool_t default_resp,
                                     zb_uint8_t cmd);
/**
 * parse ZCL frame
 */
void zcl_parse_hdr(zb_uint8_t param, zb_zcl_parsed_hdr_t *zcl_hdr);

/**
 * format string type attribute
 */
void zb_zcl_format_string(zb_uint8_t *arr, zb_uint8_t len);

/**
 * format array type attribute 
 */
void zb_zcl_format_array(zb_uint8_t *arr, zb_uint8_t len);
#endif /* ZCL_INTERNAL_H */
/*! @} */
