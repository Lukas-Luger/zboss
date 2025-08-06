#include "zb_common.h"

#ifndef ZB_ZCL_GROUPS_H
#define ZB_ZCL_GROUPS_H 1
/**
 * Server Attributes
 */
typedef struct zb_zcl_groups_srv_attr_s {
    zb_uint8_t name_support;
} zb_zcl_groups_srv_attr_t;

typedef enum zb_zcl_group_cmd_e {
    ZB_ZCL_GROUPS_ADD_GROUP         = 0x00,
    ZB_ZCL_GROUPS_VIEW_GROUP        = 0x01,
    ZB_ZCL_GROUPS_GET_GR_MEMBERSHIP = 0x02,
    ZB_ZCL_GROUPS_REMOVE_GROUP      = 0x03,
    ZB_ZCL_GROUPS_REMOVE_ALL_GROUPS = 0x04,
    ZB_ZCL_GROUPS_ADD_GR_IF_ID      = 0x05,
} zb_zcl_group_cmd_t;

typedef struct {
    zb_uint16_t group_id;
    zb_uint8_t length;
    //zb_char_t *name;
} ZB_PACKED_STRUCT zb_zcl_groups_add_group_req_t;

typedef struct {
    uint8_t status;
    uint16_t group_id;
} ZB_PACKED_STRUCT zb_zcl_groups_add_group_resp_t;

typedef struct {
    zb_uint16_t group_id;
} ZB_PACKED_STRUCT zb_zcl_groups_view_group_req_t;

typedef struct {
    zb_uint8_t status;
    zb_uint16_t group_id;
    zb_uint8_t length;
    //zb_char_t *name;
} ZB_PACKED_STRUCT zb_zcl_groups_view_group_resp_t;

typedef struct {
    uint8_t group_count;
    zb_uint16_t group_list[ZB_APS_GROUP_TABLE_SIZE];
} ZB_PACKED_STRUCT zb_zcl_groups_get_group_membership_req_t;

typedef struct {
    uint8_t group_capacity;
    uint8_t group_count;
    zb_uint16_t group_list[ZB_APS_GROUP_TABLE_SIZE];
} ZB_PACKED_STRUCT zb_zcl_groups_get_group_membership_resp_t;

typedef struct {
    uint16_t group_id;
} ZB_PACKED_STRUCT zb_zcl_groups_remove_group_req_t;

typedef struct {
    uint8_t status;
    uint16_t group_id;
} ZB_PACKED_STRUCT zb_zcl_groups_remove_group_resp_t;

/* Note: remove all groups does not have a response nor parameters */

typedef struct {
    zb_uint16_t group_id;
    zb_uint8_t length;
    //zb_char_t *name;
} ZB_PACKED_STRUCT zb_zcl_groups_add_group_iid_req_t;

/**
   Setup Method for Server

   @param ep - Endpoint of application
 */
void zb_zcl_groups_srv_setup(zb_uint8_t ep, zb_zcl_groups_srv_attr_t *attrs);

/* Public Client Methods */
/**
   Sends Add Group Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param group_id - Group ID to add
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_groups_send_add_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends View Group Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param group_id - Group ID to view
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_groups_send_view_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep);

/**
   Sends Get Group Membership Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param n_groups - Number of groups to inspect
   @param group_list - Array of group ids
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_groups_send_get_group_membership(zb_uint8_t param, zb_uint16_t profile_id, zb_uint8_t n_groups,
                                    zb_uint16_t group_list[ZB_APS_GROUP_TABLE_SIZE],
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Remove Group Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param group_id - Group ID to remove
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_groups_send_remove_group(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Remove All Groups Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */                                   
void zb_zcl_groups_send_remove_all_groups(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                                        zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Add Group if identifying Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param group_id - Group ID to add
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_groups_send_add_group_iid(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t group_id,
                                    zb_uint16_t dst_addr, zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Setup Method for Client

   @param ep - Endpoint of application
 */
void zb_zcl_groups_cli_setup(zb_uint8_t ep);


#endif /* ZB_ZCL_GROUPS_H */
