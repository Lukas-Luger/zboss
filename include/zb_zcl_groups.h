#include "zb_common.h"

#ifndef ZB_ZCL_GROUPS_H
#define ZB_ZCL_GROUPS_H 1

typedef struct {
    uint16_t group_id;
    uint8_t length;
} ZB_PACKED_STRUCT zcl_add_group_hdr_t;

typedef struct {
    uint8_t status;
    uint16_t group_id;
} ZB_PACKED_STRUCT zcl_add_group_resp_t;

typedef struct {
    uint16_t group_id;
} ZB_PACKED_STRUCT zcl_remove_group_t;

typedef struct {
    uint8_t status;
    uint16_t group_id;
} ZB_PACKED_STRUCT zcl_remove_group_resp_t;

typedef struct {
    uint8_t group_capacity;
    uint8_t group_count;
} ZB_PACKED_STRUCT zcl_get_group_membership_resp_t;

typedef struct {
    uint8_t group_count;
} ZB_PACKED_STRUCT zcl_get_group_membership_hdr_t;

typedef struct {
    uint8_t fcf;
    uint8_t sequence_number;
    uint8_t cmd;
} ZB_PACKED_STRUCT zcl_hdr_t;

#endif /* ZB_ZCL_GROUPS_H */
