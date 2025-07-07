#include "zb_common.h"

#ifndef ZB_ZCL_ON_OFF_H
#define ZB_ZCL_ON_OFF_H 1
/**
 * Server Side
 */
typedef enum zb_zcl_on_off_cmd_e{
    ZB_ZCL_ON_OFF_OFF                   = 0x00,
    ZB_ZCL_ON_OFF_ON                    = 0x01,
    ZB_ZCL_ON_OFF_TOGGLE                = 0x02,
    ZB_ZCL_ON_OFF_OFF_WITH_EFFECT       = 0x40,
    ZB_ZCL_ON_OFF_ON_WITH_GLOB_SCENE    = 0x41,
    ZB_ZCL_ON_OFF_ON_WITH_TIMED_OFF     = 0x42,
} zb_zcl_on_off_cmd_t;

typedef struct {
    zb_uint8_t effect_id;
    zb_uint8_t effect_variant;
} ZB_PACKED_STRUCT zb_zcl_on_off_off_with_effect_req_t;

typedef struct {
    zb_uint8_t on_off_ctrl;
    zb_uint16_t on_time;
    zb_uint16_t off_wait_time;
} ZB_PACKED_STRUCT zb_zcl_on_off_on_with_timed_off_req_t;
/**
   Setup Method for Server

   @param ep - Endpoint of application
   @param set_st - Callback method for setting device state
 */
void zb_zcl_on_off_srv_setup(zb_uint8_t ep, zb_callback_t set_st);

/* Public Client Methods */
/**
   Sends Off Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_off(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Om Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_on(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Toggle Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_toggle(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends Off with effect Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param effect_id - only 0 and 1 is permitted
   @param effect_variant - only 0, 1 or 2 are permitted
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_off_with_effect(zb_uint8_t param, zb_uint16_t profile_id, zb_uint8_t effect_id,
                            zb_uint8_t effect_variant, zb_uint16_t dst_addr, zb_uint8_t dst_ep,
                            zb_uint8_t src_ep);
/**
   Sends On with recall global scene Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_on_with_glob_scene(zb_uint8_t param, zb_uint16_t profile_id, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Sends On with timed off Command

   @param param - (new) out-buffer
   @param profile_id - Profile ID under which command is sent
   @param only_when_on - only process command if device is on
   @param on_time - 1/10ths seconds the device shall be on
   @param off_wait_time - 1/10ths seconds the device shall remain off
   @param dst_addr - Short destination address
   @param dst_ep - Destination endpoint
   @param src_ep - Source endpoint
 */
void zb_zcl_on_off_send_on_with_timed_off(zb_uint8_t param, zb_uint16_t profile_id, zb_bool_t only_when_on,
                            zb_uint16_t on_time, zb_uint16_t off_wait_time, zb_uint16_t dst_addr,
                            zb_uint8_t dst_ep, zb_uint8_t src_ep);
/**
   Setup Method for Client

   @param ep - Endpoint of application
 */
void zb_zcl_on_off_cli_setup(zb_uint8_t ep);
#endif
