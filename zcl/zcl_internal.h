/*
    PURPOSE: ZCL layer internals
*/
#ifndef ZCL_INTERNAL_H
#define ZCL_INTERNAL_H 1

/*! \addgroup ZB_ZCL */
/*! @{ */
/**
 * fills zcl hdr
 */
zb_zcl_hdr_t *zcl_alloc_and_fill_hdr(zb_buf_t *buf,
                                     zb_zcl_frame_type_t type,
                                     zb_zcl_frame_direction_t direction,
                                     zb_bool_t default_resp,
                                     zb_uint8_t cmd);

#endif /* ZCL_INTERNAL_H */
/*! @} */
