/*
   PURPOSE: Zigbee application layer globals definition
 */

#ifndef ZB_APL_GLOBALS_H
#define ZB_APL_GLOBALS_H        1

/*! \addtogroup ZB_ZCL */
/*! @{ */

/**
 * aplcInterPANTransIdLifetime 8 sec
 */
#define INTRP_TRANS_ID_LIFETIME ZB_MILLISECONDS_TO_BEACON_INTERVAL(8000)

/**
 * aplcMinStartupDelayTime 2 sec
 */
#define MIN_STARTUP_DELAY_TIME  ZB_MILLISECONDS_TO_BEACON_INTERVAL(2000)

/**
 * aplcRxWindowDuration 5 sec
 */
#define RX_WINDOW_DURATION      ZB_MILLISECONDS_TO_BEACON_INTERVAL(5000)

/**
 * aplcScanTimeBaseDuration 0.25 sec
 */
#define SCAN_TIME_BASE_DURATION ZB_MILLISECONDS_TO_BEACON_INTERVAL(250)

/**
 * device information table (holds app info, so this should be the right place)
 */
#define ZB_APL_MAX_DEV_ENTRIES  10

typedef struct zb_apl_dev_info_ent_s {
    zb_ieee_addr_t long_addr;  /*!< IEEE address of each node */
    zb_uint8_t endpoint;       /*!< Endpoint choosen by application */
    zb_uint16_t profile_id;    /*!< corresponds to application profile ID */
    zb_uint16_t device_id;     /*!< corresponds to application device ID */
    zb_uint8_t version;        /*!< 4 Bit device version of subdevice */
    zb_uint8_t group_id_count; /*!< number of unique group identifiers */
    zb_uint8_t sort;           /*!< sort tag, indicating an order, 0 = unordered */
} zb_apl_dev_info_ent_t;
/**
   Global ZCL structure
 */
typedef struct zb_apl_globals_s {
    zb_uint16_t free_addr_range_begin;                          /*!< APL addr range */
    zb_uint16_t free_addr_range_end;                            /*!< APL addr range */
    zb_uint16_t free_gr_id_range_begin;                         /*!< APL group id range */
    zb_uint16_t free_gr_id_range_end;                           /*!< APL group id range */
    zb_uint8_t dev_info_used;                                   /*!< Number of entries in table*/
    zb_apl_dev_info_ent_t dev_info_tbl[ZB_APL_MAX_DEV_ENTRIES]; /*!< device information table*/
} zb_apl_globals_t;

#define APL_CTX() ZG->apl

/*! @} */

#endif /* ZB_APL_GLOBALS_H */
