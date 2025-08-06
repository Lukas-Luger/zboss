#include "zb_common.h"
#include "zb_zcl.h"

#ifndef ZB_ZCL_BASIC_H
#define ZB_ZCL_BASIC_H 1
/**
 * Server Attributes
 */
typedef struct zb_zcl_basic_srv_attr_s {
    zb_uint8_t zcl_version;
    zb_uint8_t app_version;
    zb_uint8_t stack_version;
    zb_uint8_t hw_version;
    zb_uint8_t manufacturer_name[32];
    zb_uint8_t manufacturer_name_len;
    zb_uint8_t model_id[32];
    zb_uint8_t model_id_len;
    zb_uint8_t date_code[16];  /* YYYYMMDD + [country/facctory]*/
    zb_uint8_t date_code_len;
    zb_uint8_t power_source;
    zb_uint8_t generic_device_class;
    zb_uint8_t generic_device_type;
    zb_uint8_t product_code_id;
    zb_uint8_t product_code[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    zb_uint8_t product_code_len;
    zb_char_t  product_url[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    zb_uint8_t product_url_len;
    zb_char_t  man_version_details[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    zb_uint8_t man_version_details_len;
    zb_char_t  serial_number[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    zb_uint8_t serial_number_len;
    zb_char_t  product_label[ZB_ZCL_ATTR_MAX_ARRAY_LENGTH];
    zb_uint8_t product_label_len;
    zb_uint8_t location_desc[16];
    zb_uint8_t location_desc_len;
    zb_uint8_t phys_environment;
    zb_uint8_t device_enabled;
    zb_uint8_t alarm_mask;
    zb_uint8_t disable_local_conf;
    zb_uint8_t software_build_id[16];
    zb_uint8_t software_build_id_len;
} zb_zcl_basic_srv_attr_t;

typedef enum zb_zcl_basic_dev_en_e {
    ZB_ZCL_BASIC_DEV_DISABLED           = 0x00,
    ZB_ZCL_BASIC_DEV_ENABLED            = 0x01,
} zb_zcl_basic_dev_en_t;

typedef enum zb_zcl_basic_power_src_e {
    ZB_ZCL_BASIC_POWER_SRC_UNKNOWN      = 0x00, /*!< Unknown */
    ZB_ZCL_BASIC_POWER_SRC_MAINS        = 0x01, /*!< Mains (single phase) */
    ZB_ZCL_BASIC_POWER_SRC_THREE_P      = 0x02, /*!< Mains (3 phase) */
    ZB_ZCL_BASIC_POWER_SRC_BATTERY      = 0x03, /*!< Battery */
    ZB_ZCL_BASIC_POWER_SRC_DC_SRC       = 0x04, /*!< DC Source */
    ZB_ZCL_BASIC_POWER_SRC_EMER_MAINS   = 0x05, /*!< Emergency mains constantly powered */
    ZB_ZCL_BASIC_POWER_SRC_EMER_TR_SW   = 0x06  /*!< Emergency mains and transfer switch */
} zb_zcl_basic_power_src_t;

/**
 * Generic device type when generic_device_class == 0
 */
typedef enum zb_zcl_basic_generic_device_type_e {
    ZB_ZCL_BASIC_GEN_DEV_TYPE_INCANDESCENT          = 0x00, /*!< Incandescent */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_STOPTLIGHT_HALOGEN    = 0x01, /*!< Spotlight Halogen */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_HALOGEN_BULB          = 0x02, /*!< Halogen bulb */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_CFL                   = 0x03, /*!< CFL */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_LINEAR_FLUORESCENT    = 0x04, /*!< Linear Fluorescent */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_LED_BULB              = 0x05, /*!< LED bulb */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_LED_SPOT              = 0x06, /*!< Spotlight LED */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_LED_STRIP             = 0x07, /*!< LED strip */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_LED_TUBE              = 0x08, /*!< LED tube */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_GENERIC_INDOOR        = 0x09, /*!< Generic indoor luminaire/light fixture */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_GENERIC_OUTDOOR       = 0x0a, /*!< Generic outdoor luminaire/light fixture */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_PENDANT_LIGHT         = 0x0b, /*!< Pendant luminaire/light fixture */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_STANDING_LIGHT        = 0x0c, /*!< Floor standing luminaire/light fixture */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_GENERIC_CONTROLLER    = 0xe0, /*!< Generic Controller (e.g. Remote controller) */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_WALL_SWITCH           = 0xe1, /*!< Wall Switch */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_REMOTE_CONTROLLER     = 0xe2, /*!< Portable remote controller */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_MOTION_SENSOR         = 0xe3, /*!< Motion sensor / light sensor */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_GENERIC_ACTUATOR      = 0xf0, /*!< Generic actuator */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_WALL_SOCKET           = 0xf1, /*!< Wall socket */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_GATEWAY_BRIDGE        = 0xf2, /*!< Gateway/Bridge */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_PLUG_IN_UNIT          = 0xf3, /*!< Plug-in unit */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_RETROFIT_ACTUATOR     = 0xf4, /*!< Retrofit actuator */
    ZB_ZCL_BASIC_GEN_DEV_TYPE_UNSPECIFIED           = 0xff, /*!< Unspecified   */

} zb_zcl_basic_generic_device_type_t;

typedef enum zb_zcl_basic_product_code_id_e {
    ZB_ZCL_BASIC_PRODUCT_CODE_MAN_DEFINED   = 0x00, /*!< Manufacturer defined */
    ZB_ZCL_BASIC_PRODUCT_CODE_EAN           = 0x01, /*!< International article number */
    ZB_ZCL_BASIC_PRODUCT_CODE_GTIN          = 0x02, /*!< Global trade item number */
    ZB_ZCL_BASIC_PRODUCT_CODE_UPC           = 0x03, /*!< Universal product code */
    ZB_ZCL_BASIC_PRODUCT_CODE_SKU           = 0x04  /*!< Stock keeping unit */
} zb_zcl_basic_product_code_id_t;

typedef enum zb_zcl_basic_phys_env_e {
    ZB_ZCL_BASIC_PHYS_ENV_UNSPEC                    = 0x00, /*!< Unspecified environment */
    ZB_ZCL_BASIC_PHYS_ENV_MIRROR                    = 0x01, /*!< Mirror (ZSE Profile) */
    ZB_ZCL_BASIC_PHYS_ENV_ATRIUM                    = 0x01, /*!< Atrium */
    ZB_ZCL_BASIC_PHYS_ENV_BAR                       = 0x02, /*!< Bar */
    ZB_ZCL_BASIC_PHYS_ENV_COURTYARD                 = 0x03, /*!< Courtyard */
    ZB_ZCL_BASIC_PHYS_ENV_BATHROOM                  = 0x04, /*!< Bathroom */
    ZB_ZCL_BASIC_PHYS_ENV_BEDROOM                   = 0x05, /*!< Bedroom */
    ZB_ZCL_BASIC_PHYS_ENV_BILLIARD_R                = 0x06, /*!< Billiard Room */
    ZB_ZCL_BASIC_PHYS_ENV_UTILITY_R                 = 0x07, /*!< Utility Room */
    ZB_ZCL_BASIC_PHYS_ENV_CELLAR                    = 0x08, /*!< Cellar */
    ZB_ZCL_BASIC_PHYS_ENV_STORAGE                   = 0x09, /*!< Storage Closet */
    ZB_ZCL_BASIC_PHYS_ENV_THEATER                   = 0x0a, /*!< Theater */
    ZB_ZCL_BASIC_PHYS_ENV_OFFICE                    = 0x0b, /*!< Office */
    ZB_ZCL_BASIC_PHYS_ENV_DECK                      = 0x0c, /*!< Deck */
    ZB_ZCL_BASIC_PHYS_ENV_DEN                       = 0x0d, /*!< Den */
    ZB_ZCL_BASIC_PHYS_ENV_DINING_R                  = 0x0e, /*!< Dining Room */
    ZB_ZCL_BASIC_PHYS_ENV_ELECTRIC_R                = 0x0f, /*!< Electrical Room */
    ZB_ZCL_BASIC_PHYS_ENV_ELEVATOR                  = 0x10, /*!< Elevator */
    ZB_ZCL_BASIC_PHYS_ENV_ENTRY                     = 0x11, /*!< Entry */
    ZB_ZCL_BASIC_PHYS_ENV_FAMILY_R                  = 0x12, /*!< Family Room */
    ZB_ZCL_BASIC_PHYS_ENV_MAIN_FLOOR                = 0x13, /*!< Main Floor */
    ZB_ZCL_BASIC_PHYS_ENV_UPSTAIRS                  = 0x14, /*!< Upstairs */
    ZB_ZCL_BASIC_PHYS_ENV_DOWNSTAIRS                = 0x15, /*!< Downstairs */
    ZB_ZCL_BASIC_PHYS_ENV_BASEMENT                  = 0x16, /*!< Basement/Lower Level */
    ZB_ZCL_BASIC_PHYS_ENV_GALLERY                   = 0x17, /*!< Gallery */
    ZB_ZCL_BASIC_PHYS_ENV_GAME_R                    = 0x18, /*!< Game Room */
    ZB_ZCL_BASIC_PHYS_ENV_GARAGE                    = 0x19, /*!< Garage */
    ZB_ZCL_BASIC_PHYS_ENV_GYM                       = 0x1a, /*!< Gym */
    ZB_ZCL_BASIC_PHYS_ENV_HALLWAY                   = 0x1b, /*!< Hallway */
    ZB_ZCL_BASIC_PHYS_ENV_HOUSE                     = 0x1c, /*!< House */
    ZB_ZCL_BASIC_PHYS_ENV_KITCHEN                   = 0x1d, /*!< Kitchen */
    ZB_ZCL_BASIC_PHYS_ENV_LAUNDRY                   = 0x1e, /*!< Laundry Room */
    ZB_ZCL_BASIC_PHYS_ENV_LIBRARY                   = 0x1f, /*!< Library */
    ZB_ZCL_BASIC_PHYS_ENV_MASTER_BED_R              = 0x20, /*!< Master Bedroom */
    ZB_ZCL_BASIC_PHYS_ENV_MUD_R                     = 0x21, /*!< Mud Room (small room for coats and boots) */
    ZB_ZCL_BASIC_PHYS_ENV_NURSERY                   = 0x22, /*!< Nursery */
    ZB_ZCL_BASIC_PHYS_ENV_PANTRY                    = 0x23, /*!< Pantry */
    ZB_ZCL_BASIC_PHYS_ENV_OFFICE2                   = 0x24, /*!< Office No. 2 ?? */
    ZB_ZCL_BASIC_PHYS_ENV_OUTSIDE                   = 0x25, /*!< Outside */
    ZB_ZCL_BASIC_PHYS_ENV_POOL                      = 0x26, /*!< Pool */
    ZB_ZCL_BASIC_PHYS_ENV_PORCH                     = 0x27, /*!< Porch */
    ZB_ZCL_BASIC_PHYS_ENV_SEWING_R                  = 0x28, /*!< Sewing Room */
    ZB_ZCL_BASIC_PHYS_ENV_SITTING_R                 = 0x29, /*!< Sitting Room */
    ZB_ZCL_BASIC_PHYS_ENV_STAIRWAY                  = 0x2a, /*!< Stairway */
    ZB_ZCL_BASIC_PHYS_ENV_YARD                      = 0x2b, /*!< Yard */
    ZB_ZCL_BASIC_PHYS_ENV_ATTIC                     = 0x2c, /*!< Attic */
    ZB_ZCL_BASIC_PHYS_ENV_HOT_TUB                   = 0x2d, /*!< Hot Tub */
    ZB_ZCL_BASIC_PHYS_ENV_LIVING_R                  = 0x2e, /*!< Living Room */
    ZB_ZCL_BASIC_PHYS_ENV_SAUNA                     = 0x2f, /*!< Sauna */
    ZB_ZCL_BASIC_PHYS_ENV_SHOP                      = 0x30, /*!< Shop/Workshop */
    ZB_ZCL_BASIC_PHYS_ENV_GUEST_BED_R               = 0x31, /*!< Guest Bedroom */
    ZB_ZCL_BASIC_PHYS_ENV_GUEST_BATH                = 0x32, /*!< Guest Bath */
    ZB_ZCL_BASIC_PHYS_ENV_POWDER_R                  = 0x33, /*!< Powder Room (1/2 bath) */
    ZB_ZCL_BASIC_PHYS_ENV_BACK_YARD                 = 0x34, /*!< Back Yard */
    ZB_ZCL_BASIC_PHYS_ENV_FRONT_YARD                = 0x35, /*!< Front Yard */
    ZB_ZCL_BASIC_PHYS_ENV_PATIO                     = 0x36, /*!< Patio */
    ZB_ZCL_BASIC_PHYS_ENV_DRIVEWAY                  = 0x37, /*!< Driveway */
    ZB_ZCL_BASIC_PHYS_ENV_SUN_R                     = 0x38, /*!< Sun Room */
    ZB_ZCL_BASIC_PHYS_ENV_LIVING_R2                 = 0x39, /*!< Living Room No. 2 ??*/
    ZB_ZCL_BASIC_PHYS_ENV_SPA                       = 0x3a, /*!< Spa */
    ZB_ZCL_BASIC_PHYS_ENV_WHIRPOOL                  = 0x3b, /*!< Whirlpool */
    ZB_ZCL_BASIC_PHYS_ENV_SHED                      = 0x3c, /*!< Shed */
    ZB_ZCL_BASIC_PHYS_ENV_EQUIPMENT                 = 0x3d, /*!< Equipment Storage */
    ZB_ZCL_BASIC_PHYS_ENV_CRAFT_R                   = 0x3e, /*!< Hobby/Craft Room */
    ZB_ZCL_BASIC_PHYS_ENV_FOUNTAIN                  = 0x3f, /*!< Fountain */
    ZB_ZCL_BASIC_PHYS_ENV_POND                      = 0x40, /*!< Pond */
    ZB_ZCL_BASIC_PHYS_ENV_RECEPTION_R               = 0x41, /*!< Reception Room */
    ZB_ZCL_BASIC_PHYS_ENV_BREAKFAST_R               = 0x42, /*!< Breakfast Room */
    ZB_ZCL_BASIC_PHYS_ENV_NOOK                      = 0x43, /*!< Nook */
    ZB_ZCL_BASIC_PHYS_ENV_GARDEN                    = 0x44, /*!< Garden */
    ZB_ZCL_BASIC_PHYS_ENV_BALCONY                   = 0x45, /*!< Balcony */
    ZB_ZCL_BASIC_PHYS_ENV_PANIC_R                   = 0x46, /*!< Panic Room */
    ZB_ZCL_BASIC_PHYS_ENV_TERRACE                   = 0x47, /*!< Terrace */
    ZB_ZCL_BASIC_PHYS_ENV_ROOF                      = 0x48, /*!< Roof */
    ZB_ZCL_BASIC_PHYS_ENV_TOILET                    = 0x49, /*!< Toilet */
    ZB_ZCL_BASIC_PHYS_ENV_TOILET_MAIN               = 0x4a, /*!< Toilet Main */
    ZB_ZCL_BASIC_PHYS_ENV_OUTSIDE_TOI               = 0x4b, /*!< Outside Toilet */
    ZB_ZCL_BASIC_PHYS_ENV_SHOWER_R                  = 0x4c, /*!< Shower room */
    ZB_ZCL_BASIC_PHYS_ENV_STUDY                     = 0x4d, /*!< Study */
    ZB_ZCL_BASIC_PHYS_ENV_FRONT_GARDEN              = 0x4e, /*!< Front Garden */
    ZB_ZCL_BASIC_PHYS_ENV_BACK_GARDEN               = 0x4f, /*!< Back Garden */
    ZB_ZCL_BASIC_PHYS_ENV_KETTLE                    = 0x50, /*!< Kettle */
    ZB_ZCL_BASIC_PHYS_ENV_TV                        = 0x51, /*!< Television */
    ZB_ZCL_BASIC_PHYS_ENV_STOVE                     = 0x52, /*!< Stove */
    ZB_ZCL_BASIC_PHYS_ENV_MICROWAVE                 = 0x53, /*!< Microwave */
    ZB_ZCL_BASIC_PHYS_ENV_TOASTER                   = 0x54, /*!< Toaster */
    ZB_ZCL_BASIC_PHYS_ENV_VACUUM                    = 0x55, /*!< Vacuum */
    ZB_ZCL_BASIC_PHYS_ENV_APPLIANCE                 = 0x56, /*!< Appliance */
    ZB_ZCL_BASIC_PHYS_ENV_FRONT_DOOR                = 0x57, /*!< Front Door */
    ZB_ZCL_BASIC_PHYS_ENV_BACK_DOOR                 = 0x58, /*!< Back Door */
    ZB_ZCL_BASIC_PHYS_ENV_FRIDGE_DOOR               = 0x59, /*!< Fridge Door */
    ZB_ZCL_BASIC_PHYS_ENV_MED_DOOR                  = 0x60, /*!< Medication Cabinet Door */
    ZB_ZCL_BASIC_PHYS_ENV_WARDROBE_DOOR             = 0x61, /*!< Wardrobe Door */
    ZB_ZCL_BASIC_PHYS_ENV_FRONT_CUPBOARD_DOOR       = 0x62, /*!< Front Cupboard Door */
    ZB_ZCL_BASIC_PHYS_ENV_OTHER_DOOR                = 0x63, /*!< Other Door */
    ZB_ZCL_BASIC_PHYS_ENV_WAITING_R                 = 0x64, /*!< Waiting Room */
    ZB_ZCL_BASIC_PHYS_ENV_TRIAGE_R                  = 0x65, /*!< Triage Room */
    ZB_ZCL_BASIC_PHYS_ENV_DOC_OFFICE                = 0x66, /*!< Doctor’s Office */
    ZB_ZCL_BASIC_PHYS_ENV_PATIENT_R                 = 0x67, /*!< Patient’s Private Room */
    ZB_ZCL_BASIC_PHYS_ENV_CONSULT_R                 = 0x68, /*!< Consultation Room */
    ZB_ZCL_BASIC_PHYS_ENV_NURSE_R                   = 0x69, /*!< Nurse Station */
    ZB_ZCL_BASIC_PHYS_ENV_WARD                      = 0x6a, /*!< Ward */
    ZB_ZCL_BASIC_PHYS_ENV_CORRIDOR                  = 0x6b, /*!< Corridor */
    ZB_ZCL_BASIC_PHYS_ENV_OPERATING_THEATRE         = 0x6c, /*!< Operating Theatre */
    ZB_ZCL_BASIC_PHYS_ENV_DENTAL_SURGERY_R          = 0x6d, /*!< Dental Surgery Room */
    ZB_ZCL_BASIC_PHYS_ENV_MED_IMAGING_R             = 0x6e, /*!< Medical Imaging Room */
    ZB_ZCL_BASIC_PHYS_ENV_DECONTAMINATION_R         = 0x6f, /*!< Decontamination Room */
    ZB_ZCL_BASIC_PHYS_ENV_UNKNOWN_ENV               = 0xff, /*!< Unknown environment */
}zb_zcl_basic_phys_env_t;

void zb_zcl_basic_srv_set_defaults(zb_zcl_basic_srv_attr_t *attrs);
void zb_zcl_basic_srv_setup(zb_uint8_t ep, zb_zcl_basic_srv_attr_t *attrs);
#endif /* ZB_ZCL_BASIC_H */
