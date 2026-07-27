/* try to collect all the mess into this file to get the zboss stack
 * cleaned up and then clean this up later */

#include "od.h"
#include "log.h"
#include "luid.h"
#include "ztimer.h"
#include "memarray.h"


#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE
#include "periph/flashpage.h"
#include "riotboot/slot.h"
/* some mcus can only write to the "other half" from where the firmware is */
#define NV_FLASH_PAGE_0 (FLASHPAGE_NUMOF / 2 - 1)
#define NV_FLASH_PAGE_1 (FLASHPAGE_NUMOF - 1)
static unsigned _flash_page;
#elif defined MODULE_AT24CXXX
#include "at24cxxx.h"
#include "at24cxxx_params.h"
at24cxxx_t at24cxxx_dev;
#endif
bool has_eeprom;

#include "zb_common.h"
#include "zb_aps.h"
#include "zb_zdo.h"
#include "zb_secur_api.h"
#include "zb_bufpool.h"

#include <stdarg.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

// #if ENABLE_DEBUG
#include "od.h"
// #else
// #define od_hex_dump(...)
// #endif

#ifndef ZB_IS_COORDINATOR
#define ZB_IS_COORDINATOR (0)
#endif

#define QUEUE_SIZE (16)
static msg_t _zb_msg_queue[QUEUE_SIZE];

static pid_t _zb_pid;
static char _zigbee_thread_stack [THREAD_STACKSIZE_DEFAULT + 512];

static uint8_t _packet_buf[256];
static uint8_t _packet_buf_size;

// zb_ieee_addr_t extended_pan_id;

/* tradfri remote network key */
// zb_uint8_t g_key[16] = { 0x8c, 0xb0, 0x6d, 0x62, 0x93, 0x7b, 0x10, 0x83, 0x76, 0x04, 0xa8, 0x64, 0xc2, 0x7c, 0x71, 0xdf};
zb_uint8_t g_key[16] =
{ 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0x14 };

__attribute__((weak)) void zb_identify(void)
{
    puts("override zb_identify()");
}

__attribute__((weak)) void zb_data_indication(zb_uint8_t param)
{
    (void) param;
    puts("override zb_data_indication()");
}

typedef struct {
    zb_callback_t func;
    ztimer_t timer;
    msg_t msg;
    uint8_t arg;
    uint16_t run_after;
} callback_msg_t;

#define CALLBACK_BUF_SIZE (16)
static memarray_t _callback_memarray;
static uint8_t _callback_memarray_buf[sizeof(callback_msg_t) *
                                      CALLBACK_BUF_SIZE];

void extend_poll_timer(uint8_t arg)
{
    ZDO_CTX().conf_attr.nwk_indirect_poll_rate = ZB_TIME_ONE_SECOND * arg;
}


#define ZB_BEACON_INTERVAL_USEC 15360
uint16_t zb_timer_get(void)
{
   return (uint16_t) (ztimer_now(ZTIMER_USEC) / ZB_BEACON_INTERVAL_USEC);
}

void zb_trace_msg_riot(zb_char_t *format, zb_int_t level, zb_char_t *file_name,
                       const zb_char_t *function, zb_int_t line_number,
                       zb_int_t args_size, ...)
{
    va_list arglist;

    va_start(arglist, args_size);
#ifdef MODULE_LOG_DMESG
    vlog_dmesg(level, file_name, function, line_number, format, arglist);
#else
    vprintf(format, arglist);
    puts("");
#endif
    va_end(arglist);
}

void group_add_conf1(zb_uint8_t param)
{
    (void)param;
    zb_apsme_add_group_conf_t *conf = ZB_GET_BUF_PARAM(ZB_BUF_FROM_REF(param), zb_apsme_add_group_conf_t);
    DEBUG("group add status: %i\n", conf->status);
}

void zb_zdo_startup_complete(zb_uint8_t param)
{
    zb_buf_t *buf = ZB_BUF_FROM_REF(param);

    TRACE_MSG(TRACE_APS2, ">>zb_zdo_startup_complete status %d",
              (FMT__D, (int)buf->u.hdr.status));
    if (buf->u.hdr.status == 0) {
        LOG_INFO("ZDO started ok\n");
        ZB_NIB_SECURITY_LEVEL() = 5;
        // zb_af_set_data_indication(zb_data_indication);
        // zb_data_indication(param);

        // zb_apsme_add_group_req_t *req;
        // zb_buf_reuse(buf);
        // req = ZB_GET_BUF_PARAM(buf, zb_apsme_add_group_req_t);
        // req->endpoint = 1;
        // req->confirm_cb = group_add_conf1;
        // zb_zdo_add_group_req(param);

        // zb_apsme_add_group_req_t *req2;
        // zb_buf_t *buf2 = zb_get_out_buf();
        // req2 = ZB_GET_BUF_PARAM(buf2, zb_apsme_add_group_req_t);
        // req2->group_address = 0;
        // req2->endpoint = 1;
        // req2->confirm_cb = group_add_conf1;
        // zb_zdo_add_group_req(ZB_REF_FROM_BUF(buf2));
    }
    else {
        LOG_ERROR("ZDO start FAILED status %d\n", buf->u.hdr.status);
    }
    zb_free_buf(buf);
}

#define ZB_MSG_SCHEDULE_ALARM (0x4)
#define ZB_MSG_SCHEDULE_CALLBACK (0x5)
#define ZB_MSG_CANCEL_ALARM (0x6)
#define ZB_MSG_FIRE_CALLBACK (0x7)

void zb_sched_loop_iteration(void)
{
    // thread_sleep();
}

zb_ret_t zb_schedule_alarm(zb_callback_t func, zb_uint8_t param,
                           zb_time_t run_after)
{
    //     LOG_DEBUG("0x%lx(%u) run_after %lu\n", (uint32_t)func, param, run_after);

    if (func == NULL) {
        return RET_OK;
    }

    msg_t msg;

    msg.content.ptr = func;
    msg.type = ZB_MSG_SCHEDULE_ALARM;
    msg_send(&msg, _zb_pid);

    msg.content.value = run_after;
    msg.type = param;
    msg_send(&msg, _zb_pid);

    return RET_OK;
}

static zb_ret_t _zb_schedule_alarm(zb_callback_t func, zb_uint8_t param,
                                   zb_time_t run_after)
{
    //     LOG_DEBUG("0x%lx(%u) run_after %lu\n", (uint32_t)func, param, run_after);

    callback_msg_t *callback = memarray_alloc(&_callback_memarray);

    callback->func = func;
    callback->arg = param;
    callback->run_after = run_after;

    callback->msg.content.ptr = callback;
    callback->msg.type = ZB_MSG_FIRE_CALLBACK;

    if (run_after == 0) {
        msg_try_send(&(callback->msg), _zb_pid);
    }
    else {
        uint32_t run_after_usec = run_after * ZB_BEACON_INTERVAL_USEC;
        ztimer_set_msg(ZTIMER_USEC, &(callback->timer), run_after_usec,
                         &(callback->msg), _zb_pid);
    }

    return RET_OK;
}

zb_ret_t zb_schedule_callback(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);

    return zb_schedule_alarm(func, param, 0);


    // msg_t msg;
    // msg.content.ptr = func;
    // msg.type = param;
    // msg_send(&msg, _zb_pid);
    // return RET_OK;
}

zb_ret_t zb_schedule_tx_cb(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);
    return zb_schedule_alarm(func, param, 1);
}

zb_ret_t zb_schedule_alarm_cancel(zb_callback_t func, zb_uint8_t param)
{
    //     LOG_DEBUG("0x%lx(%u)\n", (uint32_t)func, param);

    msg_t msg;

    msg.content.ptr = func;
    msg.type = ZB_MSG_CANCEL_ALARM;
    msg_send(&msg, _zb_pid);

    msg.type = param;
    msg_send(&msg, _zb_pid);

    return RET_OK;
}

static zb_ret_t _zb_schedule_alarm_cancel(zb_callback_t func, zb_uint8_t param)
{
    for (int i = 0; i < CALLBACK_BUF_SIZE; i++) {
        callback_msg_t *callback_msg = (void *)_callback_memarray_buf + i *
                                       sizeof(callback_msg_t);
        if (callback_msg->func == func) {
            DEBUG("removing one 0x%lx, %u, %u\n", (uint32_t)func, param, callback_msg->run_after);
            ztimer_remove(ZTIMER_USEC, &callback_msg->timer);
            memset(callback_msg, 0, sizeof(callback_msg_t));
            memarray_free(&_callback_memarray, callback_msg);
        }

    }
    return RET_OK;
}

static void *_zb_thread(void *arg)
{
    (void)arg;
    msg_init_queue(_zb_msg_queue, QUEUE_SIZE);

//     gnrc_netreg_entry_t entry;
//     entry.target.pid = thread_getpid();
//     entry.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
// #if defined(MODULE_GNRC_NETAPI_MBOX) || defined(MODULE_GNRC_NETAPI_CALLBACKS)
//     entry.type = GNRC_NETREG_TYPE_DEFAULT;
// #endif
//     gnrc_netreg_register(GNRC_NETTYPE_UNDEF, &entry);

    while (1) {
        /* sleep until a callback needs to run */
        msg_t msg;
        msg_receive(&msg);
//         DEBUG("msg type 0x%x from pid %u\n", msg.type, msg.sender_pid);

        if (msg.type == ZB_MSG_SCHEDULE_ALARM) {
            zb_callback_t func = msg.content.ptr;
            /* remaining paramaters are sent in a second msg */
            msg_receive(&msg);
            uint8_t arg = msg.type;
            uint16_t run_after = msg.content.value;
            _zb_schedule_alarm(func, arg, run_after);
            continue;
        }
        else if (msg.type == ZB_MSG_CANCEL_ALARM) {
            zb_callback_t func = msg.content.ptr;
            /* remaining paramaters are sent in a second msg */
            msg_receive(&msg);
            uint8_t arg = msg.type;
            _zb_schedule_alarm_cancel(func, arg);
            continue;
        }
        else if (msg.type == 0x8) {
            uint8_t arg = msg.type;
            zb_callback_t func = msg.content.ptr;
            // printf("_zb_thread(0x%lx, %u)\n", (uint32_t)func, arg);
            func(arg);
            zb_mac_main_loop();
            continue;
        }
        else if (msg.type == ZB_MSG_FIRE_CALLBACK) {
            callback_msg_t *callback = msg.content.ptr;

            assert((uint32_t)msg.content.ptr > 1);

            /* execute callback */
            //         LOG_DEBUG("firing callback 0x%lx(%u)\n", (uint32_t)callback->func, callback->arg);
            if ((uint32_t)callback->func > 0x10000000) {
                printf("wtf not calling 0x%lx(%u)\n", (uint32_t)callback->func,
                       callback->arg);
                printf("sender_pid %u\n", msg.sender_pid);
                assert(0);
                continue;
            }
            callback->func(callback->arg);

            /* clean up and continue sleeping */
            memarray_free(&_callback_memarray, callback);
            // printf("running zb_mac_main_loop()\n");
            // zb_handle_data_request_cmd();
            zb_mac_main_loop();
            continue;
        }
    }
    return NULL;
}

void zb_sched_init(void)
{
//  printf("sizeof(callback_msg_t) = %u\n", sizeof(callback_msg_t));
//  printf("sizeof(xtimer_t) = %u\n", sizeof(xtimer_t));
    memset(_callback_memarray_buf, 0x00, sizeof(_callback_memarray_buf));
    memarray_init(&_callback_memarray,
                  _callback_memarray_buf,
                  sizeof(callback_msg_t),
                  CALLBACK_BUF_SIZE
                  );

    _zb_pid = thread_create(_zigbee_thread_stack, sizeof(_zigbee_thread_stack),
                            5,
                            THREAD_CREATE_STACKTEST,
                            _zb_thread, NULL, "zigbee");
    LOG_INFO("started Zigbee stack with pid %i\n", _zb_pid);
}

int zb_input_packet(int argc, char **argv)
{
    if (argc != 2) {
        printf(
            "takes one argument - hex bytes representing a zigbee packet like 030806ffffffff07\n");
        return 1;
    }
    char *packet_str = argv[1];
    _packet_buf_size = strlen(packet_str) / 2;
//     printf("got %u bytes: <%s>\n", _packet_buf_size, packet_str);

    char byte_str[3];
    byte_str[2] = '\0';
    for (int i = 0; i < _packet_buf_size; ++i) {
        byte_str[0] = packet_str[i * 2];
        byte_str[1] = packet_str[i * 2 + 1];
        _packet_buf[i] = strtoul(byte_str, NULL, 16);
    }

    // zb_set_trans_int();
    // zb_mac_main_loop();


    zb_buf_t *buf = zb_get_in_buf();
    zb_mac_recv_data(ZB_REF_FROM_BUF(buf));

    return 0;
}

void send_packet(uint8_t *buf, uint32_t length)
{
//     LOG_DEBUG("sending packet with length %u\n", length);
//     printf("out: ");
//     od_hex_dump(buf, length, 16);

//     memcpy(payload_buf, buf, length);
//     iolist_t iolist = {
//         .iol_base = payload_buf,
//         .iol_len = length
//     };
//     driver->send(netdev, &iolist);


//     gnrc_pktsnip_t netif_hdr = gnrc_netif_hdr_build(src, src_len, dst, dst_len);
//     netif_hdr.next = pkt;

//     if (!ZB_PIB_RX_ON_WHEN_IDLE()) {
//      sleep_radio(false);
//     }

//     gnrc_netapi_dispatch_send(GNRC_NETTYPE_NETIF, GNRC_NETREG_TYPE_DEFAULT,
//                                                                 netif_hdr);

//    if (!ZB_PIB_RX_ON_WHEN_IDLE()) {
//        ZB_SCHEDULE_ALARM(sleep_radio, true,
//                                ZB_MILLISECONDS_TO_BEACON_INTERVAL(200));
//        ZB_SCHEDULE_ALARM(extend_poll_timer, 180, ZB_TIME_ONE_SECOND * 15);
//    }
}

int zb_inject_packet(int argc, char **argv)
{
    if (argc != 2) {
        printf(
            "takes one argument - hex bytes representing a zigbee packet like 030806ffffffff07\n");
        return 1;
    }

    char *packet_str = argv[1];
    unsigned packet_len = strlen(packet_str) / 2;
    uint8_t buf[packet_len];

    char byte_str[3];
    byte_str[2] = '\0';
    for (int i = 0; i < packet_len; ++i) {
        byte_str[0] = packet_str[i * 2];
        byte_str[1] = packet_str[i * 2 + 1];
        buf[i] = strtoul(byte_str, NULL, 16);
    }

    send_packet(buf, packet_len);
}

#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE
static uint8_t pagebuf[FLASHPAGE_SIZE] __attribute__((aligned(FLASHPAGE_WRITE_BLOCK_ALIGNMENT)));
FLASH_WRITABLE_INIT(backing_mem, 0x1);
#endif

zb_uint8_t zb_write_nvram (zb_uint16_t pos, void *buf, zb_uint16_t len)
{
#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE
    /* get the existing page data */
//     printf("read\n");
    flashpage_read(_flash_page, pagebuf);

    /* make the requested changes */
    memcpy(pagebuf + pos, buf, len);

    /* erase the flash page */
//     printf("erase\n");
    flashpage_erase(_flash_page);//, NULL);

    /* write the new page data */
//     printf("write\n");
    if (flashpage_write_and_verify(_flash_page, pagebuf) != FLASHPAGE_OK) {
        LOG_ERROR("flashpage write failure\n");
        return 0;
    }

#elif defined MODULE_AT24CXXX
    if (at24cxxx_write(&at24cxxx_dev, pos, buf, len) != AT24CXXX_OK) {
        LOG_ERROR("eeprom write failure\n");
        return 0;
    }
#endif
    return len;
}

zb_uint8_t zb_read_nvram(zb_uint16_t pos, void *buf, zb_uint16_t len)
{
#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE
    flashpage_read(_flash_page, pagebuf);
    memcpy(buf, pagebuf + pos, len);

#elif defined MODULE_AT24CXXX
    if (at24cxxx_read(&at24cxxx_dev, pos, buf, len) != AT24CXXX_OK) {
        LOG_ERROR("eeprom read failure\n");
        return 0;
    }
#endif
    return len;
}

void zb_erase_nvram(zb_uint8_t page)
{
    (void)page;
#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE
    flashpage_erase(_flash_page);
#endif
}

void zboss_init(void)
{
#if defined MODULE_PERIPH_FLASHPAGE && defined MODULE_PERIPH_FLASHPAGE_IN_ADDRESS_SPACE

    _flash_page = flashpage_page((void *)backing_mem);
    if (_flash_page > FLASHPAGE_NUMOF) {
        _flash_page = FLASHPAGE_NUMOF -1;
    }
    has_eeprom = true;

# ifdef MODULE_RIOTBOOT
    if (riotboot_slot_current() == 0) {
        _flash_page = NV_FLASH_PAGE_1;
    }
    else if (riotboot_slot_current() == 1) {
        _flash_page = NV_FLASH_PAGE_0;
    }
    else {
        assert(0);
    }
# endif

LOG_INFO("using page %u of internal flash as nonvolatile storage\n",
           _flash_page);

#elif defined MODULE_AT24CXXX
    uint8_t c;
    if (at24cxxx_init(&at24cxxx_dev, &at24cxxx_params[0]) == AT24CXXX_OK &&
        at24cxxx_read(&at24cxxx_dev, 0, &c, 1) == AT24CXXX_OK
        ) {
        has_eeprom = true;
        LOG_ERROR("using external eeprom as nonvolatile storage\n");
    }
    else {
        LOG_ERROR("eeprom not detected\n");
    }
#else
    LOG_WARNING("compiled without eeprom/nvram support\n");
#endif

#if 0
    /* print eeprom contents to console */
    if (has_eeprom) {
        uint8_t buf[255];
        memset(buf, 0xff, sizeof(buf));
        zb_read_nvram(0, buf, sizeof(buf));
        od_hex_dump(buf, sizeof(buf), 16);
    }
#endif


    // uint8_t omg[] = {0x03, 0x08, 0x77, 0xff, 0xff, 0xff, 0xff, 0x07};
    // send_packet(omg, sizeof(omg));

    LOG_INFO("starting zigbee stack\n");

    zb_init("omg", "3", "3");
    //should be set in zb-ib.c:119 via zb_config.h!
    //ZG->nwk.nib.security_level = 0;

//     zb_secur_setup_preconfigured_key(g_key, 0);
//     zb_read_security_key();

//     zb_transceiver_update_short_addr(0x0043);
//     MAC_PIB().mac_pan_id = 0x359b;


//     extended_pan_id[7] = 0xfc;
//     extended_pan_id[6] = 0xc1;
//     extended_pan_id[5] = 0x1c;
//     extended_pan_id[4] = 0xe0;
//     extended_pan_id[3] = 0x61;
//     extended_pan_id[2] = 0xbe;
//     extended_pan_id[1] = 0x0f;
//     extended_pan_id[0] = 0xb9;
//     ZB_IEEE_ADDR_COPY(ZB_NIB_EXT_PAN_ID(), &extended_pan_id);

//     ZB_EXTPANID_COPY(ZB_PIB_BEACON_PAYLOAD().extended_panid, extended_pan_id);
//     ZB_EXTPANID_COPY(ZB_NIB_EXT_PAN_ID(), extended_pan_id);

//     if (ZB_IS_COORDINATOR || 1) {
//         /* let's always be coordinator */
//         ZB_AIB().aps_designated_coordinator = 1;
//         MAC_PIB().mac_pan_id = 0x1aaa;
//         MAC_PIB().mac_pan_id = 0x1417;
//      zb_transceiver_update_short_addr(0x0002);

//      zb_secur_setup_preconfigured_key(g_key, 0);
//     }

    uint8_t rand_seq;
    luid_get(&rand_seq, 1);
    ZB_NIB_SEQUENCE_NUMBER() = rand_seq;

#if defined BOARD_OPENLABS_KW41Z_MINI || 1
    ZG->nwk.handle.permit_join = 1;
    MAC_PIB().mac_association_permit = 1;
    /**
     * Zero will do disovery and rejoin -> provides us with PAN ID
     * One start as Coordinator -> PAN ID is zero (as coord should)
     * BUT: with PAN ID 0x0000 we do get ignored as Touchlink Target
     */
    ZB_AIB().aps_designated_coordinator = 0;
//     ZG->nwk.handle.router_started = 1;
#else
    ZB_AIB().aps_designated_coordinator = 0;
    ZB_PIB_RX_ON_WHEN_IDLE() = 0;
#endif

    ZG->aps.authenticated = 1;

    int res = zdo_dev_start();
    DEBUG("zdo_dev_start() returned %i\n", res);

    zdo_main_loop(); /* this does nothing and returns immediately */
}


int cmd_zconfig(int argc, char *argv[])
{
    char addr[ZB_PRETTY_ADDR_LEN];
    printf("manual ack:\t\t");
#ifdef ZB_MANUAL_ACK
    printf(" 1\n");
#else
    printf(" 0\n");
#endif
    printf("end device role:\t");
#ifdef ZB_ED_ROLE
    printf(" 1\n");
#else
    printf(" 0\n");
#endif
    printf("coordinator role:\t");
#ifdef ZB_COORDINATOR_ROLE
    printf(" 1\n");
#else
    printf(" 0\n");
#endif
    printf("router role:\t\t");
#ifdef ZB_ROUTER_ROLE
    printf(" 1\n");
#else
    printf(" 0\n");
#endif
    printf("device type as int:\t %d\n", (zb_uint8_t)ZB_NIB_DEVICE_TYPE());
    switch(ZB_NIB_DEVICE_TYPE()){
        case ZB_NWK_DEVICE_TYPE_COORDINATOR:
            printf("device type:\t\t COORDINATOR\n");
            break;
        case ZB_NWK_DEVICE_TYPE_ROUTER:
            printf("device type:\t\t ROUTER\n");
            break;
        case ZB_NWK_DEVICE_TYPE_ED:
            printf("device type:\t\t ED\n");
            break;
        default:
            printf("device type:\t\t NONE\n");
            break;
    }
    printf("joined: \t\t %i\n", ZG->nwk.handle.joined);
    printf("joined pro: \t\t %i\n", ZG->nwk.handle.joined_pro);
    printf("trust center: \t %i\n", ZG->nwk.handle.is_tc);
    printf("RX on while idle: \t %i\n", ZG->mac.pib.mac_rx_on_when_idle);
    printf("aps authenticated: \t %i\n", ZG->aps.authenticated);
    printf("designated coordinator:%i\n", ZB_AIB().aps_designated_coordinator);
    printf("nwk state:\t\t %i\n", ZG->nwk.handle.state);
    printf("router: \t\t %i\n", ZG->nwk.handle.router_started);
    printf("device type: \t\t %i\n", ZG->nwk.nib.device_type);
    printf("permit joining: \t %i\n", ZG->nwk.handle.permit_join);
    printf("security level: \t %i\n", ZG->nwk.nib.security_level);
    printf("in buffers used: \t %i/%i\n", ZG->bpool.bufs_allocated[1],
                                            ZB_IOBUF_POOL_SIZE / 2);
    printf("out buffers used: \t %i/%i\n", ZG->bpool.bufs_allocated[0],
                                            ZB_IOBUF_POOL_SIZE / 2);
    printf("channel: \t\t %d\n",  zb_transceiver_get_channel());
    printf("PAN ID \t\t 0x%04x\n", MAC_PIB().mac_pan_id);
    zb_pretty_long_address(addr, sizeof(addr),
                                            ZB_NIB_EXT_PAN_ID());
    printf("Extended Pan ID: \t %s\n", addr);

    printf("Short Address \t\t 0x%04x\n", ZG->mac.pib.mac_short_address);
    zb_pretty_long_address(addr, sizeof(addr),
                                            ZG->mac.pib.mac_extended_address);
    printf("Long Address: \t\t %s\n", addr);

    zb_ieee_addr_t long_parent_addr;
    zb_uint16_t short_parent_addr;
    zb_address_short_by_ref(&short_parent_addr, ZG->nwk.handle.parent);
    zb_address_ieee_by_ref(long_parent_addr, ZG->nwk.handle.parent);

    printf("Parent Short Address \t\t 0x%04x\n", short_parent_addr);
    zb_pretty_long_address(addr, sizeof(addr), long_parent_addr);
    printf("Parent Long Address: \t\t %s\n", addr);

    printf("Coordinator Short Address \t 0x%04x\n",
           ZG->mac.pib.mac_coord_short_address);
    zb_pretty_long_address(addr, sizeof(addr),
                        ZG->mac.pib.mac_coord_extended_address);
    printf("Coordinator Long Address: \t %s\n", addr);
#ifdef ZB_SECURITY
    zb_uint8_t *network_key = ZG->nwk.nib.secur_material_set[0].key;
    printf("Network Key: \t\t\t ");
    for (zb_uint8_t i=0; i < sizeof(ZG->nwk.nib.secur_material_set[0].key); i++){
        printf("%02x", network_key[i]);
    }
    printf("\n");
#endif

#ifdef ZB_ROUTER_ROLE
    printf("nwk rebroadcast table:\n");
    printf(
        "\tseq_num\tused\tretries\tnext_retransmit\twait_conf\tneighbor\tsrc_addr\tdst_addr\n");
    zb_nwk_broadcast_retransmit_t *retransmit_entry = NULL;
    for (int i = 0; i < ZB_NWK_BRR_TABLE_SIZE; i++) {
        retransmit_entry = &ZG->nwk.handle.brrt[i];
        if (!retransmit_entry || !retransmit_entry->used) {
            continue;
        }
        printf("\t% 7i\t% 4i\t% 7i\t% 15i\t% 9i\t% 8i\t% 8x\t% 8x\n",
               retransmit_entry->seq_num,
               retransmit_entry->used, retransmit_entry->retries,
               retransmit_entry->next_retransmit * ZB_BEACON_INTERVAL_USEC / 1000,
               retransmit_entry->wait_conf, retransmit_entry->neighbor_table_iterator,
               retransmit_entry->src_addr, retransmit_entry->dst_addr
        );
    }
#endif


    printf("ext neighbors: %i/%i used\n", ZG->nwk.neighbor.ext_neighbor_used,
           ZG->nwk.neighbor.ext_neighbor_size );

    printf("\tlong_addr\t\text_panid\t\t\taddr\n");
    printf("\t\tpermit_join\tpotential_parent\tdevice_type\trouter\t\n");

    zb_ext_neighbor_tbl_ent_t *ext_neighbor = NULL;
    for (int i = 0; i < ZG->nwk.neighbor.ext_neighbor_used; i++) {
        ext_neighbor = &ZG->nwk.neighbor.ext_neighbor[i];

        char long_addr[24];
        zb_ieee_addr_t laddr;
        ZB_ADDRESS_DECOMPRESS(laddr, ext_neighbor->long_addr);
        zb_pretty_long_address(long_addr, sizeof(long_addr), laddr);

        char pan_id[24];
        zb_ieee_addr_t pan;
        zb_address_ieee_by_ref(pan, ext_neighbor->panid_ref);
        zb_pretty_long_address(pan_id, sizeof(pan_id), pan);

        printf("\t%s\t%s\t0x%04x\n",
               long_addr, pan_id, ext_neighbor->short_addr
        );
        printf("\t\t%i\t\t%i\t\t\t%i\t\t%i\n",
               ext_neighbor->permit_joining, ext_neighbor->potential_parent,
               ext_neighbor->device_type, ext_neighbor->router_capacity
        );
    }

    printf("neighbors: %i/%i used\n", ZG->nwk.neighbor.base_neighbor_used,
           ZG->nwk.neighbor.base_neighbor_size );
    printf("nwk neighbor table:\n");
    printf(
        "\tdevice_type\tdepth\trelationship\tlqi\tpermit_joining\trx_idle\ttx_failure\taddress\n");
    zb_neighbor_tbl_ent_t *neighbor = NULL;
    for (int i = 0; i < ZG->nwk.neighbor.base_neighbor_size; i++) {
        neighbor = &ZG->nwk.neighbor.base_neighbor[i];
        if (!neighbor || !neighbor->used) {
            continue;
        }

        char abuf[24];
        zb_ieee_addr_t addr;
        zb_address_ieee_by_ref(addr, neighbor->addr_ref);
        zb_pretty_long_address(abuf, sizeof(abuf), addr);
        printf("\t% 11i\t% 5i\t% 12i\t% 3i\t% 14i\t% 7i\t% 10i\t%s\n",
               neighbor->device_type, neighbor->depth, neighbor->relationship,
               neighbor->lqi, neighbor->permit_joining,
               neighbor->rx_on_when_idle, neighbor->transmit_failure,
               abuf
        );
    }
    printf("source binding table:\n");
    printf("\tsrc_addr\t\tsrc_endpoint\tcluster_id\n");
    zb_aps_bind_src_table_t *src_bind = NULL;
    for(int i = 0; i < ZG->aps.binding.src_n_elements; i++){
        src_bind = &ZG->aps.binding.src_table[i];

        char abuf[24];
        zb_ieee_addr_t addr;
        zb_address_ieee_by_ref(addr, src_bind->src_addr);
        zb_pretty_long_address(abuf, sizeof(abuf), addr);
        printf("\t%s\t% 02x\t\t% 04x \n", abuf, src_bind->src_end, src_bind->cluster_id);
    }
    printf("destination binding table:\n");
    printf("\tdst_addr_mode\tdst_addr\t\tdst_endpoint\tsrc_table_index\n");
    zb_aps_bind_dst_table_t *dst_bind = NULL;
    for(int i = 0; i < ZG->aps.binding.dst_n_elements; i++){
        dst_bind = &ZG->aps.binding.dst_table[i];
        if(dst_bind->dst_addr_mode == 0){
            printf("\t% 02x\t\t% 04x\t--\t\t% u\n", dst_bind->dst_addr_mode ,dst_bind->u.group_addr, dst_bind->src_table_index);
        }else{
            char abuf[24];
            zb_ieee_addr_t addr;
            zb_address_ieee_by_ref(addr, dst_bind->u.long_addr.dst_addr);
            zb_pretty_long_address(abuf, sizeof(abuf), addr);
            printf("\t% 02x\t\t% s\t% 02x\t\t% u\n", dst_bind->dst_addr_mode ,abuf,dst_bind->u.long_addr.dst_end ,dst_bind->src_table_index);
        }
    }
    printf("simple descriptor table:\n");
    printf("\tindex\tendpoint\tprofile id\tdevice id\tversion\tinput cl\toutput cl\n");
    for(int i = 0; i < ZB_ZDO_SIMPLE_DESC_NUMBER(); i++){
        printf("\t%d\t%02x\t\t%04x\t\t%04x\t\t%02x\t%02x\t\t%02x\n",i ,ZB_ZDO_SIMPLE_DESC_LIST()[i]->endpoint, 
            ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_profile_id, 
            ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_device_id,
            ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_device_version,
            ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_input_cluster_count,
            ZB_ZDO_SIMPLE_DESC_LIST()[i]->app_output_cluster_count);
    }

    return 0;
}

int cmd_buffers(int argc, char *argv[])
{
    zb_buf_t *tmp;
    zb_ushort_t i;
    zb_uint8_t in_cnt = 0, out_cnt = 0;
    for (i = 0; i < ZB_IOBUF_POOL_SIZE; i++) {
        tmp = &ZG->bpool.pool[i];
        if (ZB_BUF_IS_FREE(tmp)) {
            continue;
        }
        if (tmp == MAC_CTX().pending_buf) {
            printf("MAC pend Buf ");
        }
        if (tmp == MAC_CTX().recv_buf) {
            printf("MAC Recv Buf ");
        }
        if (tmp == MAC_CTX().operation_buf) {
            printf("MAC Op Buf ");
        }
        if (tmp == MAC_CTX().operation_recv_buf) {
            printf("MAC Op Rcv Buf ");
        }
        if (tmp == MAC_CTX().encryption_buf) {
            printf("MAC Encr Buf ");
        }
        if (tmp == ZLL_COMM().net_p_buf) {
            printf("ZLL Net param Buf ");
        }
        if (i == MAC_CTX().tx_wait_cb_arg) {
            printf("MAC cb arg Buf for 0x%x ", MAC_CTX().tx_wait_cb);
        }
        if (i == ZG->zdo.handle.parent_annce) {
            printf("ZDO Parent annce Buf ");
        }
        if (tmp->u.hdr.is_in_buf) {
            printf("IN Buffer %d (size: %d)\n", i, ZB_BUF_LEN(tmp));
            in_cnt++;
        } else {
            printf("OUT Buffer %d (size: %d)\n", i, ZB_BUF_LEN(tmp));
            out_cnt++;
        }
        if (ZB_BUF_LEN(tmp) > 0 ) {
            od_hex_dump(ZB_BUF_BEGIN(tmp), ZB_BUF_LEN(tmp), 16);
        } else{
            od_hex_dump(tmp->buf, ZB_IO_BUF_SIZE, 16);
        }
    }
    printf("\nshown %d/%d IN  Buffers\nshown %d/%d OUT Buffers\n",in_cnt, ZG->bpool.bufs_allocated[1], out_cnt, ZG->bpool.bufs_allocated[0]);
}

int cmd_dev_info(int argc, char *argv[])
{
    zb_apl_dev_info_ent_t *ent;
    zb_address_ieee_ref_t addr;
    zb_uint16_t short_addr;
    printf("available devices:\n\tshort addr\tendpoint\tprofile id\tdevice id\tversion\tgroup_id_count\n");
    for (zb_uint8_t i = 0; i < APL_CTX().dev_info_used; i++) {
        ent = &APL_CTX().dev_info_tbl[i];
        short_addr = 0xffff;
        if (RET_OK == zb_address_by_ieee(ent->long_addr, ZB_FALSE, ZB_FALSE, &addr)) {
            zb_address_short_by_ref(&short_addr, addr);
        }
        printf("\t%04x\t\t%d\t\t%04x\t\t%04x\t\t%d\t%d\n", short_addr, ent->endpoint, ent->profile_id,
            ent->device_id, ent->version, ent->group_id_count);
    }
    return 0;
}
