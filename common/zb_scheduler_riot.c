#include "ztimer.h"
#include "zb_common.h"
#include "memarray.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#define QUEUE_SIZE (16)
static msg_t _zb_msg_queue[QUEUE_SIZE];

static pid_t _zb_pid;
static char _zigbee_thread_stack [THREAD_STACKSIZE_DEFAULT + 512];

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
}

zb_ret_t zb_schedule_tx_cb(zb_callback_t func,
                           zb_uint8_t param) ZB_SDCC_REENTRANT
{
    zb_ret_t ret = RET_OK;
    zb_mac_cb_ent_t *ent = ZB_RING_BUFFER_PUT_RESERVE(&ZG->sched.mac_tx_q);

    if (ent) {
        ent->func = func;
        ent->param = param;
        ZB_RING_BUFFER_FLUSH_PUT(&ZG->sched.mac_tx_q);
        TRACE_MSG(TRACE_COMMON2, "%p scheduled mac cb %p param %hd (in_b %hd)",
                  (FMT__P_P_H_H, ent, ent->func, ent->param,
                   (!param ? (zb_uint8_t)-1 : ZB_BUF_FROM_REF(param)->u.hdr.
                    is_in_buf)));
        ZB_ASSERT(param <= ZB_IOBUF_POOL_SIZE);
    }
    else {
        TRACE_MSG(TRACE_ERROR, "MAC callbacks rb overflow! param %hd",
                  (FMT__H, param));
        ret = RET_OVERFLOW;
    }
    return ret;
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

void zb_riot_sched_init(void)
{
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
