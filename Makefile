MODULE = zboss

DIRS += aps common mac nwk secur zdo osif/unix

CFLAGS += -DZB_PLATFORM_RIOT_ARM
CFLAGS += -W -Wall -Wpointer-arith -Wcast-align -w -fno-strict-aliasing

include $(RIOTBASE)/Makefile.base
