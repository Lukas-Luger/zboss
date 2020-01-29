This is a fork of ZBOSS Zigbee Pro 2007 stack for integration with [RIOT-OS](https://github.com/RIOT-OS/RIOT).

Currently it is hacked haphazardly and only compiles with Riot. It works, but I haven't checked how completely.

I do plan to clean it up and un-break the build for other platforms, but perhaps not before adding support for ZLL since I probably won't maintain interest if I don't end up doing that.

```shell
git clone https://github.com/RIOT-OS/RIOT.git
mkdir RIOT/pkg/zboss
cat <<'EOF' > RIOT/pkg/zboss/Makefile
PKG_NAME=zboss
PKG_URL=https://github.com/benemorius/zboss.git
PKG_VERSION=master
PKG_LICENSE=GPL-2

.PHONY: all

all: git-download
# 	cp $(RIOTBASE)/pkg/zboss/src/zboss-riot.c $(PKG_BUILDDIR)/osif/unix/zboss-riot.c
	$(MAKE) -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
EOF
cat <<'EOF' > RIOT/pkg/zboss/Makefile.include
INCLUDES += -I$(PKGDIRBASE)/zboss/include
INCLUDES += -I$(PKGDIRBASE)/zboss/osif/include
EOF
cd RIOT/examples/hello-world
sed -i 's/return 0;/zboss_init();\n\n    return 0;/' main.c
export CFLAGS=-DZB_IS_COORDINATOR=1 && USEPKG+=zboss USEMODULE+="gnrc_netif" make -j4
```
