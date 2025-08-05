This is a fork of ZBOSS Zigbee Pro 2007 stack for integration with [RIOT-OS](https://github.com/RIOT-OS/RIOT).

Initial Touchlink/ZLL support has been added and tested to work with Tradfri and Hue devices.

To use this stack with RIOT-OS, download the pr/zboss branch and run the zigbee-zll example:

```shell
git clone https://github.com/Lukas-Luger/RIOT.git
git checkout pr/zboss
cd RIOT/examples/networking/zigbee-zll
make -j4 flash
```
