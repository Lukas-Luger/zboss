This is a fork of ZBOSS Zigbee Pro 2007 stack for integration with [RIOT-OS](https://github.com/RIOT-OS/RIOT).

Initial ZLL support has been added and tested to work with Tradfri devices.

To use this stack with RIOT-OS, download the openlabs branch and run the zigbee-zll example:

```shell
git clone https://github.com/benemorius/RIOT.git
cd RIOT/examples/zigbee-zll
make -j4 flash
```
