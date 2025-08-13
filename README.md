# About
This is a fork of ZBOSS Zigbee Pro 2007 stack for integration with [RIOT-OS](https://github.com/RIOT-OS/RIOT). For current progress see [WORKING.md](./WORKING.md). Note that things might not work as intended or even crash, since this is still work in progress to bring everything up to date.

# Verified working devices

Interoperablity was tested with following devices: Fritz!Box 7690, IKEA Tradfri and Phillips Hue White & Ambience Bulbs.
Each device is tested seperately. Multidevice support is not tested.

# Installation
To use this stack with RIOT-OS, download the pr/zboss branch and run the zigbee-zll example:

```shell
git clone https://github.com/Lukas-Luger/RIOT.git
git checkout pr/zboss
cd RIOT/examples/networking/zigbee-zll
make -j4 flash
```

## Usage
**WARNING:** not all information is persistent, be sure to use ```reset``` command on failed joining attempts.

### Touchlink Initiator (e.g. joining a IKEA/Phillips Hue bulb)
- bring the microcontroller as close as possible to the bulb.
- enter ```tl_scan``` in the console.
- ZBOSS will do an automated dicovery on predefined channels for possible Targets.
- the bulb is joined as soon as ```saving config``` appears in the console.

### Touchlink Target (e.g. joining to IKEA Styrbar Remote)
- bring the microcontroller as close as possible to the remote.
- press and hold the pairing button on Styrbar.
- Touchlink procedure should follow.
- release button once ```JJOINED``` appears in console.
- On/Off button now controls LED.

### Permit Joining (e.g. joining to Fritz!Box)
- set channel to 25 on your device OR change ZB_DEFAULT_APS_CHANNEL_MASK to include your channel in zb_config.h:716 by appending ```| (1l << [your_channel])```
- press button to join a new Device.
- start the microcontroller (e.g. apply power).
- it will request a Beacon, which should have Association Permit bit set to true.
- ZBOSS will automatically follow up with MAC association request.
- Supported Key Exchange Method: APSME-TRANSPORT-KEY.
- after a short interview, your hub/bridge should show a On/Off Light.


For more details see [zll-zigbee example README.md](https://github.com/Lukas-Luger/RIOT/tree/pr/zboss/examples/networking/zigbee-zll)
