# WIP Kernel 4.4 for LeEco Le Max 2 (X820/821/829)

This is a try to port kernel 4.4 to LeEco Le Max 2 from 3.18 one


## Changes from 3.18 in build things..

Much of defconfig MSM flags are "mainlined" as QCOM flags in kernel 4.4, then, old defconfig it's bit difficult to parse

Legacy interfaces may be obsoleted in 4.4 like some from I2C, I fixed ANX7418 one, but may be more while adding to defconfig

Don't know if IIO defconfig flags are needed

QPNP Driver is modified a lot.. Don't expect 100% great work

It can build with 4.9 and 9.x GCC, but while not boots, I recommend using GCC 4.9

## TODO

- Fix camera\_v2 sensor msm\_eeprom\_letv imports

- Add drivers

- Fixing new defconfig (At least, know what drivers are not there, to add it)

- One expert that sees qpnp-smbcharger.c, I fixed build, but not pro.

- Make it boot
