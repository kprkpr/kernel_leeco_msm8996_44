# WIP Kernel 4.4 for LeEco Le Max 2 (X820/821/829)

This is a try to port kernel 4.4 to LeEco Le Max 2 from 3.18 one


## Changes from 3.18 in build things..

Much of defconfig MSM flags are "mainlined" as QCOM flags in kernel 4.4, then, old defconfig it's bit difficult to parse

Legacy interfaces may be obsoleted in 4.4 like some from I2C, I fixed ANX7418 one, but may be more while adding to defconfig

Don't know if IIO defconfig flags are needed

QPNP Driver is modified a lot.. Don't expect 100% great work

It can build with 4.9 and 9.x GCC, but while not boots, I recommend using GCC 4.9

## TODO

- Fix drivers/media/platform/msm/camera_v2/sensor/eeprom/ \_eeprom\_letv imports

- Port sound/soc/msm/qdsp6v2/msm-pcm-routing-v2.c and sound/soc/msm/qdsp6v2/q6afe.c if needed (They are very different in 3.18 and 4.4)

- Search/add more leeco drivers?

- Fix why CONFIG_DIAG doesn't be in .config

- More fixing new defconfig (At least, know what drivers are not there, to add it)

- One expert that sees qpnp-smbcharger.c, I fixed build, but not pro.

- Make it boot

## To build

- Have a aarch64 linux kernel toolchain (GCC 4.9 recommended yet, but other will work)

Ex: https://github.com/LineageOS/android_prebuilts_gcc_linux-x86_aarch64_aarch64-linux-android-4.9


    $ export ARCH=arm64 && SUBARCH=arm64
    $ export CROSS_COMPILE=/path/to/aarch64-linux-android-4.9/bin/aarch64-linux-android-
    $ make O=out mrproper
    $ make O=out lineage_x2_defconfig
    $ make O=out -j8
