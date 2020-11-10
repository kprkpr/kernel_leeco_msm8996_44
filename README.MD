# WIP Kernel 4.4 for LeEco Le Max 2 (X820/821/829)

This is a try to port kernel 4.4 to LeEco Le Max 2 from 3.18 one


## Changes from 3.18 in build things..

Much of defconfig MSM flags are "mainlined" as QCOM flags in kernel 4.4, then, old defconfig it's bit difficult to parse

Legacy interfaces may be obsoleted in 4.4 like some from I2C, I fixed ANX7418 one, but may be more while adding to defconfig

Don't know if IIO defconfig flags are needed

QPNP Driver is modified a lot.. Don't expect 100% great work

It can build with 4.9 and 9.x GCC, but while not boots, I recommend using GCC 4.9

## TODO

- Port sound/soc/msm/qdsp6v2/msm-pcm-routing-v2.c and sound/soc/msm/qdsp6v2/q6afe.c if needed (They are very different in 3.18 and 4.4)

- Search/add more leeco drivers?

- defconfig checks:
```
CONFIG_DIAG_CHAR=y
CONFIG_DIAG_OVER_USB=y
CONFIG_REGULATOR_CPR3_VOLTAGE_CONTROL=y
CONFIG_FB_MSM_MDSS_KCAL_CTRL  (Not exists)
CONFIG_SOUND_CONTROL=y (not exists)
CONFIG_BUS_TOPOLOGY_ADHOC=y
CONFIG_MSM_CPU_PWR_CTL=y
CONFIG_MSM_RPM_SMD=y
CONFIG_MSM_RPM_LOG=y
CONFIG_MSM_RPM_STATS_LOG=y
CONFIG_MSM_RUN_QUEUE_STATS=y
CONFIG_MSM_POWER=y
CONFIG_SOC_WCD9335 why not in final .config
```

- More fixing new defconfig (At least, know what drivers are not there, to add it)

- One expert that sees qpnp-smbcharger.c, I fixed build, but not pro.

## Fix this error!

```
 CC      drivers/spmi/qpnp-int.o
../drivers/spmi/qpnp-int.c: In function 'qpnpint_spmi_read':
../drivers/spmi/qpnp-int.c:129:33: warning: passing argument 1 of 'spmi_ext_register_readl' from incompatible pointer type
  return spmi_ext_register_readl(chip_d->spmi_ctrl,
                                 ^
In file included from ../drivers/spmi/qpnp-int.c:25:0:
../include/linux/spmi.h:198:5: note: expected 'struct spmi_device *' but argument is of type 'struct spmi_controller *'
 int spmi_ext_register_readl(struct spmi_device *sdev, u16 addr, u8 *buf,
     ^
../drivers/spmi/qpnp-int.c: In function 'qpnpint_spmi_write':
../drivers/spmi/qpnp-int.c:142:32: warning: passing argument 1 of 'spmi_ext_register_writel' from incompatible pointer type
  rc = spmi_ext_register_writel(chip_d->spmi_ctrl,
                                ^
In file included from ../drivers/spmi/qpnp-int.c:25:0:
../include/linux/spmi.h:204:5: note: expected 'struct spmi_device *' but argument is of type 'struct spmi_controller *'
 int spmi_ext_register_writel(struct spmi_device *sdev, u16 addr,
```

- Make it boot

## To build

- Have a aarch64 linux kernel toolchain (GCC 4.9 recommended yet, but other will work)

Ex: https://github.com/LineageOS/android_prebuilts_gcc_linux-x86_aarch64_aarch64-linux-android-4.9


    $ export ARCH=arm64 && SUBARCH=arm64
    $ export CROSS_COMPILE=/path/to/aarch64-linux-android-4.9/bin/aarch64-linux-android-
    $ make O=out mrproper
    $ make O=out lineage_x2_defconfig
    $ make O=out -j8
