# WIP Kernel 4.4 for LeEco Le Max 2 (X820/821/829)

This is a try to port kernel 4.4 to LeEco Le Max 2 from 3.18 one


## Changes from 3.18 in build things..

Much of defconfig MSM flags are "mainlined" as QCOM flags in kernel 4.4, then, old defconfig it's bit difficult to parse

Legacy interfaces may be obsoleted in 4.4 like some from I2C, I fixed ANX7418 one, but may be more while adding to defconfig

Don't know if IIO defconfig flags are needed

QPNP Driver is modified a lot.. Don't expect 100% great work

It can build with 4.9 and 9.x GCC, but while not boots, I recommend using GCC 4.9

CONFIG\_BUS\_TOPOLOGY\_ADHOC not neccesary, it's in mainline code ever activated.

## TODO

- Port sound/soc/msm/qdsp6v2/msm-pcm-routing-v2.c and sound/soc/msm/qdsp6v2/q6afe.c if needed (They are very different in 3.18 and 4.4)

- Search/add more leeco drivers?

- defconfig why doesn't appear in .config (Seems to be not important):
```
CONFIG_DIAG_CHAR=y
CONFIG_DIAG_OVER_USB=y
CONFIG_SOC_WCD9335
```

- More fixing new defconfig (At least, know what drivers are not there, to add it)

- One expert that sees qpnp-smbcharger.c, I fixed build, but not pro.

## Fix warnings

That about qpnp-int seems important to work right
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

Unused var:
```
  CC      sound/soc/codecs/wcd-mbhc-v2.o
../sound/soc/codecs/wcd-mbhc-v2.c: In function 'wcd_mbhc_init':
../sound/soc/codecs/wcd-mbhc-v2.c:3032:14: warning: unused variable 'hph_irq_det' [-Wunused-variable]
  const char *hph_irq_det = "letv,hph_irq_detect";
```

Unused functions:
```
 CC      sound/soc/msm/msm8996.o
../sound/soc/msm/msm8996.c:5890:12: warning: 'msm_sec_mi2s_rx_be_hw_params_fixup' defined but not used [-Wunused-function]
 static int msm_sec_mi2s_rx_be_hw_params_fixup(struct snd_soc_pcm_runtime *rtd,
            ^
../sound/soc/msm/msm8996.c:5912:12: warning: 'msm_sec_mi2s_tx_be_hw_params_fixup' defined but not used [-Wunused-function]
 static int msm_sec_mi2s_tx_be_hw_params_fixup(struct snd_soc_pcm_runtime *rtd,
            ^
../sound/soc/msm/msm8996.c:5935:12: warning: 'msm_tert_mi2s_rx_be_hw_params_fixup' defined but not used [-Wunused-function]
 static int msm_tert_mi2s_rx_be_hw_params_fixup(struct snd_soc_pcm_runtime *rtd,
            ^
../sound/soc/msm/msm8996.c:6480:27: warning: 'msm8996_sec_mi2s_be_ops' defined but not used [-Wunused-variable]
 static struct snd_soc_ops msm8996_sec_mi2s_be_ops = {
                           ^
../sound/soc/msm/msm8996.c:6485:27: warning: 'msm8996_tert_mi2s_be_ops' defined but not used [-Wunused-variable]
 static struct snd_soc_ops msm8996_tert_mi2s_be_ops = {
                           ^
```

```
  CC      drivers/video/fbdev/msm/mdss_panel.o
../drivers/video/fbdev/msm/mdss_dsi_panel.c:1141:13: warning: 'mdss_dsi_panel_on_hdmi' defined but not used [-Wunused-function]
 static void mdss_dsi_panel_on_hdmi(struct mdss_dsi_ctrl_pdata *ctrl,
             ^
../drivers/video/fbdev/msm/mdss_dsi_panel.c:3139:12: warning: 'mdss_panel_parse_dt_hdmi' defined but not used [-Wunused-function]
 static int mdss_panel_parse_dt_hdmi(struct device_node *np,
            ^
```

```
../drivers/scsi/ufs/ufshcd.c: In function 'ufshcd_hibern8_hold':
../drivers/scsi/ufs/ufshcd.c:1911:7: warning: unused variable 'flush_result' [-Wunused-variable]
 1911 |  bool flush_result;
      |       ^~~~~~~~~~~~

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
