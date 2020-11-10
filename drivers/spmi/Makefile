#
# Makefile for kernel SPMI framework.
#
obj-$(CONFIG_SPMI)	+= spmi.o

obj-$(CONFIG_MSM_QPNP_INT)		+= qpnp-int.o

obj-$(CONFIG_SPMI_MSM_PMIC_ARB)	+= spmi-pmic-arb.o

obj-$(CONFIG_VIRTSPMI_MSM_PMIC_ARB)	+= virtspmi-pmic-arb.o

ifdef CONFIG_DEBUG_FS
obj-$(CONFIG_SPMI)			+= spmi-dbgfs.o
endif
