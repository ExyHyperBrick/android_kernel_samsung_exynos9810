#
# Copyright (c) 2013 Samsung Electronics Co., Ltd.
#		http://www.samsung.com
#
# Licensed under GPLv2
#

subdir-ccflags-$(CONFIG_DPU_2_0_FENCE)	+= -DCONFIG_EXYNOS_DPU20

obj-$(CONFIG_EXYNOS_DPP) += dpp.o
dpp-y := dpp_drv.o
obj-$(CONFIG_EXYNOS_MIPI_DSIM) += dsim.o
dsim-y += dsim_drv.o
obj-$(CONFIG_EXYNOS_DISPLAYPORT) += displayport.o
displayport-y += displayport_drv.o displayport_edid.o displayport_hdcp13.o ./cal_9810/displayport_reg.o secdp_unit_test.o secdp_aux_control.o
obj-$(CONFIG_SOC_EXYNOS9810) += ./cal_9810/dsim_reg.o ./cal_9810/dpp_reg.o ./cal_9810/decon_reg.o
obj-$(CONFIG_EXYNOS_EVEREST) += decon.o
obj-$(CONFIG_DECON_EVENT_LOG) += event_log.o
obj-$(CONFIG_EXYNOS9810_BTS) += bts.o
decon-y += decon_core.o decon_dsi.o decon_displayport.o decon_wb.o helper.o win_update.o cursor.o
obj-y += panels/
obj-y += dp_logger/
