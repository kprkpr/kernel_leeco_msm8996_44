/* Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _SPMI_DBGFS_H
#define _SPMI_DBGFS_H

#include <linux/spmi.h>
#include <linux/debugfs.h>

#ifdef CONFIG_DEBUG_FS

extern void __init spmi_dfs_init(void);
extern void __exit spmi_dfs_exit(void);
extern void spmi_dfs_add_controller(struct spmi_controller *ctrl);
extern void spmi_dfs_del_controller(struct spmi_controller *ctrl);
extern void spmi_dfs_add_device(struct spmi_device *sdev);
extern void spmi_dfs_del_device(struct spmi_device *sdev);

#else

static inline void __init spmi_dfs_init(void) { }
static inline void __exit spmi_dfs_exit(void) { }
static inline void spmi_dfs_add_controller(struct spmi_controller *ctrl) { }
static inline void spmi_dfs_del_controller(struct spmi_controller *ctrl) { }
static inline void spmi_dfs_add_device(struct spmi_device *sdev) { }
static inline void spmi_dfs_del_device(struct spmi_device *sdev) { }
#endif

#endif /* _SPMI_DBGFS_H */
