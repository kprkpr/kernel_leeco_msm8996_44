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
#define pr_fmt(fmt) "%s:%d: " fmt, __func__, __LINE__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/spmi.h>
#include <linux/ctype.h>
#include "spmi-dbgfs.h"

#define ADDR_LEN	 6	/* 5 byte address + 1 space character */
#define CHARS_PER_ITEM	 3	/* Format is 'XX ' */
#define ITEMS_PER_LINE	16	/* 16 data items per line */
#define MAX_LINE_LENGTH	(ADDR_LEN + (ITEMS_PER_LINE * CHARS_PER_ITEM) + 1)

#define MAX_REG_PER_TRANSACTION	(8)

static const mode_t DFS_MODE = S_IRUSR | S_IWUSR;

/* Log buffer */
struct spmi_log_buffer {
	u32 rpos;	/* Current 'read' position in buffer */
	u32 wpos;	/* Current 'write' position in buffer */
	u32 len;	/* Length of the buffer */
	char data[0];	/* Log buffer */
};

/* SPMI transaction parameters */
struct spmi_trans {
	u32 cnt;	/* Number of bytes to read */
	u32 addr;	/* 20-bit address: SID + PID + Register offset */
	u32 offset;	/* Offset of last read data */
	bool raw_data;	/* Set to true for raw data dump */
	struct spmi_device *sdev;
	struct spmi_log_buffer *log; /* log buffer */
};

static char dbgfs_help[] =
	"SPMI Debug-FS support\n"
	"\n"
	"Hierarchy schema:\n"
	"/sys/kernel/debug/spmi\n"
	"       /help                -- Static help text\n"
	"       /spmi-0              -- Directory for SPMI bus 0\n"
	"       /spmi-0/0-1          -- Directory for SPMI device '0-1'\n"
	"       /spmi-0/0-1/address  -- Starting register for reads or writes\n"
	"       /spmi-0/0-1/count    -- Number of registers to read (only used for reads)\n"
	"       /spmi-0/0-1/data     -- Initiates the SPMI read (formatted output)\n"
	"       /spmi-0/0-1/data_raw -- Initiates the SPMI raw read or write\n"
	"       /spmi-n              -- Directory for SPMI bus n\n"
	"\n"
	"To perform SPMI read or write transactions, you need to first write the\n"
	"address of the slave device register to the 'address' file.  For read\n"
	"transactions, the number of bytes to be read needs to be written to the\n"
	"'count' file.\n"
	"\n"
	"The 'address' file specifies the 20-bit address of a slave device register.\n"
	"The upper 4 bits 'address[19..16]' specify the slave identifier (SID) for\n"
	"the slave device.  The lower 16 bits specify the slave register address.\n"
	"\n"
	"Reading from the 'data' file will initiate a SPMI read transaction starting\n"
	"from slave register 'address' for 'count' number of bytes.\n"
	"\n"
	"Writing to the 'data' file will initiate a SPMI write transaction starting\n"
	"from slave register 'address'.  The number of registers written to will\n"
	"match the number of bytes written to the 'data' file.\n"
	"\n"
	"Example: Read 4 bytes starting at register address 0x1234 for SID 2\n"
	"\n"
	"echo 0x21234 > address\n"
	"echo 4 > count\n"
	"cat data\n"
	"\n"
	"Example: Write 3 bytes starting at register address 0x1008 for SID 1\n"
	"\n"
	"echo 0x11008 > address\n"
	"echo 0x01 0x02 0x03 > data\n"
	"\n"
	"Note that the count file is not used for writes.  Since 3 bytes are\n"
	"written to the 'data' file, then 3 bytes will be written across the\n"
	"SPMI bus.\n\n";

static struct debugfs_blob_wrapper spmi_debug_help = {
	.data	= dbgfs_help,
	.size	= sizeof(dbgfs_help),
};

static struct dentry *spmi_debug_root;

static int spmi_device_dfs_open(struct spmi_device *sdev, struct file *file)
{
	struct spmi_log_buffer *log;
	struct spmi_trans *trans;

	size_t logbufsize = SZ_4K;

	/* Per file "transaction" data */
	trans = kzalloc(sizeof(*trans), GFP_KERNEL);
	if (!trans)
		return -ENOMEM;

	log = kzalloc(logbufsize, GFP_KERNEL);
	if (!log) {
		kfree(trans);
		return -ENOMEM;
	}

	log->rpos = 0;
	log->wpos = 0;
	log->len = logbufsize - sizeof(*log);

	trans->log = log;
	trans->cnt = sdev->dfs_cnt;
	trans->addr = sdev->dfs_addr;
	trans->sdev = sdev;
	trans->offset = trans->addr;

	file->private_data = trans;
	return 0;
}

static int spmi_device_dfs_data_open(struct inode *inode, struct file *file)
{
	struct spmi_device *sdev = inode->i_private;
	return spmi_device_dfs_open(sdev, file);
}

static int spmi_device_dfs_raw_data_open(struct inode *inode, struct file *file)
{
	struct spmi_device *sdev = inode->i_private;
	struct spmi_trans *trans;
	int rc;

	rc = spmi_device_dfs_open(sdev, file);
	trans = file->private_data;
	trans->raw_data = true;
	return rc;
}

static int spmi_device_dfs_close(struct inode *inode, struct file *file)
{
	struct spmi_trans *trans = file->private_data;
	kfree(trans->log);
	kfree(trans);
	return 0;
}

/**
 * spmi_read_data: reads data across the SPMI bus
 * @ctrl: The SPMI controller
 * @buf: buffer to store the data read.
 * @offset: SPMI address offset to start reading from.
 * @cnt: The number of bytes to read.
 *
 * Returns 0 on success, otherwise returns error code from SPMI driver.
 */
static int
spmi_read_data(struct spmi_device *sdev, uint8_t *buf, int offset, int cnt)
{
	int ret = 0;
	int len;
	uint16_t addr;

	while (cnt > 0) {
		addr = offset & 0xFFFF;
		len = min(cnt, MAX_REG_PER_TRANSACTION);

		ret = spmi_ext_register_readl(sdev, addr, buf, len);
		if (ret < 0) {
			pr_err("SPMI read failed, err = %d\n", ret);
			goto done;
		}

		cnt -= len;
		buf += len;
		offset += len;
	}

done:
	return ret;
}

/**
 * spmi_write_data: writes data across the SPMI bus
 * @ctrl: The SPMI controller
 * @buf: data to be written.
 * @offset: SPMI address offset to start writing to.
 * @cnt: The number of bytes to write.
 *
 * Returns 0 on success, otherwise returns error code from SPMI driver.
 */
static int
spmi_write_data(struct spmi_device *sdev, uint8_t *buf, int offset, int cnt)
{
	int ret = 0;
	int len;
	uint16_t addr;

	while (cnt > 0) {
		addr = offset & 0xFFFF;
		len = min(cnt, MAX_REG_PER_TRANSACTION);

		ret = spmi_ext_register_writel(sdev, addr, buf, len);
		if (ret < 0) {
			pr_err("SPMI write failed, err = %d\n", ret);
			goto done;
		}

		cnt -= len;
		buf += len;
		offset += len;
	}

done:
	return ret;
}

/**
 * print_to_log: format a string and place into the log buffer
 * @log: The log buffer to place the result into.
 * @fmt: The format string to use.
 * @...: The arguments for the format string.
 *
 * The return value is the number of characters written to @log buffer
 * not including the trailing '\0'.
 */
static int print_to_log(struct spmi_log_buffer *log, const char *fmt, ...)
{
	va_list args;
	int cnt;
	char *buf = &log->data[log->wpos];
	size_t size = log->len - log->wpos;

	va_start(args, fmt);
	cnt = vscnprintf(buf, size, fmt, args);
	va_end(args);

	log->wpos += cnt;
	return cnt;
}

/**
 * write_next_line_to_log: Writes a single "line" of data into the log buffer
 * @trans: Pointer to SPMI transaction data.
 * @offset: SPMI address offset to start reading from.
 * @pcnt: Pointer to 'cnt' variable.  Indicates the number of bytes to read.
 *
 * The 'offset' is a 20-bits SPMI address which includes a 4-bit slave id (SID),
 * an 8-bit peripheral id (PID), and an 8-bit peripheral register address.
 *
 * On a successful read, the pcnt is decremented by the number of data
 * bytes read across the SPMI bus.  When the cnt reaches 0, all requested
 * bytes have been read.
 */
static int
write_next_line_to_log(struct spmi_trans *trans, int offset, size_t *pcnt)
{
	int i, j;
	u8  data[ITEMS_PER_LINE];
	struct spmi_log_buffer *log = trans->log;

	int cnt = 0;
	int padding = offset % ITEMS_PER_LINE;
	int items_to_read = min(ARRAY_SIZE(data) - padding, *pcnt);
	int items_to_log = min(ITEMS_PER_LINE, padding + items_to_read);

	/* Buffer needs enough space for an entire line */
	if ((log->len - log->wpos) < MAX_LINE_LENGTH)
		goto done;

	/* Read the desired number of "items" */
	if (spmi_read_data(trans->sdev, data, offset, items_to_read))
		goto done;

	*pcnt -= items_to_read;

	/* Each line starts with the aligned offset (20-bit address) */
	cnt = print_to_log(log, "%5.5X ", offset & 0xffff0);
	if (cnt == 0)
		goto done;

	/* If the offset is unaligned, add padding to right justify items */
	for (i = 0; i < padding; ++i) {
		cnt = print_to_log(log, "-- ");
		if (cnt == 0)
			goto done;
	}

	/* Log the data items */
	for (j = 0; i < items_to_log; ++i, ++j) {
		cnt = print_to_log(log, "%2.2X ", data[j]);
		if (cnt == 0)
			goto done;
	}

	/* If the last character was a space, then replace it with a newline */
	if (log->wpos > 0 && log->data[log->wpos - 1] == ' ')
		log->data[log->wpos - 1] = '\n';

done:
	return cnt;
}

/**
 * write_raw_data_to_log: Writes a single "line" of data into the log buffer
 * @trans: Pointer to SPMI transaction data.
 * @offset: SPMI address offset to start reading from.
 * @pcnt: Pointer to 'cnt' variable.  Indicates the number of bytes to read.
 *
 * The 'offset' is a 20-bits SPMI address which includes a 4-bit slave id (SID),
 * an 8-bit peripheral id (PID), and an 8-bit peripheral register address.
 *
 * On a successful read, the pcnt is decremented by the number of data
 * bytes read across the SPMI bus.  When the cnt reaches 0, all requested
 * bytes have been read.
 */
static int
write_raw_data_to_log(struct spmi_trans *trans, int offset, size_t *pcnt)
{
	u8  data[16];
	struct spmi_log_buffer *log = trans->log;

	int i;
	int cnt = 0;
	int items_to_read = min(ARRAY_SIZE(data), *pcnt);

	/* Buffer needs enough space for an entire line */
	if ((log->len - log->wpos) < 80)
		goto done;

	/* Read the desired number of "items" */
	if (spmi_read_data(trans->sdev, data, offset, items_to_read))
		goto done;

	*pcnt -= items_to_read;

	/* Log the data items */
	for (i = 0; i < items_to_read; ++i) {
		cnt = print_to_log(log, "0x%2.2X ", data[i]);
		if (cnt == 0)
			goto done;
	}

	/* If the last character was a space, then replace it with a newline */
	if (log->wpos > 0 && log->data[log->wpos - 1] == ' ')
		log->data[log->wpos - 1] = '\n';

done:
	return cnt;
}

/**
 * get_log_data - reads data across the SPMI bus and saves to the log buffer
 * @trans: Pointer to SPMI transaction data.
 *
 * Returns the number of "items" read or SPMI error code for read failures.
 */
static int get_log_data(struct spmi_trans *trans)
{
	int cnt;
	int last_cnt;
	int items_read;
	int total_items_read = 0;
	u32 offset = trans->offset;
	size_t item_cnt = trans->cnt;
	struct spmi_log_buffer *log = trans->log;
	int (*write_to_log)(struct spmi_trans *, int, size_t *);

	if (item_cnt == 0)
		return 0;

	if (trans->raw_data)
		write_to_log = write_raw_data_to_log;
	else
		write_to_log = write_next_line_to_log;

	/* Reset the log buffer 'pointers' */
	log->wpos = log->rpos = 0;

	/* Keep reading data until the log is full */
	do {
		last_cnt = item_cnt;
		cnt = write_to_log(trans, offset, &item_cnt);
		items_read = last_cnt - item_cnt;
		offset += items_read;
		total_items_read += items_read;
	} while (cnt && item_cnt > 0);

	/* Adjust the transaction offset and count */
	trans->cnt = item_cnt;
	trans->offset += total_items_read;

	return total_items_read;
}

static ssize_t spmi_device_dfs_reg_write(struct file *file,
					 const char __user *buf,
					 size_t count, loff_t *ppos)
{
	int bytes_read;
	int data;
	int pos = 0;
	int cnt = 0;
	u8  *values;
	size_t ret = 0;

	struct spmi_trans *trans = file->private_data;
	u32 offset = trans->offset;

	/* Make a copy of the user data */
	char *kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = copy_from_user(kbuf, buf, count);
	if (ret == count) {
		pr_err("failed to copy data from user\n");
		ret = -EFAULT;
		goto free_buf;
	}

	count -= ret;
	*ppos += count;
	kbuf[count] = '\0';

	/* Override the text buffer with the raw data */
	values = kbuf;

	/* Parse the data in the buffer.  It should be a string of numbers */
	while (sscanf(kbuf + pos, "%i%n", &data, &bytes_read) == 1) {
		pos += bytes_read;
		values[cnt++] = data & 0xff;
	}

	if (!cnt)
		goto free_buf;

	/* Perform the SPMI write(s) */
	ret = spmi_write_data(trans->sdev, values, offset, cnt);

	if (ret) {
		pr_err("SPMI write failed, err = %zu\n", ret);
	} else {
		ret = count;
		trans->offset += cnt;
	}

free_buf:
	kfree(kbuf);
	return ret;
}

static ssize_t spmi_device_dfs_reg_read(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct spmi_trans *trans = file->private_data;
	struct spmi_log_buffer *log = trans->log;
	size_t ret;
	size_t len;

	/* Is the the log buffer empty */
	if (log->rpos >= log->wpos) {
		if (get_log_data(trans) <= 0)
			return 0;
	}

	len = min(count, (size_t) log->wpos - log->rpos);

	ret = copy_to_user(buf, &log->data[log->rpos], len);
	if (ret == len) {
		pr_err("error copy SPMI register values to user\n");
		return -EFAULT;
	}

	/* 'ret' is the number of bytes not copied */
	len -= ret;

	*ppos += len;
	log->rpos += len;
	return len;
}

static const struct file_operations spmi_dfs_reg_fops = {
	.open		= spmi_device_dfs_data_open,
	.release	= spmi_device_dfs_close,
	.read		= spmi_device_dfs_reg_read,
	.write		= spmi_device_dfs_reg_write,
};

static const struct file_operations spmi_dfs_raw_data_fops = {
	.open		= spmi_device_dfs_raw_data_open,
	.release	= spmi_device_dfs_close,
	.read		= spmi_device_dfs_reg_read,
	.write		= spmi_device_dfs_reg_write,
};

void spmi_dfs_add_controller(struct spmi_controller *ctrl)
{
	ctrl->dfs_dir = debugfs_create_dir(dev_name(&ctrl->dev),
					   spmi_debug_root);
	WARN_ON(!ctrl->dfs_dir);

	dev_dbg(&ctrl->dev, "adding debug entries for spmi controller\n");
}

void spmi_dfs_del_controller(struct spmi_controller *ctrl)
{
	debugfs_remove_recursive(ctrl->dfs_dir);
}

void spmi_dfs_add_device(struct spmi_device *sdev)
{
	struct dentry *file;

	dev_dbg(&sdev->dev, "adding debugfs entries for spmi device\n");

	sdev->dfs_dir = debugfs_create_dir(dev_name(&sdev->dev),
					   sdev->ctrl->dfs_dir);
	if (WARN_ON(!sdev->dfs_dir))
		return;

	sdev->dfs_cnt  = 1;

	file = debugfs_create_u32("count", DFS_MODE, sdev->dfs_dir,
				  &sdev->dfs_cnt);
	if (WARN_ON(!file))
		goto err_remove_fs;

	file = debugfs_create_x32("address", DFS_MODE, sdev->dfs_dir,
				  &sdev->dfs_addr);
	if (WARN_ON(!file))
		goto err_remove_fs;

	file = debugfs_create_file("data", DFS_MODE, sdev->dfs_dir, sdev,
				   &spmi_dfs_reg_fops);
	if (WARN_ON(!file))
		goto err_remove_fs;

	file = debugfs_create_file("data_raw", DFS_MODE, sdev->dfs_dir,
				   sdev, &spmi_dfs_raw_data_fops);
	if (WARN_ON(!file))
		goto err_remove_fs;

	return;

err_remove_fs:
	debugfs_remove_recursive(sdev->dfs_dir);
}

void spmi_dfs_del_device(struct spmi_device *sdev)
{
	dev_dbg(&sdev->dev, "Deleting device\n");
	debugfs_remove_recursive(sdev->dfs_dir);
}

void __exit spmi_dfs_exit(void)
{
	pr_debug("de-initializing spmi debugfs ...");
	debugfs_remove_recursive(spmi_debug_root);
}

void __init spmi_dfs_init(void)
{
	struct dentry *help;

	pr_debug("creating SPMI debugfs file-system\n");

	spmi_debug_root = debugfs_create_dir("spmi", NULL);

	help = debugfs_create_blob("help", S_IRUGO, spmi_debug_root,
				   &spmi_debug_help);

	WARN_ON(!spmi_debug_root || !help);
}

MODULE_LICENSE("GPL v2");
