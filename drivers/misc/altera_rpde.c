/*
 * Copyright Altera Corporation (C) 2013. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/time.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/platform_device.h>
#include <linux/of_irq.h>

#include "altera_rpde.h"
#include "altera_epde.h"

#define DRIVER_NAME             "altera_rpde_driver"
#define MAJOR_NR                240
#define DEVICE_NAME             "blkrpde"

struct block_device_t {
	spinlock_t     lock;
	void __iomem   *rpdata;
	unsigned long  rpdata_avoff;
	unsigned long  datlen;
	void __iomem   *dmacsr;
	void __iomem   *dmades;
	unsigned int   rphwirq;
	void __iomem   *epdata;
	unsigned long  epdata_avoff;
	char           *sys_buf;
	unsigned long  sys_buf_phys;
	void __iomem   *perfcounter;
	unsigned long  timediff;
	unsigned long  perfcountertick;
	unsigned int   dmaxfer_cmd;
	unsigned int   dma_transfer_completed;
	struct gendisk *gd;
};
static struct block_device_t block_device;

/* Support only one DES */
static void init_msgdma_xfer(void __iomem *dmades, unsigned long frphy,
			     unsigned long tophy, u32 size32)
{
	writel(frphy, dmades + MSGDMA_READ_ADDR);
	writel(tophy, dmades + MSGDMA_WRITE_ADDR);
	writel(size32, dmades + MSGDMA_DES_LEN);

	/* record start time */
	/* reset */
	writel(PERFCTR_GBL_CLK_CTR_LO_RST,
		block_device.perfcounter + PERFCTR_GBL_CLK_CTR_LO);
	/* start */
	writel(PERFCTR_GBL_CLK_CTR_HI_START,
		block_device.perfcounter + PERFCTR_GBL_CLK_CTR_HI);

	/* start transfer */
	writel(MSGDMA_DES_CTL_TX_CH   |
	       MSGDMA_DES_CTL_TC_IRQ  |
	       MSGDMA_DES_CTL_GO,
	      dmades + MSGDMA_DES_CTL);
}

/* Simple SGDMA csr with interrupt */
static void init_msgdma_csr(void __iomem *dmacsr)
{
	/* Stop and clear CSR */
	MSGDMA_STOP_CTL(dmacsr);

	/* Clear any SDGMA STS */
	MSGDMA_CLR_STS(dmacsr);

	/* Enable CSR */
	MSGDMA_ENA_CTL(dmacsr);
}

/* MSGDMA transfer function
 *   return timediff from performance counter
 */
static unsigned long msgdma_transfer(unsigned long frphy, unsigned long tophy,
				     u32 size32)
{
	unsigned long rt;

	/* Setup performance counter and barrier */
	block_device.perfcountertick = 0;
	block_device.dma_transfer_completed = 0;

	/* Setting up SGDMA CSR */
	init_msgdma_csr(block_device.dmacsr);

	/* Init SGDMA transfer */
	init_msgdma_xfer(block_device.dmades,
			 frphy, tophy, size32);

	/* wait DMA transfer complete */
	while (block_device.dma_transfer_completed == 0)
		mb();

	rt = (block_device.perfcountertick / RP_PERFCOUNTER_MFREQ);  /* usec */

	return rt;
}

static int block_ioctl(struct block_device *bdev, fmode_t mode,
		       unsigned int cmd, unsigned long arg)
{
	int rt;
	struct ioctl_t ioctl_data;
	unsigned long sys_buf_avoff;

	block_device.rpdata_avoff = RP_OCRAM_AVOFF;
	sys_buf_avoff = block_device.sys_buf_phys + RP_AS_DMA2F2H_AVOFF;

	switch (cmd) {
	case GET_IOCTL:
		return copy_to_user((void *)arg,
				    (void *)&block_device.datlen,
				    sizeof(long));
	case SET_IOCTL:
		return copy_from_user((void *)&block_device.dmaxfer_cmd,
					  (void *)arg,
				      sizeof(int));
	case PCI_RX_IOCTL:
		/* From EP On-Chip RAM to RP On-Chip RAM using SGDMA */
		memset(block_device.rpdata, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.epdata_avoff,
						      block_device.rpdata_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case PCI_TX_IOCTL:
		/* From RP On-Chip RAM to EP On-Chip RAM using SGDMA */
		memset(block_device.epdata, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.rpdata_avoff,
						      block_device.epdata_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case SYS_RX_IOCTL:
		/* From EP On-Chip RAM to RP System Memory using SGDMA */
		memset(block_device.sys_buf, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.epdata_avoff,
						      sys_buf_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case SYS_TX_IOCTL:
		/* From RP System Memory to EP On-Chip RAM using SGDMA */
		memset(block_device.epdata, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(sys_buf_avoff,
						      block_device.epdata_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	}

	return -ENOTTY;
}

static struct request_queue *block_queue;
static const struct block_device_operations block_fops = {
	.owner = THIS_MODULE,
	.ioctl = block_ioctl,
};

static void blk_request(struct request_queue *rq)
{
	int err;
	struct request *req;
	unsigned long offset, nbytes;

	req = blk_fetch_request(rq);
	while (req) {
		if (req->cmd_type != REQ_TYPE_FS)
			continue;

		offset = blk_rq_pos(req) * SECTOR_SIZE;
		nbytes = blk_rq_cur_sectors(req) * SECTOR_SIZE;

		err = -EIO;
		if ((offset + nbytes) <= block_device.datlen) {
			err = 0;
			switch (rq_data_dir(req)) {
			case READ:
				switch (block_device.dmaxfer_cmd) {
				case PCI_RX_IOCTL:
					/* Read from RP On-Chip RAM to Buffer */
					memcpy(req->buffer,
						block_device.rpdata + offset,
						nbytes);
					break;
				case SYS_RX_IOCTL:
					/* Read from System Buffer to Buffer */
					memcpy(req->buffer,
						block_device.sys_buf + offset,
						nbytes);
					break;
				case PCI_TX_IOCTL:
				case SYS_TX_IOCTL:
					/* Read from EP On-Chip RAM to Buffer */
					memcpy(req->buffer,
						block_device.epdata + offset,
						nbytes);
					break;
				}
				break;
			case WRITE:
				switch (block_device.dmaxfer_cmd) {
				case PCI_RX_IOCTL:
				case SYS_RX_IOCTL:
					/* Write from Buffer to EP OCM */
					memcpy(block_device.epdata + offset,
						req->buffer, nbytes);
					break;
				case PCI_TX_IOCTL:
					/* Write from Buffer to RP OCM */
					memcpy(block_device.rpdata + offset,
						req->buffer, nbytes);
					break;
				case SYS_TX_IOCTL:
					/* Write from Buffer to System Buffer */
					memcpy(block_device.sys_buf + offset,
						req->buffer, nbytes);
					break;
				}
				break;
			default:
				err = -EIO;
				pr_notice("Unknown request %u\n",
				       rq_data_dir(req));
				break;
			}
		}

		if (__blk_end_request_cur(req, err) == 0)
			req = blk_fetch_request(rq);
	}
}

static int block_device_init(struct pci_dev *pdev)
{
	int err;

	/* register as block device */
	err = register_blkdev(MAJOR_NR, DEVICE_NAME);
	if (err) {
		pr_err("block device fail to register\n");
		goto err_ret;
	}

	spin_lock_init(&block_device.lock);

	block_queue = blk_init_queue(blk_request, &block_device.lock);
	if (block_queue == NULL) {
		pr_warn("block_device: error in blk_init_queue\n");
		goto err_unregdev;
	}

	/* whole disk, no partition */
	block_device.gd = alloc_disk(1);
	if (!block_device.gd) {
		pr_warn("block_device: error in alloc_disk\n");
		goto err_deinit_queue;
	}

	block_device.gd->major = MAJOR_NR;
	block_device.gd->first_minor = 0;
	block_device.gd->fops = &block_fops;
	block_device.gd->private_data = &block_device;
	sprintf(block_device.gd->disk_name, "%s%d", DEVICE_NAME, 0);
	set_capacity(block_device.gd,
		    (block_device.datlen/SECTOR_SIZE));

	block_device.gd->queue = block_queue;

	add_disk(block_device.gd);

	return 0;
err_deinit_queue:
	blk_cleanup_queue(block_queue);
err_unregdev:
	unregister_blkdev(MAJOR_NR, DEVICE_NAME);
err_ret:
	return err;
}

static irqreturn_t driver_isr(int irq, void *arg)
{
	/* make last 4 bytes posted write complete */
	switch (block_device.dmaxfer_cmd) {
	case PCI_RX_IOCTL:
	case PCI_TX_IOCTL:
		while (memcmp((block_device.rpdata + block_device.datlen - 4),
			      (block_device.epdata + block_device.datlen - 4),
			      4))
			;
		break;
	case SYS_RX_IOCTL:
	case SYS_TX_IOCTL:
		while (memcmp((block_device.sys_buf + block_device.datlen - 4),
			      (block_device.epdata + block_device.datlen - 4),
			      4))
			;
		break;
	}

	/* record end time */
	/* stop */
	__raw_writel(PERFCTR_GBL_CLK_CTR_LO_STOP,
		block_device.perfcounter + PERFCTR_GBL_CLK_CTR_LO);

	/* Clear Interrupt and RUN bits */
	__raw_writel((__raw_readl(block_device.dmacsr + MSGDMA_CTL)
				  | MSGDMA_CTL_DIS_BITS)
				  & ~MSGDMA_CTL_IE_GLOBAL,
		     block_device.dmacsr + MSGDMA_CTL);

	if (__raw_readl(block_device.dmacsr + MSGDMA_STS) & MSGDMA_STS_IRQ)
		/* read tick */
		block_device.perfcountertick = readl(block_device.perfcounter +
						     PERFCTR_GBL_CLK_CTR_LO);
	else
		pr_err("msgdma IRQ not triggered\n");

	/* Clear any SDGMA STS */
	__raw_writel(MSGDMA_STS_CLR_BITS, block_device.dmacsr + MSGDMA_STS);

	/* completed */
	block_device.dma_transfer_completed = 1;

	return IRQ_HANDLED;
}

/*
 * Map (physical) PCI mem into (virtual) kernel space
 */
static void __iomem *remap_pci_mem(ulong base, ulong size)
{
	ulong page_base = ((ulong) base) & PAGE_MASK;
	ulong page_offs = ((ulong) base) - page_base;
	void __iomem *page_remapped = ioremap_nocache(page_base,
						      page_offs + size);

	return page_remapped ? (page_remapped + page_offs) : NULL;
}

static const struct of_device_id altrpcie_ids[] = {
	{ .compatible = "ALTR,msgdma-1.0", },
	{ .compatible = "ALTR,msgdma-dispatcher-1.0", },
	{},
};

static int __devinit altr_rpde_pci_probe(struct pci_dev *pdev,
				    const struct pci_device_id *pci_id)
{
	int err = -EIO;
	struct pci_dev *lpdev = NULL;
	struct device_node *node = NULL;

	/* Max block length */
	block_device.datlen = min3((unsigned long)RP_OCRAM_SIZE,
				   (unsigned long)EP_OCRAM_SIZE,
				   (unsigned long)SGDMA_MAX_SIZE);

	/*********** Is the right EP available? ***********/

	lpdev = pci_get_device(PCI_VENDOR_ID_EPDE, PCI_DEVICE_ID_EPDE, NULL);
	if (!lpdev) {
		pr_err("%s has no require EP detected\n", DRIVER_NAME);
		err = -ENODEV;
		return err;
	}
	if ((lpdev->subsystem_vendor != PCI_SUBVEN_ID_EPDE) ||
	    (lpdev->subsystem_device != PCI_SUBDEV_ID_EPDE)) {
		pr_err("%s has no require EP detected\n", DRIVER_NAME);
		err = -ENODEV;
		goto err_nodev;
	}
	block_device.epdata_avoff = EP_OCRAM_BAR_AVOFF;
	block_device.epdata =
		remap_pci_mem(pci_resource_start(lpdev, EP_DIR_BAR_NR)
			      + EP_OCRAM_BAR_AVOFF,
			      block_device.datlen);
	if (block_device.epdata == NULL) {
		pr_err("fail to ioremap epdata\n");
		goto err_nodev;
	}

	/*********** RP Setup ***********/

	/* Request RP On-Chip RAM region */
	if (!request_mem_region(RP_OCRAM_SBASE, RP_OCRAM_SIZE,
				DRIVER_NAME)) {
		pr_err("fail to request RP OCM region\n");
		goto err_unmapep;
	}
	/* IO Map RP On-Chip RAM region*/
	block_device.rpdata = ioremap_nocache(RP_OCRAM_SBASE,
					      block_device.datlen);
	if (block_device.rpdata == NULL) {
		pr_err("fail to ioremap rpdata\n");
		goto err_freeocr;
	}
	/* IO Map RP DMA CSR */
	block_device.dmacsr = ioremap_nocache(RP_DMA_CSR_SBASE,
					      RP_DMA_CSR_SIZE);
	if (block_device.dmacsr == NULL) {
		pr_err("fail to ioremap DMA CSR region\n");
		goto err_unmapocr;
	}
	/* IO Map RP DMA DES */
	block_device.dmades = ioremap_nocache(RP_DMA_DES_SBASE,
					      RP_DMA_DES_SIZE);
	if (block_device.dmades == NULL) {
		pr_err("fail to ioremap DMA DES region\n");
		goto err_unmapdmacsr;
	}
	/* IO Map RP Performance Counter */
	block_device.perfcounter = ioremap_nocache(RP_PERFCOUNTER_SBASE,
						   RP_PERFCOUNTER_SIZE);
	if (block_device.perfcounter == NULL) {
		pr_err("fail to ioremap performance counter region\n");
		goto err_unmapdmades;
	}

	/*********** SGDMA IRQ Setup ***********/
	/* verify if SGDMA status ok */
	writel(~0UL, block_device.dmacsr + MSGDMA_STS);
	if ((readl(block_device.dmacsr + MSGDMA_STS) & MSGDMA_STS_MASK) !=
	    MSGDMA_STS_AT_RESET) {
		pr_err("RP MSGDMA fail status test\n");
		goto err_unmapperfcounter;
	}

	/* SGDMA IRQ */
	node = of_find_matching_node(NULL, altrpcie_ids);
	if (node) {
		block_device.rphwirq = irq_of_parse_and_map(node, 0);
		if (request_irq(block_device.rphwirq, driver_isr,
				0, "RPDE", &block_device)) {
			pr_err("RPDE failed to register legacy IRQ\n");
			goto err_unmapperfcounter;
		} else {
			block_device.timediff = 0;
			set_irq_flags(block_device.rphwirq, IRQF_VALID);
		}
	} else {
		pr_notice("No SGDMA found in Device Tree\n");
		goto err_unmapperfcounter;
	}

	/*********** Block Setup ***********/

	/* Init block device API */
	err = block_device_init(pdev);
	if (err) {
		pr_err("fail to init block device\n");
		goto err_freeirq;
	}

	/* Allocate system memory for DMA trasfer */
	block_device.sys_buf = kmalloc(block_device.datlen,
				       GFP_DMA | GFP_ATOMIC);
	if (!block_device.sys_buf) {
		pr_notice("Fail to allocate system memory for DMA\n");
		goto err_unregblk;
	}
	block_device.sys_buf_phys = virt_to_phys(block_device.sys_buf);

	pci_dev_put(lpdev);
	return 0;
err_unregblk:
	unregister_blkdev(MAJOR_NR, DEVICE_NAME);
err_freeirq:
	free_irq(block_device.rphwirq, pdev);
err_unmapperfcounter:
	iounmap(block_device.perfcounter);
err_unmapdmades:
	iounmap(block_device.dmades);
err_unmapdmacsr:
	iounmap(block_device.dmacsr);
err_unmapocr:
	iounmap(block_device.rpdata);
err_freeocr:
	release_mem_region(RP_OCRAM_SBASE, RP_OCRAM_SIZE);
err_unmapep:
	pci_iounmap(pdev, block_device.epdata);
err_nodev:
	pci_dev_put(lpdev);
	return err;
}

static void __devexit altr_rpde_pci_remove(struct pci_dev *pdev)
{
	kfree(block_device.sys_buf);
	blk_cleanup_queue(block_queue);
	unregister_blkdev(MAJOR_NR, DEVICE_NAME);
	free_irq(pdev->irq, pdev);
	iounmap(block_device.dmacsr);
	iounmap(block_device.dmades);
	iounmap(block_device.rpdata);
	release_mem_region(RP_OCRAM_SBASE, RP_OCRAM_SIZE);
	return;
}

static DEFINE_PCI_DEVICE_TABLE(altr_rpde_pci_tbl) = {
	{ PCI_VENDOR_ID_RPDE, PCI_DEVICE_ID_RPDE,
	  PCI_SUBVEN_ID_RPDE, PCI_SUBDEV_ID_RPDE,
	  0, 0, 0 },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, altr_rpde_pci_tbl);

static struct pci_driver lpde_driver = {
	.name = DRIVER_NAME,
	.probe = altr_rpde_pci_probe,
	.remove = altr_rpde_pci_remove,
	.id_table = altr_rpde_pci_tbl,
};

static int __init altr_rpde_pci_init(void)
{
	if (pci_register_driver(&lpde_driver) == 0)
		return 0;
	return -EIO;
}

static void __exit altr_rpde_pci_exit(void)
{
	pci_unregister_driver(&lpde_driver);
}

module_init(altr_rpde_pci_init);
module_exit(altr_rpde_pci_exit);

MODULE_DESCRIPTION("Altera RootPort Design Example with SGDMA Block Transfer");
MODULE_AUTHOR("Simon Yap");
MODULE_LICENSE("GPL v2");
