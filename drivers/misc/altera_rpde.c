/*
 *  Copyright (C) 2013 Altera Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
	void __iomem   *rpdmacsr;
	void __iomem   *rpdmades;
	unsigned int   rphwirq;
	void __iomem   *epdata;
	unsigned long  epdata_avoff;
	void __iomem   *perfcounter;
	struct gendisk *gd;
};
static struct block_device_t block_device;

/* time measurement */
static unsigned long timediff;
static unsigned long perfcountertick;
static int rpdma_transfer_completed;

/* Support only one DES */
static void init_msgdma_xfer(void __iomem *dmades, unsigned long frphy,
			     unsigned long tophy, u32 size32)
{
	writel(frphy, dmades + MSGDMA_READ_ADDR);
	writel(tophy, dmades + MSGDMA_WRITE_ADDR);
	writel(size32, dmades + MSGDMA_DES_LEN);

	/* record start time */
	/* reset */
	writel(1, block_device.perfcounter);
	/* start */
	writel(0, block_device.perfcounter + 4);

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

static int block_ioctl(struct block_device *bdev, fmode_t mode,
		       unsigned int cmd, unsigned long arg)
{
	int rt;
	unsigned long count;

	switch(cmd) {
	case GET_IOCTL:
		return copy_to_user((void *)arg,
				    (void *)&block_device.datlen,
				    sizeof(long));
	case READ_IOCTL:
		/* wait DMA transfer complete */
		count = ~0UL;
		while (rpdma_transfer_completed == 0) {
			if (count-- == 0) {
				printk(KERN_NOTICE
					"RP interrupt fail\n");
				return -ENOTTY;
			}
			barrier();
		}
		rpdma_transfer_completed = 0;
		timediff = perfcountertick / RP_PERFCOUNTER_MFREQ;  /* usec */
		rt = copy_to_user((void *)arg, (void *)&timediff, sizeof(long));
		return rt;
	case WRITE_IOCTL:
		/* set timediff */
		rt = copy_from_user((void *)&perfcountertick, (void *)arg,
				    sizeof(long));
		if (rt)
			return rt;
		/* From RP On-Chip RAM to EP On-Chip RAM using SGDMA */
		rpdma_transfer_completed = 0;
		/* Setting up SGDMA CSR */
		init_msgdma_csr(block_device.rpdmacsr);
		/* Init SGDMA transfer */
		init_msgdma_xfer(block_device.rpdmades,
			       block_device.rpdata_avoff,
			       block_device.epdata_avoff,
			       block_device.datlen);
		return rt;
	}

	return -ENOTTY;
}

static struct request_queue *block_queue = NULL;
static struct block_device_operations block_fops = {
    .owner	= THIS_MODULE,
    .ioctl	= block_ioctl,
};

static void blk_request(struct request_queue *rq)
{
	int err;
	struct request *req;
	unsigned long offset, nbytes;

	req = blk_fetch_request(rq);
	while (req) {
		if (req->cmd_type != REQ_TYPE_FS) {
			continue;
		}

		offset = blk_rq_pos(req) * SECTOR_SIZE;
		nbytes = blk_rq_cur_sectors(req) * SECTOR_SIZE;

		err = -EIO;
		if ((offset + nbytes) <= block_device.datlen) {
			err = 0;
			switch(rq_data_dir(req)) {
			case READ:
				/* Read from RP On-Chip RAM to Buffer */
				memcpy(req->buffer,
				       block_device.rpdata + offset,
				       nbytes);
				break;
			case WRITE:
				/* Write from Buffer to RP On-Chip RAM */
				memcpy(block_device.rpdata + offset,
				       req->buffer, nbytes);
				break;
			default:
				err = -EIO;
				printk(KERN_NOTICE "Unknown request %u\n",
				       rq_data_dir(req));
				break;
			}
		}

		if (__blk_end_request_cur(req, err) == 0) {
			req = blk_fetch_request(rq);
		}
	}
}

static int block_device_init(struct pci_dev *pdev)
{
	int err;

	/* register as block device */
	err = register_blkdev(MAJOR_NR, DEVICE_NAME);
	if (err) {
		goto err_ret;
	}

	spin_lock_init(&block_device.lock);

	block_queue = blk_init_queue(blk_request,&block_device.lock);
	if (block_queue == NULL) {
		printk(KERN_WARNING
		       "block_device: error in blk_init_queue\n");
		goto err_unregdev;
	}

	block_device.gd = alloc_disk(1);
	if (!block_device.gd) {
		printk(KERN_WARNING
		       "block_device: error in alloc_disk\n");
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
	/* make posted write complete */
	while (memcmp((block_device.rpdata + block_device.datlen - 4),
	              (block_device.epdata + block_device.datlen - 4),
	              4));

	/* record end time */
	/* stop */
	__raw_writel(0, block_device.perfcounter);

	/* Clear Interrupt and RUN bits */
	__raw_writel((__raw_readl(block_device.rpdmacsr + MSGDMA_CTL)
		                  | MSGDMA_CTL_DIS_BITS)
		                  & ~MSGDMA_CTL_IE_GLOBAL,
		     block_device.rpdmacsr + MSGDMA_CTL);

	if (__raw_readl(block_device.rpdmacsr + MSGDMA_STS) & MSGDMA_STS_IRQ)
		/* read tick */
		perfcountertick = readl(block_device.perfcounter);
	else
		pr_err("msgdma transfer error\n");

	/* Clear any SDGMA STS */
	__raw_writel(MSGDMA_STS_CLR_BITS, block_device.rpdmacsr + MSGDMA_STS);

	/* completed */
	rpdma_transfer_completed = 1;

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
	if (block_device.epdata == NULL)
		goto err_nodev;

	/*********** RP Setup ***********/

	/* Request RP On-Chip RAM region */
	if (!request_mem_region(RP_OCRAM_SBASE, RP_OCRAM_SIZE,
				DRIVER_NAME))
		goto err_unmapep;
	/* IO Map RP On-Chip RAM region*/
	block_device.rpdata_avoff = RP_OCRAM_AVOFF;
	if ((block_device.rpdata = ioremap_nocache(RP_OCRAM_SBASE,
					  block_device.datlen)) == NULL)
		goto err_freeocr;
	/* IO Map RP DMA CSR */
	if ((block_device.rpdmacsr = ioremap_nocache(RP_DMA_CSR_SBASE,
					    RP_DMA_CSR_SIZE)) == NULL)
		goto err_unmapocr;
	/* IO Map RP DMA DES */
	if ((block_device.rpdmades = ioremap_nocache(RP_DMA_DES_SBASE,
					    RP_DMA_DES_SIZE)) == NULL)
		goto err_unmapdmacsr;
	/* IO Map RP Performance Counter */
	if ((block_device.perfcounter = ioremap_nocache(RP_PERFCOUNTER_SBASE,
					    RP_PERFCOUNTER_SIZE)) == NULL)
		goto err_unmapdmades;

	/*********** SGDMA IRQ Setup ***********/

	/* SGDMA IRQ */
	node = of_find_matching_node(NULL, altrpcie_ids);
	if (node) {
		block_device.rphwirq = irq_of_parse_and_map(node, 0);
		if (request_irq(block_device.rphwirq, driver_isr,
				0, "RPDE", &block_device)) {
			pr_err("RPDE failed to register legacy IRQ\n");
			goto err_unmapperfcounter;
		} else {
			timediff = 0;
			wmb();
			rpdma_transfer_completed = 1;
			set_irq_flags(block_device.rphwirq, IRQF_VALID);
		}
	} else {
		printk(KERN_NOTICE "No SGDMA found in Device Tree\n");
		goto err_unmapperfcounter;
	}

	/*********** Block Setup ***********/

	/* Init block device API */
	err = block_device_init(pdev);
	if (err)
		goto err_freeirq;

	pci_dev_put(lpdev);
	return 0;
err_freeirq:
	free_irq(block_device.rphwirq, pdev);
err_unmapperfcounter:
	iounmap(block_device.perfcounter);
err_unmapdmades:
	iounmap(block_device.rpdmades);
err_unmapdmacsr:
	iounmap(block_device.rpdmacsr);
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
	blk_cleanup_queue(block_queue);
	unregister_blkdev(MAJOR_NR, DEVICE_NAME);
	free_irq(pdev->irq, pdev);
	iounmap(block_device.rpdmacsr);
	iounmap(block_device.rpdmades);
	iounmap(block_device.rpdata);
	release_mem_region(RP_OCRAM_SBASE, RP_OCRAM_SIZE);
	return;
}

static struct pci_device_id altr_rpde_pci_tbl[] = {
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
