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

#define DRIVER_NAME             "altera_epde_driver"
#define MAJOR_NR                241
#define DEVICE_NAME             "blkepde"

struct block_device_t {
	spinlock_t     lock;
	void __iomem   *rpdata;
	unsigned long  rpdata_avoff;
	unsigned long  datlen;
	void __iomem   *dmacsr;
	void __iomem   *dmades;
	void __iomem   *ephipcsr;
	void __iomem   *epdata;
	unsigned long  epdata_avoff;
	char           *sys_buf;
	unsigned long  sys_buf_phys;
	unsigned long  translation_mask;
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

	rt = (block_device.perfcountertick / EP_PERFCOUNTER_MFREQ);  /* usec */

	return rt;
}

static int block_ioctl(struct block_device *bdev, fmode_t mode,
		       unsigned int cmd, unsigned long arg)
{
	int rt;
	struct ioctl_t ioctl_data;
	unsigned long sys_buf_avoff;

	block_device.rpdata_avoff = RP_AS_RPM2OCR_AVOFF &
				    ~block_device.translation_mask;
	sys_buf_avoff = (block_device.sys_buf_phys + RP_AS_RPM2F2H_AVOFF) &
			~block_device.translation_mask;
	/* PCIE TXS range is small, use Address Translation Table to rebase */
	switch (cmd) {
	case PCI_TX_IOCTL:
	case PCI_RX_IOCTL:
		writel(RP_AS_RPM2OCR_AVOFF & block_device.translation_mask,
			block_device.ephipcsr + A2P_ADDR_MAP_LO0);
		break;
	case SYS_TX_IOCTL:
	case SYS_RX_IOCTL:
		writel(block_device.sys_buf_phys &
			block_device.translation_mask,
			block_device.ephipcsr + A2P_ADDR_MAP_LO0);
		break;
	}
	writel(0x0, block_device.ephipcsr + A2P_ADDR_MAP_HI0);

	switch (cmd) {
	case GET_IOCTL:
		return copy_to_user((void *)arg,
				    (void *)&block_device.datlen,
				    sizeof(long));
	case SET_IOCTL:
		return copy_from_user((void *)&block_device.dmaxfer_cmd,
					  (void *)arg,
				      sizeof(int));
	case PCI_TX_IOCTL:
		/* From EP On-Chip RAM to RP On-Chip RAM using SGDMA */
		memset(block_device.rpdata, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.epdata_avoff,
						      block_device.rpdata_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case PCI_RX_IOCTL:
		/* From RP On-Chip RAM to EP On-Chip RAM using SGDMA */
		memset(block_device.epdata, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.rpdata_avoff,
						      block_device.epdata_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case SYS_TX_IOCTL:
		/* From EP On-Chip RAM to RP System Memory using SGDMA */
		memset(block_device.sys_buf, 0, block_device.datlen);
		ioctl_data.datlen = block_device.datlen;
		ioctl_data.timediff = msgdma_transfer(block_device.epdata_avoff,
						      sys_buf_avoff,
						      block_device.datlen);
		rt = copy_to_user((void *)arg, (void *)&ioctl_data,
				  sizeof(struct ioctl_t));
		return rt;
	case SYS_RX_IOCTL:
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
				case PCI_TX_IOCTL:
					/* Read from RP On-Chip RAM to Buffer */
					memcpy(req->buffer,
						block_device.rpdata + offset,
						nbytes);
					break;
				case SYS_TX_IOCTL:
					/* Read from System Buffer to Buffer */
					memcpy(req->buffer,
						block_device.sys_buf + offset,
						nbytes);
					break;
				case PCI_RX_IOCTL:
				case SYS_RX_IOCTL:
					/* Read from EP On-Chip RAM to Buffer */
					memcpy(req->buffer,
						block_device.epdata + offset,
						nbytes);
					break;
				}
				break;
			case WRITE:
				switch (block_device.dmaxfer_cmd) {
				case PCI_TX_IOCTL:
				case SYS_TX_IOCTL:
					/* Write from Buffer to EP OCM */
					memcpy(block_device.epdata + offset,
						req->buffer, nbytes);
					break;
				case PCI_RX_IOCTL:
					/* Write from Buffer to RP OCM */
					memcpy(block_device.rpdata + offset,
						req->buffer, nbytes);
					break;
				case SYS_RX_IOCTL:
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

	/* Clear HIP INT status */
	__raw_writel(EP_DMA_IRQ_A2P, block_device.ephipcsr + A2P_INT_STS_REG);

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

static int __devinit altr_epde_pci_probe(struct pci_dev *pdev,
				    const struct pci_device_id *pci_id)
{
	int err = -EIO;
	struct pci_dev *lpdev = NULL;

	/* Max block length */
	block_device.datlen = min3((unsigned long)RP_OCRAM_SIZE,
				   (unsigned long)EP_OCRAM_SIZE,
				   (unsigned long)SGDMA_MAX_SIZE);

	/*********** Is the right RP available? ***********/

	lpdev = pci_get_device(PCI_VENDOR_ID_RPDE, PCI_DEVICE_ID_RPDE, NULL);
	if (!lpdev) {
		pr_err("%s has no require RP detected\n", DRIVER_NAME);
		err = -ENODEV;
		return err;
	}
	if ((lpdev->subsystem_vendor != PCI_SUBVEN_ID_RPDE) ||
	    (lpdev->subsystem_device != PCI_SUBDEV_ID_RPDE)) {
		pr_err("%s has no require RP detected\n", DRIVER_NAME);
		err = -ENODEV;
		goto err_nodev;
	}
	/* IO Map RP On-Chip RAM region*/
	block_device.rpdata = ioremap_nocache(RP_OCRAM_SBASE,
					      block_device.datlen);
	if (block_device.rpdata == NULL) {
		pr_err("fail to ioremap rpdata\n");
		goto err_nodev;
	}

	/*********** EP Setup ***********/

	/* Enable Device */
	err = pci_enable_device(pdev);
	if (err) {
		pr_err("fail to enable pcie device\n");
		goto err_unmaprpdata;
	}
	pci_set_master(pdev);
	/* Request EP data resources */
	err = pci_request_region(pdev, EP_DIR_BAR_NR, DRIVER_NAME);
	if (err) {
		pr_err("fail to request DIR BAR region\n");
		goto err_disdev;
	}
	/* Map EP On-Chip RAM */
	block_device.epdata_avoff = EP_OCRAM_BAR_AVOFF;
	block_device.epdata =
		remap_pci_mem(pci_resource_start(pdev, EP_DIR_BAR_NR)
			      + EP_OCRAM_BAR_AVOFF,
			      block_device.datlen);
	if (block_device.epdata == NULL) {
		pr_err("fail to ioremap epdata\n");
		goto err_freedir;
	}
	/* Request EP CSR resources */
	err = pci_request_region(pdev, EP_CSR_BAR_NR, DRIVER_NAME);
	if (err) {
		pr_err("fail to request CSR BAR region\n");
		goto err_unmapocr;
	}
	/* Configure Avalon-MM-to-PCI Express Address Translation Table */
	block_device.ephipcsr =
		remap_pci_mem(pci_resource_start(pdev, EP_CSR_BAR_NR)
			      + EP_HIP_CRA_AVOFF,
			      EP_HIP_CRA_SIZE);
	if (block_device.ephipcsr == NULL) {
		pr_err("fail to request EP CSR region\n");
		goto err_freecsr;
	}
	/* get address translation table mask */
	writel(~0UL, block_device.ephipcsr + A2P_ADDR_MAP_LO0);
	block_device.translation_mask = readl(
		block_device.ephipcsr + A2P_ADDR_MAP_LO0) & A2P_ADDR_MAP_MASK;
	/* IO Map EP DMA CSR */
	block_device.dmacsr =
		remap_pci_mem(pci_resource_start(pdev, EP_CSR_BAR_NR)
			      + EP_DMA_CSR_AVOFF,
			      EP_DMA_CSR_SIZE);
	if (block_device.dmacsr == NULL) {
		pr_err("fail to request MSGDMA CSR region\n");
		goto err_unmaphipcsr;
	}
	/* IO Map EP DMA DES */
	block_device.dmades =
		remap_pci_mem(pci_resource_start(pdev, EP_CSR_BAR_NR)
			      + EP_DMA_DES_AVOFF,
			      EP_DMA_DES_SIZE);
	if (block_device.dmades == NULL) {
		pr_err("fail to request DMA DES region\n");
		goto err_unmapdmacsr;
	}
	/* IO Map EP Performance Counter */
	block_device.perfcounter =
		remap_pci_mem(pci_resource_start(pdev, EP_CSR_BAR_NR)
			      + EP_PERFCOUNTER_AVOFF,
			      EP_PERFCOUNTER_SIZE);
	if (block_device.perfcounter == NULL) {
		pr_err("fail to request performance counter region\n");
		goto err_unmapdmades;
	}

	/*********** SGDMA IRQ Setup ***********/
	/* verify if SGDMA status ok */
	writel(~0UL, block_device.dmacsr + MSGDMA_STS);
	if ((readl(block_device.dmacsr + MSGDMA_STS) & MSGDMA_STS_MASK) !=
	    MSGDMA_STS_AT_RESET) {
		pr_err("EP MSGDMA fail status test\n");
		goto err_unmapperfcounter;
	}

	/* EP IRQ */
	if (request_irq(pdev->irq, driver_isr, IRQF_SHARED,
			"EPDE", &block_device)) {
		pr_err("EPDE failed to register legacy IRQ\n");
		goto err_unmapperfcounter;
	} else {
		block_device.timediff = 0;
		block_device.dma_transfer_completed = 1;
		/* enable IRQ */
		writel(EP_DMA_IRQ_A2P,
			block_device.ephipcsr + A2P_INT_ENA_REG);
		set_irq_flags(pdev->irq, IRQF_VALID);
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
	free_irq(pdev->irq, pdev);
err_unmapperfcounter:
	pci_iounmap(pdev, block_device.perfcounter);
err_unmapdmades:
	pci_iounmap(pdev, block_device.dmades);
err_unmapdmacsr:
	pci_iounmap(pdev, block_device.dmacsr);
err_unmaphipcsr:
	pci_iounmap(pdev, block_device.ephipcsr);
err_freecsr:
	pci_release_region(pdev, EP_CSR_BAR_NR);
err_unmapocr:
	pci_iounmap(pdev, block_device.epdata);
err_freedir:
	pci_release_region(pdev, EP_DIR_BAR_NR);
err_disdev:
	pci_disable_device(pdev);
err_unmaprpdata:
	iounmap(block_device.rpdata);
err_nodev:
	pci_dev_put(lpdev);
	return err;
}

static void __devexit altr_epde_pci_remove(struct pci_dev *pdev)
{
	kfree(block_device.sys_buf);
	blk_cleanup_queue(block_queue);
	unregister_blkdev(MAJOR_NR, DEVICE_NAME);
	free_irq(pdev->irq, pdev);
	pci_iounmap(pdev, block_device.dmacsr);
	pci_iounmap(pdev, block_device.dmades);
	pci_release_region(pdev, EP_CSR_BAR_NR);
	pci_iounmap(pdev, block_device.epdata);
	pci_release_region(pdev, EP_DIR_BAR_NR);
	pci_disable_device(pdev);
	iounmap(block_device.rpdata);
	return;
}

static DEFINE_PCI_DEVICE_TABLE(altr_epde_pci_tbl) = {
	{ PCI_VENDOR_ID_EPDE, PCI_DEVICE_ID_EPDE,
	  PCI_SUBVEN_ID_EPDE, PCI_SUBDEV_ID_EPDE,
	  0, 0, 0 },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, altr_epde_pci_tbl);

static struct pci_driver lpde_driver = {
	.name = DRIVER_NAME,
	.probe = altr_epde_pci_probe,
	.remove = altr_epde_pci_remove,
	.id_table = altr_epde_pci_tbl,
};

static int __init altr_epde_pci_init(void)
{
	if (pci_register_driver(&lpde_driver) == 0)
		return 0;
	return -EIO;
}

static void __exit altr_epde_pci_exit(void)
{
	pci_unregister_driver(&lpde_driver);
}

module_init(altr_epde_pci_init);
module_exit(altr_epde_pci_exit);

MODULE_DESCRIPTION("Altera EndPoint Design Example with SGDMA Block Transfer");
MODULE_AUTHOR("Simon Yap");
MODULE_LICENSE("GPL v2");
