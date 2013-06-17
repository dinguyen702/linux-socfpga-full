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

#ifndef _ALTERA_RPDE_H
#define _ALTERA_RPDE_H

/* From QSYS design */
#define PCI_VENDOR_ID_RPDE      0x1172
#define PCI_DEVICE_ID_RPDE      0xE000
#define PCI_SUBVEN_ID_RPDE      0x0000  /* missing */
#define PCI_SUBDEV_ID_RPDE      0x0000  /* missing */
#define H2F_BASE                0xC0000000
#define H2F_LW_BASE             0xFF200000
#define RP_DMA_CSR_AVOFF        0x00044000
#define RP_DMA_CSR_SBASE        (H2F_LW_BASE + RP_DMA_CSR_AVOFF)
#define RP_DMA_CSR_SIZE         0x20
#define RP_DMA_DES_AVOFF        0x00044020
#define RP_DMA_DES_SBASE        (H2F_LW_BASE + RP_DMA_DES_AVOFF)
#define RP_DMA_DES_SIZE         0x10
#define RP_PERFCOUNTER_AVOFF    0x000100E0
#define RP_PERFCOUNTER_SBASE    (H2F_LW_BASE + RP_PERFCOUNTER_AVOFF)
#define RP_PERFCOUNTER_SIZE     0x20
#define RP_PERFCOUNTER_MFREQ    50
#define RP_OCRAM_AVOFF          0x20000000
#define RP_OCRAM_SBASE          (H2F_BASE + RP_OCRAM_AVOFF)
#define RP_OCRAM_SIZE           0x40000
#define RP_AS_RPM2F2H_BASE      0x00000000
#define RP_AS_RPM2F2H_AVOFF     (RP_AS_RPM2F2H_BASE + 0) /* IP offset */
#define RP_AS_RPM2OCR_BASE      0x80000000
#define RP_AS_RPM2OCR_AVOFF     (RP_AS_RPM2OCR_BASE + 0) /* IP offset */
#define RP_AS_DMA2F2H_BASE      0x80000000
#define RP_AS_DMA2F2H_AVOFF     (RP_AS_DMA2F2H_BASE + 0) /* IP offset */

/* HIP registers offset */
#define A2P_INT_STS_REG         0x0040
#define A2P_INT_ENA_REG         0x0050
#define A2P_ADDR_MAP_LO0        0x1000
#define A2P_ADDR_MAP_HI0        0x1004
#define A2P_ADDR_MAP_MASK       0xFFFFFFFC

/* SGDMA CSR Registers */
#define MSGDMA_STS              0x00
#define  MSGDMA_STS_BUSY        0x00000001
#define  MSGDMA_STS_DES_E       0x00000002
#define  MSGDMA_STS_DES_F       0x00000004
#define  MSGDMA_STS_RES_E       0x00000008
#define  MSGDMA_STS_RES_F       0x00000010
#define  MSGDMA_STS_MASK        0x0000001F
#define    MSGDMA_STS_AT_RESET  0x00000002
#define  MSGDMA_STS_STOP        0x00000020
#define  MSGDMA_STS_RESET       0x00000040
#define  MSGDMA_STS_STOP_ERR    0x00000080
#define  MSGDMA_STS_STOP_TER    0x00000100
#define  MSGDMA_STS_IRQ         0x00000200
#define MSGDMA_CTL              0x04
#define  MSGDMA_CTL_STOP        0x00000001
#define  MSGDMA_CTL_RESET       0x00000002
#define  MSGDMA_CTL_STOP_ERR    0x00000004
#define  MSGDMA_CTL_STOP_TER    0x00000008
#define  MSGDMA_CTL_IE_GLOBAL   0x00000010
#define  MSGDMA_CTL_STOP_DES    0x00000020

/* SGDMA Descriptor */
#define MSGDMA_READ_ADDR        0x00
#define MSGDMA_WRITE_ADDR       0x04
#define MSGDMA_DES_LEN          0x08
#define MSGDMA_DES_CTL          0x0C
#define  MSGDMA_DES_CTL_TX_CH   0x00000000
#define  MSGDMA_DES_CTL_GEN_SOP 0x00000100
#define  MSGDMA_DES_CTL_GEN_EOP 0x00000200
#define  MSGDMA_DES_CTL_END_EOP 0x00001000
#define  MSGDMA_DES_CTL_END_LEN 0x00002000
#define  MSGDMA_DES_CTL_TC_IRQ  0x00004000
#define  MSGDMA_DES_CTL_ET_IRQ  0x00008000
#define  MSGDMA_DES_CTL_TE_IRQ  0x00FF0000
#define  MSGDMA_DES_CTL_GO      0x80000000
#define SGDMA_MAX_SIZE          0xFFFFFFFF

/* MSGDMA macro */
#define MSGDMA_CTL_DIS_BITS  (MSGDMA_CTL_STOP        |  \
			      MSGDMA_CTL_STOP_DES)
#define MSGDMA_STOP_CTL(dmacsr)  \
	writel((readl(dmacsr + MSGDMA_CTL)  \
		       | MSGDMA_CTL_DIS_BITS)           \
		       & ~MSGDMA_CTL_IE_GLOBAL,         \
		     dmacsr + MSGDMA_CTL);
#define MSGDMA_ENA_CTL(dmacsr)  \
	writel((readl(dmacsr + MSGDMA_CTL)  \
		       | MSGDMA_CTL_IE_GLOBAL)          \
		       & ~MSGDMA_CTL_DIS_BITS,          \
		     dmacsr + MSGDMA_CTL);
#define MSGDMA_STS_CLR_BITS  (MSGDMA_STS_BUSY      |  \
			      MSGDMA_STS_DES_E     |  \
			      MSGDMA_STS_DES_F     |  \
			      MSGDMA_STS_RES_E     |  \
			      MSGDMA_STS_RES_F     |  \
			      MSGDMA_STS_STOP      |  \
			      MSGDMA_STS_RESET     |  \
			      MSGDMA_STS_STOP_ERR  |  \
			      MSGDMA_STS_STOP_TER  |  \
			      MSGDMA_STS_IRQ)
#define MSGDMA_CLR_STS(dmacsr)  \
	writel(MSGDMA_STS_CLR_BITS,  \
		     dmacsr + MSGDMA_STS);

/* Performance Counter */
#define PERFCTR_GBL_CLK_CTR_LO          0x00
#define   PERFCTR_GBL_CLK_CTR_LO_STOP   0x00000000
#define   PERFCTR_GBL_CLK_CTR_LO_RST    0x00000001
#define PERFCTR_GBL_CLK_CTR_HI          0x04
#define   PERFCTR_GBL_CLK_CTR_HI_START  0x00000000

/* Block Device */
struct ioctl_t {
	unsigned long  datlen;
	unsigned long  timediff;
};

#define IOCTL_TYPE 'Z'
#define GET_IOCTL _IOR(IOCTL_TYPE, 1, long)
#define SET_IOCTL _IOW(IOCTL_TYPE, 2, int)
#define PCI_RX_IOCTL _IOR(IOCTL_TYPE, 3, struct ioctl_t)
#define PCI_TX_IOCTL _IOR(IOCTL_TYPE, 4, struct ioctl_t)
#define SYS_RX_IOCTL _IOR(IOCTL_TYPE, 5, struct ioctl_t)
#define SYS_TX_IOCTL _IOR(IOCTL_TYPE, 6, struct ioctl_t)

#endif

