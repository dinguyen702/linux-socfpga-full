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

#ifndef _ALTERA_EPDE_H
#define _ALTERA_EPDE_H

/* From QSYS design */
#define PCI_VENDOR_ID_EPDE      0x1172
#define PCI_DEVICE_ID_EPDE      0xE001
#define PCI_SUBVEN_ID_EPDE      0x1172
#define PCI_SUBDEV_ID_EPDE      0x1484
#define EP_DIR_BAR_NR           0
#define  EP_OCRAM_BAR_AVOFF     0x02000000
#define  EP_OCRAM_SIZE          0x40000
#define EP_CSR_BAR_NR           2
#define  EP_HIP_CRA_AVOFF       0x00000000
#define  EP_HIP_CRA_SIZE        0x4000
#define  EP_DMA_CSR_AVOFF       0x00004000
#define  EP_DMA_CSR_SIZE        0x20
#define  EP_DMA_DES_AVOFF       0x00004020
#define  EP_DMA_DES_SIZE        0x10
#define  EP_PERFCOUNTER_AVOFF   0x00004040
#define  EP_PERFCOUNTER_SIZE    0x20
#define  EP_PERFCOUNTER_MFREQ   125
#define EP_DMA_IRQ_A2P          0x01

#endif

