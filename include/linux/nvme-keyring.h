/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Hannes Reinecke, SUSE Software Solutions
 */

#ifndef _NVME_KEYRING_H
#define _NVME_KEYRING_H

int nvme_keyring_init(void);
void nvme_keyring_exit(void);

#endif
