/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Hannes Reinecke, SUSE Software Solutions
 */

#ifndef _NVME_KEYRING_H
#define _NVME_KEYRING_H

#include <linux/key.h>

struct key *nvme_tls_psk_lookup(key_ref_t keyring,
				const char *hostnqn, const char *subnqn,
				int hmac, bool generated);

key_serial_t nvme_keyring_id(void);

int nvme_keyring_init(void);
void nvme_keyring_exit(void);

#endif
