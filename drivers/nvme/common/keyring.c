// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Hannes Reinecke, SUSE Linux
 */

#include <linux/module.h>
#include <linux/nvme.h>
#include <linux/seq_file.h>
#include <linux/key-type.h>
#include <keys/user-type.h>

static struct key *nvme_keyring;

int nvme_keyring_init(void)
{
	int err;

	nvme_keyring = keyring_alloc(".nvme",
				     GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				     current_cred(),
				     (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				     (KEY_USR_ALL & ~KEY_USR_SETATTR),
				     KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(nvme_keyring))
		return PTR_ERR(nvme_keyring);

	return 0;
}
EXPORT_SYMBOL_GPL(nvme_keyring_init);

void nvme_keyring_exit(void)
{
	key_revoke(nvme_keyring);
	key_put(nvme_keyring);
}
EXPORT_SYMBOL_GPL(nvme_keyring_exit);
