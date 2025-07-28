/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Hannes Reinecke, SUSE Software Solutions
 */

#ifndef _NVME_BPF_H
#define _NVME_BPF_H

struct nvme_ns_head;
struct nvme_ns;

/**
 * struct nvme_bpf_iter - Iterator for select_path BPF function
 * @head: namespace head to iterate over
 * @curr: current namespace path
 * @prev: previous namespace path
 */
struct nvme_bpf_iter {
	struct nvme_ns_head *head;
	struct nvme_ns *curr;
	struct nvme_ns *prev;
};

/**
 * struct nvme_bpf_ops - A BPF struct_ops of callbacks allowing to implement
 * 			an nvme bpf path selector
 * @uuid: ops uuid
 * @subsys_id: instance number of the subsystem to attach to
 * @nsid: namespace ID within @subsys_id to attach to
 * @select_path: callback for selecting the path for @sector
 */
struct nvme_bpf_ops {
	/* UUID to distinguish different instances */
	uuid_t			uuid;

	/* Subsystem NQN */
	char			subsysnqn[256];

	/* Namespace ID number or -1 if valid for all namespace */
	int		nsid;

	/* Return the controller ID of the selected path or -1 if not found */
	int		(*select_path)(struct nvme_bpf_iter *, sector_t);

	/* private: don't show in doc, must be the last field */
	struct nvme_ns_head *head;
};

int nvme_bpf_first_path(struct nvme_bpf_iter *iter);
int nvme_bpf_next_path(struct nvme_bpf_iter *iter);
u32 nvme_bpf_count_paths(struct nvme_bpf_iter *iter);

#endif

