// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef NVME_INT_BPF_HEADER
#define NVME_INT_BPF_HEADER

#ifdef CONFIG_NVME_BPF
#include <linux/filter.h>
#include <linux/nvme-bpf.h>

static inline bool nvme_bpf_enabled(struct nvme_ns_head *head)
{
	return !!(srcu_dereference(head->bpf_ops, &head->srcu));
}

void nvme_bpf_detach(struct nvme_ns_head *head);
struct nvme_ns *nvme_bpf_select_path(struct nvme_ns_head *head, sector_t sector);

int __init nvme_bpf_struct_ops_init(void);

#else

static inline bool nvme_bpf_enabled(struct nvme_ns_head *head)
{
	return false;
}

static inline void nvme_bpf_detach(struct nvme_ns_head *head) {}
static inline struct nvme_ns *nvme_bpf_select_path(struct nvme_ns_head *head, sector_t sector)
{
	return NULL;
}

#endif
#endif
