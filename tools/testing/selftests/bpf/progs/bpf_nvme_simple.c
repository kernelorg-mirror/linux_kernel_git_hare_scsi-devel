// SPDX-License-Identifier: GPL-2.0

/*
 * simple nvme ebpf path selector
 *
 * Simulates a RAID layout with chunk size 2M
 */

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

static sector_t simple_offset = 0;
static sector_t simple_blocksize = 1048576;

SEC("struct_ops")
int BPF_PROG(simple_select, struct nvme_bpf_iter *iter, sector_t sector)
{
	sector_t offset = simple_offset;
	sector_t block_size = simple_blocksize;
	u32 num_blks, num_paths, num_iter, i;
	int cntlid;

	if (sector > offset)
		sector -= offset;
	cntlid = nvme_bpf_first_path(iter);
	if (cntlid < 0)
		return cntlid;
	if (!block_size || sector < block_size)
		return cntlid;

	num_blks = (sector / block_size);
	num_paths = nvme_bpf_count_paths(iter);
	num_iter = num_blks % num_paths;
	bpf_for (i, 1, num_iter) {
		cntlid = nvme_bpf_next_path(iter);
		if (cntlid < 0)
			break;
	}
	return cntlid;
}

SEC(".struct_ops")
struct nvme_bpf_ops bpf_nvme_simple = {
	.uuid = { 0x86, 0xee, 0x41, 0xd5, 0x25, 0x6b, 0x45, 0xd0, 0xa4, 0x81, 0x5e, 0x35, 0xf6, 0x02, 0xf5, 0x11 },
	.subsysnqn = "blktests-subsystem-1",
	.nsid = 1,
	.select_path = (void *)simple_select,
};
