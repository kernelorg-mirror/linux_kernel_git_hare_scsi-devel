// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Hannes Reinecke, SUSE */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include "nvme.h"
#include "bpf.h"

static struct btf *nvme_bpf_ops_btf;
static char nvme_bpf_ops_name[] = "nvme_bpf_ops";

static int nvme_bpf_ops_init(struct btf *btf)
{
	nvme_bpf_ops_btf = btf;
	return 0;
}

static bool nvme_bpf_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

BTF_ID_LIST(nvme_bpf_ops_args_ids)
BTF_ID(struct, nvme_ns_head)
BTF_ID(struct, nvme_ns)
BTF_ID(struct, nvme_bpf_iter)

static int nvme_bpf_ops_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	const struct btf_type *nhit, *nit, *niter, *t;

	nhit = btf_type_by_id(reg->btf, nvme_bpf_ops_args_ids[0]);
	nit = btf_type_by_id(reg->btf, nvme_bpf_ops_args_ids[1]);
	niter = btf_type_by_id(reg->btf, nvme_bpf_ops_args_ids[2]);

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t != nhit && t != niter) {
		bpf_log(log, "write access to struct %d is not supported\n", reg->btf_id);
		return -EACCES;
	}
	if (t == niter) {
		/* Allow writes to the 'head' element */
		if (off >= offsetof(struct nvme_bpf_iter, head) &&
		    off + size < offsetofend(struct nvme_bpf_iter, head))
			return NOT_INIT;
	} else {
		/* Allow writes to the 'bpf_ops' element */
		if (off >= offsetof(struct nvme_ns_head, bpf_ops) &&
		    off + size < offsetofend(struct nvme_ns_head, bpf_ops)) {
			return NOT_INIT;
		}
	}
	bpf_log(log, "write access for struct %s at off %d with size %d\n",
		nvme_bpf_ops_name, off, size);
	return -EACCES;
}

static const struct bpf_verifier_ops nvme_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = nvme_bpf_ops_is_valid_access,
	.btf_struct_access = nvme_bpf_ops_btf_struct_access,
};

static int nvme_bpf_ops_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct nvme_bpf_ops, select_path):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int nvme_bpf_ops_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	const struct nvme_bpf_ops *uops;
	struct nvme_bpf_ops *kops;
	u32 moff;

	uops = (const struct nvme_bpf_ops *)udata;
	kops = (struct nvme_bpf_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct nvme_bpf_ops, subsysnqn):
		memcpy(kops->subsysnqn, uops->subsysnqn,
		       sizeof(kops->subsysnqn));
		return 1;
	case offsetof(struct nvme_bpf_ops, nsid):
		kops->nsid = uops->nsid;
		return 1;
	case offsetof(struct nvme_bpf_ops, uuid):
		if (uuid_is_null(&uops->uuid))
			uuid_gen(&kops->uuid);
		else
			uuid_copy(&kops->uuid, &uops->uuid);
		return 1;
	}
	return 0;
}

static int nvme_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct nvme_bpf_ops *ops = kdata;
	struct nvme_ns_head *head;
	struct nvme_subsystem *subsys = NULL;

	pr_debug("%s: register %s nsid %d\n",
		 __func__, ops->subsysnqn, ops->nsid);

	subsys = nvme_find_get_subsystem(ops->subsysnqn);
	if (!subsys)
		return -EINVAL;

	mutex_lock(&subsys->lock);
	list_for_each_entry(head, &subsys->nsheads, entry) {
		if (head->ns_id != ops->nsid)
			continue;
		if (head->bpf_ops) {
			pr_debug("%s: instance %d already attached\n",
				 __func__, head->instance);
			continue;
		}
		if (nvme_tryget_ns_head(head)) {
			mutex_lock(&head->lock);
			ops->head = head;
			head->bpf_ops = ops;
			mutex_unlock(&head->lock);
			pr_debug("%s: attached to %d\n",
				 __func__, head->instance);
			synchronize_srcu(&head->srcu);
			break;
		}
	}
	mutex_unlock(&subsys->lock);
	nvme_put_subsystem(subsys);

	return 0;
}

static void nvme_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct nvme_bpf_ops *ops = kdata;
	struct nvme_ns_head *head;

	if (ops->head) {
		head = ops->head;
		pr_debug("%s: unregistered from %d\n",
			 __func__, head->instance);
		mutex_lock(&head->lock);
		head->bpf_ops = NULL;
		ops->head = NULL;
		mutex_unlock(&head->lock);
		nvme_put_ns_head(head);
		synchronize_srcu(&head->srcu);
	}
}

void nvme_bpf_detach(struct nvme_ns_head *head)
{
	struct nvme_bpf_ops *ops =
		srcu_dereference(head->bpf_ops, &head->srcu);

	if (ops) {
		mutex_lock(&head->lock);
		rcu_assign_pointer(head->bpf_ops, NULL);
		list_del_init(&head->bpf_list);
		mutex_unlock(&head->lock);
		nvme_put_ns_head(head);
	}
}

static int __nvme_bpf_select_path(struct nvme_bpf_iter *iter,
				  sector_t sector)
{
	return -ENXIO;
}

static struct nvme_bpf_ops __bpf_nvme_bpf_ops = {
	.uuid = {},
	.subsysnqn = "",
	.nsid = UINT_MAX,
	.select_path = __nvme_bpf_select_path,
	.head = NULL,
};

struct nvme_ns *nvme_bpf_select_path(struct nvme_ns_head *head,
				     sector_t sector)
{
	struct nvme_ns *ns = NULL;
	struct nvme_bpf_ops *ops =
		srcu_dereference(head->bpf_ops, &head->srcu);
	struct nvme_bpf_iter iter = {
		.head = head,
	};
	s32 cntlid;

	if (ops) {
		cntlid = ops->select_path(&iter, sector);
		if (cntlid < 0)
			return ERR_PTR(cntlid);
		if (iter.curr) {
			ns = iter.curr;
			if (ns->ctrl->cntlid == cntlid)
				return ns;
		}
	}
	return ERR_PTR(-ENXIO);
}

__bpf_kfunc_start_defs();

/**
 * nvme_bpf_first_path - select the first path from a nvme bpf path iterator
 * @iter: nvme_bpf path iterator
 *
 * Initializes @iter with the first nvme namespace path (if present) and
 * returns the controller id of the first nvme namespace path or
 * -ENXIO if no namespace path is present.
 */
__bpf_kfunc int nvme_bpf_first_path(struct nvme_bpf_iter *iter)
{
	struct nvme_ns *ns;

	if (!iter || !iter->head)
		return -EINVAL;
	if (!nvme_bpf_enabled(iter->head))
		return -EPERM;

	ns = list_first_or_null_rcu(&iter->head->list, struct nvme_ns, siblings);
	iter->curr = ns;
	iter->prev = NULL;
	return ns ? ns->ctrl->cntlid : -ENXIO;
}
EXPORT_SYMBOL_GPL(nvme_bpf_first_path);

/**
 * nvme_bpf_next_path - select the next path from a nvme bpf path iterator
 * @iter: nvme_bpf path iterator
 *
 * Moves @iter to the next namespace path in @curr, storing the previous namespace
 * path in @prev. Returns the controller id of the current namespace path, -ENXIO
 * if no current path is set, or -EAGAIN if no next namespace is found.
 */
__bpf_kfunc int nvme_bpf_next_path(struct nvme_bpf_iter *iter)
{
	struct nvme_ns *ns, *old;

	if (!iter || !iter->head)
		return -EINVAL;
	if (!nvme_bpf_enabled(iter->head))
		return -EPERM;
	if (!iter->curr)
		return -ENXIO;
	old = iter->curr;
	ns = list_next_or_null_rcu(&iter->head->list, &old->siblings, struct nvme_ns,
				   siblings);
	iter->prev = old;
	iter->curr = ns;
	return ns ? ns->ctrl->cntlid : -EAGAIN;
}
EXPORT_SYMBOL_GPL(nvme_bpf_next_path);

/**
 * nvme_bpf_count_paths - count the number of paths in a nvme bpf path iterator
 * @iter: nvme_bpf namespace path iterator
 *
 * Returns number of paths in @iter
 */
__bpf_kfunc u32 nvme_bpf_count_paths(struct nvme_bpf_iter *iter)
{
	struct nvme_ns *ns;
	u32 num = 0;

	if (!iter || !iter->head)
		return 0;
	if (!nvme_bpf_enabled(iter->head))
		return num;

	ns = list_first_or_null_rcu(&iter->head->list, struct nvme_ns, siblings);
	while (ns) {
		num++;
		ns = list_next_or_null_rcu(&iter->head->list, &ns->siblings, struct nvme_ns,
					   siblings);
	}
	return num;
}
EXPORT_SYMBOL_GPL(nvme_bpf_count_paths);

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(nvme_bpf_kfunc_set_ids)
BTF_ID_FLAGS(func, nvme_bpf_first_path, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, nvme_bpf_next_path, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, nvme_bpf_count_paths, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(nvme_bpf_kfunc_set_ids)

static const struct btf_kfunc_id_set nvme_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &nvme_bpf_kfunc_set_ids,
};

static struct bpf_struct_ops bpf_nvme_bpf_ops = {
	.verifier_ops = &nvme_bpf_verifier_ops,
	.init = nvme_bpf_ops_init,
	.check_member = nvme_bpf_ops_check_member,
	.init_member = nvme_bpf_ops_init_member,
	.reg = nvme_bpf_reg,
	.unreg = nvme_bpf_unreg,
	.name = nvme_bpf_ops_name,
	.cfi_stubs = &__bpf_nvme_bpf_ops,
	.owner = THIS_MODULE,
};

int __init nvme_bpf_struct_ops_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&nvme_bpf_kfunc_set);
	if (ret) {
		pr_err("Failed to register nvme_bpf_kfunc_set, error %d\n", ret);
		return ret;
	}
	ret = register_bpf_struct_ops(&bpf_nvme_bpf_ops, nvme_bpf_ops);
	if (ret)
		pr_err("Failed to register nvme_bpf_ops, error %d\n", ret);
	else
		pr_info("nvme_bpf_ops registered\n");
	return ret;
}
