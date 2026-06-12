// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mount.c - operations for initializing and mounting configfs.
 *
 * Based on sysfs:
 * 	sysfs is Copyright (C) 2001, 2002, 2003 Patrick Mochel
 *
 * configfs Copyright (C) 2005 Oracle.  All rights reserved.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/configfs.h>
#include "configfs_internal.h"

/* Random magic number */
#define CONFIGFS_MAGIC 0x62656570

struct kmem_cache *configfs_dir_cachep;
static DEFINE_XARRAY(configfs_super_xa);
static struct configfs_super_info *configfs_root = NULL;

static void configfs_free_inode(struct inode *inode)
{
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	free_inode_nonrcu(inode);
}

static const struct super_operations configfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= inode_just_drop,
	.free_inode	= configfs_free_inode,
};

int configfs_is_root(struct config_item *item)
{
	struct configfs_dirent *sd =
		item->ci_dentry->d_fsdata;
	return sd->s_type == CONFIGFS_ROOT;
}

static void configfs_fill_super_info(struct configfs_super_info *info)
{
	INIT_LIST_HEAD(&info->root.s_sibling);
	INIT_LIST_HEAD(&info->root.s_children);
	info->root.s_type = CONFIGFS_ROOT;
	info->root.s_element = &info->group.cg_item;
	strcpy(info->group.cg_item.ci_namebuf, "root");
	info->group.cg_item.ci_name = info->group.cg_item.ci_namebuf;
	config_group_init(&info->group);
	INIT_LIST_HEAD(&info->subsys_list);
	mutex_init(&info->subsys_mutex);
	refcount_set(&info->ref, 1);
	info->mnt_count = 0;
}

struct configfs_super_info *configfs_get_super_info(u64 ns_id)
{
	struct configfs_super_info *info;
	int err;

	info = xa_load(&configfs_super_xa, ns_id);
	if (info) {
		if (!refcount_inc_not_zero((&info->ref))) {
			pr_warn("%s: ns %llu already freed\n",
				__func__, ns_id);
			return ERR_PTR(-EBUSY);
		}
		pr_info("%s: use ns %llu\n",
			__func__, ns_id);
		return info;
	}
	info = kzalloc_obj(*info);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->ns_id = ns_id;
	configfs_fill_super_info(info);
	err = xa_insert(&configfs_super_xa, ns_id,
			info, GFP_KERNEL);
	if (err < 0) {
		kfree(info);
		return ERR_PTR(err);
	}
	pr_info("%s: alloc ns %llu\n", __func__, info->ns_id);
	return info;
}

void configfs_put_super_info(struct configfs_super_info *info)
{
	if (refcount_dec_and_test(&info->ref)) {
		pr_info("%s: ns %llu free fs info\n",
			__func__, info->ns_id);
		xa_erase(&configfs_super_xa, info->ns_id);
		WARN_ON(!list_empty(&info->subsys_list));
		kfree(info);
	}
}

static int configfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct configfs_super_info *info = configfs_get_super_info(0);
	struct inode *inode;
	struct dentry *root;

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = CONFIGFS_MAGIC;
	sb->s_op = &configfs_ops;
	sb->s_time_gran = 1;

	inode = configfs_new_inode(S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
				   &info->root, sb);
	if (inode) {
		inode->i_op = &configfs_root_inode_operations;
		inode->i_fop = &configfs_dir_operations;
		/* directory inodes start off with i_nlink == 2 (for "." entry) */
		inc_nlink(inode);
	} else {
		pr_debug("could not get root inode\n");
		configfs_put_super_info(info);
		return -ENOMEM;
	}

	root = d_make_root(inode);
	if (!root) {
		pr_debug("%s: could not get root dentry!\n",__func__);
		configfs_put_super_info(info);
		return -ENOMEM;
	}
	config_group_init(&info->group);
	info->group.cg_item.ci_dentry = root;
	root->d_fsdata = &info->root;
	sb->s_root = root;
	sb->s_fs_info = info;
	set_default_d_op(sb, &configfs_dentry_ops); /* the rest get that */
	sb->s_d_flags |= DCACHE_DONTCACHE;
	return 0;
}

static int configfs_get_tree(struct fs_context *fc)
{
	return get_tree_single(fc, configfs_fill_super);
}

static const struct fs_context_operations configfs_context_ops = {
	.get_tree	= configfs_get_tree,
};

static int configfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &configfs_context_ops;
	return 0;
}

static void configfs_kill_sb(struct super_block *sb)
{
	struct configfs_super_info *info = sb->s_fs_info;

	kill_anon_super(sb);
	configfs_put_super_info(info);
	sb->s_fs_info = NULL;
}

static struct file_system_type configfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "configfs",
	.init_fs_context = configfs_init_fs_context,
	.kill_sb	= configfs_kill_sb,
};
MODULE_ALIAS_FS("configfs");

struct dentry *configfs_pin_fs(struct super_block *sb)
{
	struct configfs_super_info *info = configfs_root;
	int err;

	if (sb) {
		struct configfs_super_info *root = info;
		struct dentry *dentry = sb->s_root;
		struct vfsmount *mnt;

		info = sb->s_fs_info;
		if (!info->mnt) {
			mnt = mnt_clone_direct(root->mnt, dentry);
			if (IS_ERR(mnt))
				return ERR_CAST(mnt);
			info->mnt = mnt;
		}
		dget(dentry);
		mntget(info->mnt);
		info->mnt_count++;
		return info->mnt->mnt_root;
	}

	err = simple_pin_fs(&configfs_fs_type, &info->mnt, &info->mnt_count);
	if (err)
		return ERR_PTR(err);

	return info->mnt->mnt_root;
}

void configfs_release_fs(struct super_block *sb)
{
	struct configfs_super_info *info = configfs_root;

	if (sb) {
		info = sb->s_fs_info;
		dput(sb->s_root);
	}

	pr_debug("release ns %llu\n", info->ns_id);
	simple_release_fs(&info->mnt, &info->mnt_count);
}

static int __init configfs_init(void)
{
	int err = -ENOMEM;

	configfs_dir_cachep = kmem_cache_create("configfs_dir_cache",
						sizeof(struct configfs_dirent),
						0, 0, NULL);
	if (!configfs_dir_cachep)
		goto out;

	err = sysfs_create_mount_point(kernel_kobj, "config");
	if (err)
		goto out2;

	err = register_filesystem(&configfs_fs_type);
	if (err)
		goto out3;

	configfs_root = configfs_get_super_info(0);
	if (IS_ERR(configfs_root)) {
		err = PTR_ERR(configfs_root);
		goto out4;
	}

	return 0;
out4:
	pr_err("Unable to get initlal root context\n");
	unregister_filesystem(&configfs_fs_type);
out3:
	pr_err("Unable to register filesystem!\n");
	sysfs_remove_mount_point(kernel_kobj, "config");
out2:
	kmem_cache_destroy(configfs_dir_cachep);
	configfs_dir_cachep = NULL;
out:
	return err;
}

static void __exit configfs_exit(void)
{
	configfs_put_super_info(configfs_root);
	unregister_filesystem(&configfs_fs_type);
	sysfs_remove_mount_point(kernel_kobj, "config");
	kmem_cache_destroy(configfs_dir_cachep);
	configfs_dir_cachep = NULL;
}

MODULE_AUTHOR("Oracle");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.2");
MODULE_DESCRIPTION("Simple RAM filesystem for user driven kernel subsystem configuration.");

core_initcall(configfs_init);
module_exit(configfs_exit);
