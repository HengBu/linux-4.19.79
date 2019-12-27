/*
 * Copyright (C) 2016 Parav Pandit <pandit.parav@gmail.com>
 *
 * This file is subject to the terms and conditions of version 2 of the GNU
 * General Public License. See the file COPYING in the main directory of the
 * Linux distribution for more details.
 */

#ifndef _CGROUP_NVM_H
#define _CGROUP_NVM_H

#include <linux/cgroup.h>

enum nvmcg_resource_type {
	NVMCG_RESOURCE_SPACE,
	NVMCG_RESOURCE_BANDWIDTH,
	NVMCG_RESOURCE_MAX,
};

#ifdef CONFIG_CGROUP_NVM

struct nvm_cgroup {
	struct cgroup_subsys_state	css;

	/*
	 * head to keep track of all resource pools
	 * that belongs to this cgroup.
	 */
	struct list_head		rpools;
};

struct nvmcg_device {
	struct list_head	dev_node;
	struct list_head	rpools;
	u32			size;
	char			*name;
};

/*
 * APIs for nvm/IB stack to publish when a device wants to
 * participate in resource accounting
 */
int nvmcg_register_device(struct nvmcg_device *device);
void nvmcg_unregister_device(struct nvmcg_device *device);

/* APIs for nvm/IB stack to charge/uncharge pool specific resources */
int nvmcg_try_charge_space(struct nvm_cgroup **nvmcg,
		      struct nvmcg_device *device,
		      u32 zoneid,
		      u32 pages);
void nvmcg_uncharge_space(struct nvm_cgroup *cg,
		     struct nvmcg_device *device,
		     u32 zoneid,
		     u32 pages);


#endif	/* CONFIG_CGROUP_NVM */
#endif	/* _CGROUP_NVM_H */
