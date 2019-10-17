/*
 * nvm resource limiting controller for cgroups.
 *
 * Used to allow a cgroup hierarchy to stop processes from consuming
 * additional nvm resources after a certain limit is reached.
 *
 * Copyright (C) 2016 Parav Pandit <pandit.parav@gmail.com>
 *
 * This file is subject to the terms and conditions of version 2 of the GNU
 * General Public License. See the file COPYING in the main directory of the
 * Linux distribution for more details.
 */

#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/cgroup.h>
#include <linux/parser.h>
#include <linux/cgroup_nvm.h>

#define NVMCG_MAX_STR "max"

/*
 * Protects list of resource pools maintained on per cgroup basis
 * and nvm device list.
 */
static DEFINE_MUTEX(nvmcg_mutex);
static LIST_HEAD(nvmcg_devices);

enum nvmcg_file_type {
	NVMCG_RESOURCE_TYPE_MAX,
	NVMCG_RESOURCE_TYPE_STAT,
};

/*
 * resource table definition as to be seen by the user.
 * Need to add entries to it when more resources are
 * added/defined at IB verb/core layer.
 */
static char const *nvmcg_resource_names[] = {
	[NVMCG_RESOURCE_SPACE]	= "space",
	[NVMCG_RESOURCE_BANDWIDTH]	= "bandwidth",
};

struct nvmcg_zone_list {
	u32 zoneid;
	struct list_head resoure_node;
};

/* resource tracker for each resource of nvm cgroup */
struct nvmcg_resource {
	int max;
	int usage;
	struct list_head zoneids;
};

/*
 * resource pool object which represents per cgroup, per device
 * resources. There are multiple instances of this object per cgroup,
 * therefore it cannot be embedded within nvm_cgroup structure. It
 * is maintained as list.
 */
struct nvmcg_resource_pool {
	struct nvmcg_device	*device;
	struct nvmcg_resource	resources[NVMCG_RESOURCE_MAX];

	struct list_head	cg_node;
	struct list_head	dev_node;

	/* count active user tasks of this pool */
	u64			usage_sum;
	/* total number counts which are set to max */
	int			num_max_cnt;
};

static struct nvm_cgroup *css_nvmcg(struct cgroup_subsys_state *css)
{
	return container_of(css, struct nvm_cgroup, css);
}

static struct nvm_cgroup *parent_nvmcg(struct nvm_cgroup *cg)
{
	return css_nvmcg(cg->css.parent);
}

static inline struct nvm_cgroup *get_current_nvmcg(void)
{
	return css_nvmcg(task_get_css(current, nvm_cgrp_id));
}

static void set_resource_limit(struct nvmcg_resource_pool *rpool,
			       int index, int new_max)
{
	if (new_max == U32_MAX) {
		if (rpool->resources[index].max != U32_MAX)
			rpool->num_max_cnt++;
	} else {
		if (rpool->resources[index].max == U32_MAX)
			rpool->num_max_cnt--;
	}
	rpool->resources[index].max = new_max;
}

static void set_all_resource_max_limit(struct nvmcg_resource_pool *rpool)
{
	int i;

	for (i = 0; i < NVMCG_RESOURCE_MAX; i++) {
		set_resource_limit(rpool, i, U32_MAX);
	}
}

static void free_cg_rpool_locked(struct nvmcg_resource_pool *rpool)
{
	lockdep_assert_held(&nvmcg_mutex);

	list_del(&rpool->cg_node);
	list_del(&rpool->dev_node);
	kfree(rpool);
}

static struct nvmcg_resource_pool *
find_cg_rpool_locked(struct nvm_cgroup *cg,
		     struct nvmcg_device *device)

{
	struct nvmcg_resource_pool *pool;

	lockdep_assert_held(&nvmcg_mutex);

	list_for_each_entry(pool, &cg->rpools, cg_node)
		if (pool->device == device)
			return pool;

	return NULL;
}

static struct nvmcg_resource_pool *
get_cg_rpool_locked(struct nvm_cgroup *cg, struct nvmcg_device *device)
{
	struct nvmcg_resource_pool *rpool;

	rpool = find_cg_rpool_locked(cg, device);
	if (rpool)
		return rpool;

	rpool = kzalloc(sizeof(*rpool), GFP_KERNEL);
	if (!rpool)
		return ERR_PTR(-ENOMEM);

	rpool->device = device;
	set_all_resource_max_limit(rpool);
	INIT_LIST_HEAD(& (rpool->resources[0].zoneids));

	INIT_LIST_HEAD(&rpool->cg_node);
	INIT_LIST_HEAD(&rpool->dev_node);
	list_add_tail(&rpool->cg_node, &cg->rpools);
	list_add_tail(&rpool->dev_node, &device->rpools);
	return rpool;
}

/**
 * uncharge_cg_locked - uncharge resource for nvm cgroup
 * @cg: pointer to cg to uncharge and all parents in hierarchy
 * @device: pointer to nvmcg device
 * @index: index of the resource to uncharge in cg (resource pool)
 *
 * It also frees the resource pool which was created as part of
 * charging operation when there are no resources attached to
 * resource pool.
 */
static void
uncharge_cg_locked(struct nvm_cgroup *cg,
		   struct nvmcg_device *device,
		   u32 zoneid,
		   u32 pages)
{
	struct nvmcg_resource_pool *rpool;
	struct nvmcg_zone_list *zone, *tmp;

	rpool = find_cg_rpool_locked(cg, device);

	/*
	 * rpool cannot be null at this stage. Let kernel operate in case
	 * if there a bug in IB stack or nvm controller, instead of crashing
	 * the system.
	 */
	if (unlikely(!rpool)) {
		pr_warn("Invalid device %p or nvm cgroup %p\n", cg, device);
		return;
	}

	rpool->resources[0].usage -= pages;

	if (zoneid != 0) {
		list_for_each_entry_safe(zone, tmp, &(rpool->resources[0].zoneids),resoure_node)
			if (zone->zoneid == zoneid) {
				list_del(&zone->resoure_node);
				kfree(zone);
				break;
			}
	}

	/*
	 * A negative count (or overflow) is invalid,
	 * it indicates a bug in the nvm controller.
	 */
	WARN_ON_ONCE(rpool->resources[0].usage < 0);
	rpool->usage_sum -= pages;
	if (rpool->usage_sum == 0 &&
	    rpool->num_max_cnt == NVMCG_RESOURCE_MAX) {
		/*
		 * No user of the rpool and all entries are set to max, so
		 * safe to delete this rpool.
		 */
		free_cg_rpool_locked(rpool);
	}
}

/**
 * nvmcg_uncharge_hierarchy - hierarchically uncharge nvm resource count
 * @device: pointer to nvmcg device
 * @stop_cg: while traversing hirerchy, when meet with stop_cg cgroup
 *           stop uncharging
 * @index: index of the resource to uncharge in cg in given resource pool
 */
static void nvmcg_uncharge_hierarchy(struct nvm_cgroup *cg,
				     struct nvmcg_device *device,
				     struct nvm_cgroup *stop_cg,
				     u32 zoneid, u32 pages)
{
	struct nvm_cgroup *p;

	mutex_lock(&nvmcg_mutex);

	for (p = cg; p != stop_cg; p = parent_nvmcg(p))
		uncharge_cg_locked(p, device, zoneid, pages);

	mutex_unlock(&nvmcg_mutex);

	css_put(&cg->css);
}

/**
 * nvmcg_uncharge - hierarchically uncharge nvm resource count
 * @device: pointer to nvmcg device
 * @index: index of the resource to uncharge in cgroup in given resource pool
 */
void nvmcg_uncharge_space(struct nvm_cgroup *cg,
		     struct nvmcg_device *device,
		     u32 zoneid,
		     u32 pages)
{
	nvmcg_uncharge_hierarchy(cg, device, NULL, zoneid, pages);
}
EXPORT_SYMBOL(nvmcg_uncharge_space);

/**
 * nvmcg_try_charge - hierarchically try to charge the nvm resource
 * @nvmcg: pointer to nvm cgroup which will own this resource
 * @device: pointer to nvmcg device
 * @index: index of the resource to charge in cgroup (resource pool)
 *
 * This function follows charging resource in hierarchical way.
 * It will fail if the charge would cause the new value to exceed the
 * hierarchical limit.
 * Returns 0 if the charge succeded, otherwise -EAGAIN, -ENOMEM or -EINVAL.
 * Returns pointer to nvmcg for this resource when charging is successful.
 *
 * Charger needs to account resources on two criteria.
 * (a) per cgroup & (b) per device resource usage.
 * Per cgroup resource usage ensures that tasks of cgroup doesn't cross
 * the configured limits. Per device provides granular configuration
 * in multi device usage. It allocates resource pool in the hierarchy
 * for each parent it come across for first resource. Later on resource
 * pool will be available. Therefore it will be much faster thereon
 * to charge/uncharge.
 */
int nvmcg_try_charge_space(struct nvm_cgroup **nvmcg,
		      struct nvmcg_device *device,
		      u32 zoneid,
		      u32 pages)
{
	struct nvm_cgroup *cg, *p;
	struct nvmcg_resource_pool *rpool;
	struct nvmcg_zone_list *zone;
	s64 new;
	int ret = 0;

	/*
	 * hold on to css, as cgroup can be removed but resource
	 * accounting happens on css.
	 */
	cg = get_current_nvmcg();

	mutex_lock(&nvmcg_mutex);
	for (p = cg; p; p = parent_nvmcg(p)) {
		rpool = get_cg_rpool_locked(p, device);
		if (IS_ERR(rpool)) {
			ret = PTR_ERR(rpool);
			goto err;
		} else {
			if (zoneid != 0) {
				list_for_each_entry(zone, &(rpool->resources[0].zoneids),resoure_node)
					if (zone->zoneid == zoneid) {
						return 0;
					}
			}

			new = rpool->resources[0].usage + pages;
			if (new > rpool->resources[0].max) {
				ret = -EAGAIN;
				goto err;
			} else {
				rpool->resources[0].usage = new;
				rpool->usage_sum += pages;
				if (zoneid != 0) {
					zone = kmalloc(sizeof(struct nvmcg_zone_list), GFP_KERNEL);
					zone->zoneid = zoneid;
					INIT_LIST_HEAD(&zone->resoure_node);
					list_add_tail(&zone->resoure_node, &rpool->resources[0].zoneids);
				}
			}
		}
	}
	mutex_unlock(&nvmcg_mutex);

	*nvmcg = cg;
	return 0;

err:
	mutex_unlock(&nvmcg_mutex);
	nvmcg_uncharge_hierarchy(cg, device, p, zoneid, pages);
	return ret;
}
EXPORT_SYMBOL(nvmcg_try_charge_space);

/**
 * nvmcg_register_device - register nvmcg device to nvm controller.
 * @device: pointer to nvmcg device whose resources need to be accounted.
 *
 * If IB stack wish a device to participate in nvm cgroup resource
 * tracking, it must invoke this API to register with nvm cgroup before
 * any user space application can start using the nvm resources.
 * Returns 0 on success or EINVAL when table length given is beyond
 * supported size.
 */
int nvmcg_register_device(struct nvmcg_device *device)
{
	INIT_LIST_HEAD(&device->dev_node);
	INIT_LIST_HEAD(&device->rpools);

	mutex_lock(&nvmcg_mutex);
	list_add_tail(&device->dev_node, &nvmcg_devices);
	mutex_unlock(&nvmcg_mutex);
	return 0;
}
EXPORT_SYMBOL(nvmcg_register_device);

/**
 * nvmcg_unregister_device - unregister nvmcg device from nvm controller.
 * @device: pointer to nvmcg device which was previously registered with nvm
 *          controller using nvmcg_register_device().
 *
 * IB stack must invoke this after all the resources of the IB device
 * are destroyed and after ensuring that no more resources will be created
 * when this API is invoked.
 */
void nvmcg_unregister_device(struct nvmcg_device *device)
{
	struct nvmcg_resource_pool *rpool, *tmp;

	/*
	 * Synchronize with any active resource settings,
	 * usage query happening via configfs.
	 */
	mutex_lock(&nvmcg_mutex);
	list_del_init(&device->dev_node);

	/*
	 * Now that this device is off the cgroup list, its safe to free
	 * all the rpool resources.
	 */
	list_for_each_entry_safe(rpool, tmp, &device->rpools, dev_node)
		free_cg_rpool_locked(rpool);

	mutex_unlock(&nvmcg_mutex);
}
EXPORT_SYMBOL(nvmcg_unregister_device);

static int parse_resource(char *c, int *intval)
{
	substring_t argstr;
	char *name, *value = c;
	size_t len;
	int ret, i;

	name = strsep(&value, "=");
	if (!name || !value)
		return -EINVAL;

	i = match_string(nvmcg_resource_names, NVMCG_RESOURCE_MAX, name);
	if (i < 0)
		return i;

	len = strlen(value);

	argstr.from = value;
	argstr.to = value + len;

	ret = match_int(&argstr, intval);
	if (ret >= 0) {
		if (*intval < 0)
			return -EINVAL;
		return i;
	}
	if (strncmp(value, NVMCG_MAX_STR, len) == 0) {
		*intval = U32_MAX;
		return i;
	}
	return -EINVAL;
}

static int nvmcg_parse_limits(char *options,
			       int *new_limits, unsigned long *enables)
{
	char *c;
	int err = -EINVAL;

	/* parse resource options */
	while ((c = strsep(&options, " ")) != NULL) {
		int index, intval;

		index = parse_resource(c, &intval);
		if (index < 0)
			goto err;

		new_limits[index] = intval;
		*enables |= BIT(index);
	}
	return 0;

err:
	return err;
}

static struct nvmcg_device *nvmcg_get_device_locked(const char *name)
{
	struct nvmcg_device *device;

	lockdep_assert_held(&nvmcg_mutex);

	list_for_each_entry(device, &nvmcg_devices, dev_node)
		if (!strcmp(name, device->name))
			return device;

	return NULL;
}

static ssize_t nvmcg_resource_set_max(struct kernfs_open_file *of,
				       char *buf, size_t nbytes, loff_t off)
{
	struct nvm_cgroup *cg = css_nvmcg(of_css(of));
	const char *dev_name;
	struct nvmcg_resource_pool *rpool;
	struct nvmcg_device *device;
	char *options = strstrip(buf);
	int *new_limits;
	unsigned long enables = 0;
	int i = 0, ret = 0;

	/* extract the device name first */
	dev_name = strsep(&options, " ");
	if (!dev_name) {
		ret = -EINVAL;
		goto err;
	}

	new_limits = kcalloc(NVMCG_RESOURCE_MAX, sizeof(int), GFP_KERNEL);
	if (!new_limits) {
		ret = -ENOMEM;
		goto err;
	}

	ret = nvmcg_parse_limits(options, new_limits, &enables);
	if (ret)
		goto parse_err;

	/* acquire lock to synchronize with hot plug devices */
	mutex_lock(&nvmcg_mutex);

	device = nvmcg_get_device_locked(dev_name);
	if (!device) {
		ret = -ENODEV;
		goto dev_err;
	}

	rpool = get_cg_rpool_locked(cg, device);
	if (IS_ERR(rpool)) {
		ret = PTR_ERR(rpool);
		goto dev_err;
	}

	/* now set the new limits of the rpool */
	for_each_set_bit(i, &enables, NVMCG_RESOURCE_MAX)
		set_resource_limit(rpool, i, new_limits[i]);

	if (rpool->usage_sum == 0 &&
	    rpool->num_max_cnt == NVMCG_RESOURCE_MAX) {
		/*
		 * No user of the rpool and all entries are set to max, so
		 * safe to delete this rpool.
		 */
		free_cg_rpool_locked(rpool);
	}

dev_err:
	mutex_unlock(&nvmcg_mutex);

parse_err:
	kfree(new_limits);

err:
	return ret ?: nbytes;
}

static void print_rpool_values(struct seq_file *sf,
			       struct nvmcg_resource_pool *rpool)
{
	enum nvmcg_file_type sf_type;
	int i;
	u32 value;

	sf_type = seq_cft(sf)->private;

	for (i = 0; i < NVMCG_RESOURCE_MAX; i++) {
		seq_puts(sf, nvmcg_resource_names[i]);
		seq_putc(sf, '=');
		if (sf_type == NVMCG_RESOURCE_TYPE_MAX) {
			if (rpool)
				value = rpool->resources[i].max;
			else
				value = U32_MAX;
		} else {
			if (rpool)
				value = rpool->resources[i].usage;
			else
				value = 0;
		}

		if (value == U32_MAX)
			seq_puts(sf, NVMCG_MAX_STR);
		else
			seq_printf(sf, "%d", value);
		seq_putc(sf, ' ');
	}
}

static int nvmcg_resource_read(struct seq_file *sf, void *v)
{
	struct nvmcg_device *device;
	struct nvmcg_resource_pool *rpool;
	struct nvm_cgroup *cg = css_nvmcg(seq_css(sf));

	mutex_lock(&nvmcg_mutex);

	list_for_each_entry(device, &nvmcg_devices, dev_node) {
		seq_printf(sf, "%s ", device->name);

		rpool = find_cg_rpool_locked(cg, device);
		print_rpool_values(sf, rpool);

		seq_putc(sf, '\n');
	}

	mutex_unlock(&nvmcg_mutex);
	return 0;
}

static struct cftype nvmcg_files[] = {
	{
		.name = "max",
		.write = nvmcg_resource_set_max,
		.seq_show = nvmcg_resource_read,
		.private = NVMCG_RESOURCE_TYPE_MAX,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "current",
		.seq_show = nvmcg_resource_read,
		.private = NVMCG_RESOURCE_TYPE_STAT,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ }	/* terminate */
};

static struct cgroup_subsys_state *
nvmcg_css_alloc(struct cgroup_subsys_state *parent)
{
	struct nvm_cgroup *cg;

	cg = kzalloc(sizeof(*cg), GFP_KERNEL);
	if (!cg)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&cg->rpools);
	return &cg->css;
}

static void nvmcg_css_free(struct cgroup_subsys_state *css)
{
	struct nvm_cgroup *cg = css_nvmcg(css);

	kfree(cg);
}

/**
 * nvmcg_css_offline - cgroup css_offline callback
 * @css: css of interest
 *
 * This function is called when @css is about to go away and responsible
 * for shooting down all nvmcg associated with @css. As part of that it
 * marks all the resource pool entries to max value, so that when resources are
 * uncharged, associated resource pool can be freed as well.
 */
static void nvmcg_css_offline(struct cgroup_subsys_state *css)
{
	struct nvm_cgroup *cg = css_nvmcg(css);
	struct nvmcg_resource_pool *rpool;

	mutex_lock(&nvmcg_mutex);

	list_for_each_entry(rpool, &cg->rpools, cg_node)
		set_all_resource_max_limit(rpool);

	mutex_unlock(&nvmcg_mutex);
}

struct cgroup_subsys nvm_cgrp_subsys = {
	.css_alloc	= nvmcg_css_alloc,
	.css_free	= nvmcg_css_free,
	.css_offline	= nvmcg_css_offline,
	.legacy_cftypes	= nvmcg_files,
	.dfl_cftypes	= nvmcg_files,
};
