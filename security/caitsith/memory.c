/*
 * security/caitsith/memory.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#include "internal.h"

#ifdef CONFIG_CAITSITH_USE_EXTERNAL_TASK_SECURITY

/***** SECTION1: Constants definition *****/

/***** SECTION2: Structure definition *****/

/***** SECTION3: Prototype definition section *****/

static int cs_alloc_task_security(const struct task_struct *task);
static void cs_free_task_security(const struct task_struct *task);
static void cs_add_task_security(struct cs_security *ptr,
				 struct list_head *list);
static void cs_rcu_free(struct rcu_head *rcu);

/***** SECTION4: Standalone functions section *****/

/***** SECTION5: Variables definition section *****/

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_oom_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_default_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* List of "struct cs_security". */
struct list_head cs_task_security_list[CS_MAX_TASK_SECURITY_HASH];
/* Lock for protecting cs_task_security_list[]. */
static DEFINE_SPINLOCK(cs_task_security_list_lock);

/***** SECTION6: Dependent functions section *****/

/**
 * cs_add_task_security - Add "struct cs_security" to list.
 *
 * @ptr:  Pointer to "struct cs_security".
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void cs_add_task_security(struct cs_security *ptr,
				 struct list_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
}

/**
 * cs_alloc_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_alloc_task_security(const struct task_struct *task)
{
	struct cs_security *old_security = cs_current_security();
	struct cs_security *new_security = kzalloc(sizeof(*new_security),
						   GFP_KERNEL);
	struct list_head *list = &cs_task_security_list
		[hash_ptr((void *) task, CS_TASK_SECURITY_HASH_BITS)];
	if (!new_security)
		return -ENOMEM;
	new_security->task = task;
	new_security->cs_domain_info = old_security->cs_domain_info;
	new_security->cs_flags = old_security->cs_flags;
	cs_add_task_security(new_security, list);
	return 0;
}

/**
 * cs_find_task_security - Find "struct cs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct cs_security" on success, &cs_oom_security on
 * out of memory, &cs_default_security otherwise.
 *
 * If @task is current thread and "struct cs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct cs_security *cs_find_task_security(const struct task_struct *task)
{
	struct cs_security *ptr;
	struct list_head *list = &cs_task_security_list
		[hash_ptr((void *) task, CS_TASK_SECURITY_HASH_BITS)];
	/* Make sure INIT_LIST_HEAD() in cs_mm_init() takes effect. */
	while (!list->next)
		smp_rmb();
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &cs_default_security;
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &cs_oom_security;
	}
	*ptr = cs_default_security;
	ptr->task = task;
	cs_add_task_security(ptr, list);
	return ptr;
}

/**
 * cs_rcu_free - RCU callback for releasing "struct cs_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void cs_rcu_free(struct rcu_head *rcu)
{
	struct cs_security *ptr = container_of(rcu, typeof(*ptr), rcu);

	kfree(ptr);
}

/**
 * cs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void cs_free_task_security(const struct task_struct *task)
{
	unsigned long flags;
	struct cs_security *ptr = cs_find_task_security(task);

	if (ptr == &cs_default_security || ptr == &cs_oom_security)
		return;
	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
	call_rcu(&ptr->rcu, cs_rcu_free);
}

/**
 * cs_mm_init - Initialize mm related code.
 *
 * Returns nothing.
 */
void __init cs_mm_init(void)
{
	int idx;

	for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&cs_task_security_list[idx]);
	smp_wmb(); /* Avoid out of order execution. */
	caitsith_ops.alloc_task_security = cs_alloc_task_security;
	caitsith_ops.free_task_security = cs_free_task_security;
}

#endif
