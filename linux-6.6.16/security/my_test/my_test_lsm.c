#include<linux/lsm_hooks.h>
#include<linux/kern_levels.h>
#include<linux/binfmts.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h> 
#include <linux/uaccess.h>     
#include <linux/kernel.h> 
static int my_test_bprm_check_security(struct linux_binprm *bprm)
{
	struct task_struct *task = current;
	printk(KERN_INFO "Process '%s' '%d' started with parent PID %d!\n",bprm->filename, task->pid, task->parent->pid);
return 0;
}


int my_inode_alloc_security(struct inode *inode)
{
    printk(KERN_INFO "New inode allocated: %lu\n", inode->i_ino);
    return 0; 
}

static struct security_hook_list my_test_hooks[] = {
	LSM_HOOK_INIT(bprm_check_security, my_test_bprm_check_security),
};


static int __init my_test_init(void)
{
  printk(KERN_ERR "mytest: we are going to do things \n");
  security_add_hooks(my_test_hooks, ARRAY_SIZE(my_test_hooks), "my_test");
  return 0;
}

DEFINE_LSM(yama)={
 .name = "my_test",
 .init = my_test_init,
};

