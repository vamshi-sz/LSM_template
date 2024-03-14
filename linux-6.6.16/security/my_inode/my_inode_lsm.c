#include<linux/lsm_hooks.h>
#include<linux/kern_levels.h>
#include<linux/binfmts.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stat.h> 

static int my_test_bprm_check_security(struct linux_binprm *bprm)
{
	struct task_struct *currentS = current;

	printk(KERN_INFO "Process '%s' (%d) started with parent PID %d!\n", bprm->filename, currentS->pid, currentS->parent->pid);

	return 0;
}
static int my_lsm_hook_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode) {
    printk(KERN_INFO "File created: %s\n", dentry->d_name.name);
    return 0; 
}

static int my_lsm_hook_inode_unlink(struct inode *dir, struct dentry *dentry) {
    printk(KERN_INFO "File deleted: %s\n", dentry->d_name.name);
    return 0;  
}
static int my_lsm_hook_inode_setattr(struct dentry *dentry, struct iattr *attr) {
    if (S_ISREG(dentry->d_inode->i_mode)) {
        // It's a regular file
        printk(KERN_INFO "File modified: %s\n", dentry->d_name.name);
    } else if (S_ISDIR(dentry->d_inode->i_mode)) {
        // It's a directory
        printk(KERN_INFO "Directory modified: %s\n", dentry->d_name.name);
    } else {
        // It's neither a regular file nor a directory
        printk(KERN_INFO "Unknown inode type modified: %s\n", dentry->d_name.name);
    }
    return 0; 
}


 static int my_lsm_hook_msg_msg_alloc_security(struct msg_msg *msg)
 {
    printk(KERN_INFO "my_lsm_hook_msg_msg_alloc_security is called \n");
    return 0;
 }

 void my_lsm_hook_msg_msg_free_security(struct msg_msg *msg)
 {
    printk(KERN_INFO "my_lsm_hook_msg_msg_free_security IS CALLED \n");
 }

static struct security_hook_list my_test_hooks[]={
	LSM_HOOK_INIT(bprm_check_security, my_test_bprm_check_security),
	LSM_HOOK_INIT(inode_create, my_lsm_hook_inode_create),
	LSM_HOOK_INIT(inode_unlink, my_lsm_hook_inode_unlink),
	LSM_HOOK_INIT(inode_setattr, my_lsm_hook_inode_setattr),
    LSM_HOOK_INIT(msg_msg_alloc_security, my_lsm_hook_msg_msg_alloc_security),
    LSM_HOOK_INIT(msg_msg_free_security, my_lsm_hook_msg_msg_free_security),
};

static int __init my_test_init(void)
{
	printk(KERN_ERR "mytest:we are going to do things \n");
	security_add_hooks(my_test_hooks,ARRAY_SIZE(my_test_hooks),"my_test");
	return 0;
}



DEFINE_LSM(yama)={
	.name = "my_inode",
	.init = my_test_init,
};



