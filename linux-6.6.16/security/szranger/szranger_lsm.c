#include<linux/binfmts.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stat.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/kernel.h>

//static pid_t parent_pid = -1;

static int szranger_bprm_check_security(struct linux_binprm *bprm)
{
        struct task_struct *task = current;
         unsigned int pid = task->pid; 
        unsigned int tgid = task->tgid;
	pid_t current_pid = current->pid; 

	if(bprm->mm && pid != tgid)
	{
		printk(KERN_INFO "thread '%s' created with tid = '%d' and its process id = '%d'",bprm->filename,pid,tgid);
	} 
        else if(bprm->mm && pid == tgid) {
        //for thread as well pid and tgid will be same becase thread is also taking pid and tgid from its parent process only,
        //thread does not have a pid        
                printk(KERN_INFO "Process '%s' with PID ='%d' created with fork() ",bprm->filename,pid);
        }

        if(!bprm->mm)
        {
                printk(KERN_INFO "Process '%s' with PID '%d' started with exec() with parent PID %d!\n", 
                                                                        bprm->filename, task->pid, task->parent->pid);
        }             
        // if (parent_pid != current_pid) {
        // printk(KERN_INFO "Process created by exec(): PID=%d, Command=%s\n", current_pid, current->comm);
        // } else {
        // printk(KERN_INFO "Process created by fork(): PID=%d, Command=%s\n", current_pid, current->comm);
        // }
        //parent_pid = -1;
        return 0;
}

static int szranger_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
        //unsigned long clone_flags_set = clone_flags << 4;
        

        if(!(clone_flags & CLONE_VM))
        {
                printk(KERN_INFO "process is creted by EXEC() with task->pid %d current->pid %d \n",task->pid,current->pid);
        }
        else if (clone_flags & CLONE_THREAD)
        {
                printk(KERN_INFO "New thread created: PID=%d, Command=%s\n", task->pid, task->comm);
        }
        else{
                printk(KERN_INFO "New process created: with FORK() PID=%d, Command=%s\n", task->pid, task->comm);
        }
        // if(clone_flags_set & (CLONE_NEWUSER | CLONE_NEWCGROUP))
        // {
        //         printk(KERN_INFO "checking with 0x12");
        // }
        printk(KERN_INFO "parent process id %d and current pid %d and clone_flags 0x%x \nclone_flags=%lu",
                                task->real_parent->pid,current->pid,clone_flags,clone_flags);
           
        // if (task->pid != current->pid) {
        //         parent_pid = task->pid;
        // }
        return 0;
}

static struct security_hook_list szranger_hooks[]={
        LSM_HOOK_INIT(bprm_check_security, szranger_bprm_check_security),
        LSM_HOOK_INIT(task_alloc, szranger_task_alloc),
};

static int __init szranger_init(void)
{
        printk(KERN_ERR "mytest:we are going to do things \n");
        security_add_hooks(szranger_hooks,ARRAY_SIZE(szranger_hooks),"szranger");
        return 0;
}



DEFINE_LSM(yama)={
        .name = "szranger",
        .init = szranger_init,
};

