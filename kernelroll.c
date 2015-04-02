/*
 * kernelroll - linux kernel module for advanced rickrolling
 * Copyright (C) 2011 Franz Pletz <fpletz@fnordicwalking.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/init.h> 
#include <asm/unistd.h> 
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/amd_nb.h>
#include <linux/highuid.h>

#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Franz Pletz");
MODULE_DESCRIPTION("for teh lulz!");

char *rollfile;
void **sys_call_table;

module_param(rollfile, charp, 0000);
MODULE_PARM_DESC(rollfile, "music trolling file");

unsigned long **find_sys_call_table(void) {
    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long)sys_close;
         ptr < (unsigned long)&loops_per_jiffy;
         ptr += sizeof(void *)) {
             
        p = (unsigned long *)ptr;

        if (p[__NR_close] == (unsigned long)sys_close) {
            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
            return (unsigned long **)p;
        }
    }
    
    return NULL;
}


asmlinkage long (*o_open)(const char __user *path, int oflag, mode_t mode); 
asmlinkage long my_open(const char __user *path, int oflag, mode_t mode) 
{
    int len = strlen(rollfile) + 1;
    char* p;
    long r;

    p = (char *)(path + strlen(path) - 4);

    if(rollfile != NULL && !strcmp(p, ".mp3")) {
        void *buf = kmalloc(len, GFP_KERNEL);
        memcpy(buf, path, len);
        printk(KERN_INFO "patching %s with %s\n", path, rollfile);
        memcpy((void *)path, rollfile, len);
        r = o_open(path, oflag, mode);
        memcpy((void *)path, buf, len);
        kfree(buf);
    } else {
        r = o_open(path, oflag, mode);
        printk(KERN_DEBUG "file %s has been opened with mode %d\n", path, mode);
    }


    return r;
} 


void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if(pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}

static int __init init_rickroll(void) 
{
    sys_call_table = (void **)find_sys_call_table();
    if(!sys_call_table)
    {
        printk(KERN_ERR "Cannot find the system call address\n"); 
        return -1;  /* do not load */
    } else {
        printk(KERN_INFO "System call table found @ %lx\n", (unsigned long)sys_call_table);
    }

    set_addr_rw((unsigned long)sys_call_table);
    GPF_DISABLE;

    o_open = (long(*)(const char *, int, mode_t))(sys_call_table[__NR_open]); 
    sys_call_table[__NR_open] = (void *) my_open; 
    GPF_ENABLE;

    return 0; 
} 

static void __exit exit_rickroll(void) 
{ 
    GPF_DISABLE;
    sys_call_table[__NR_open] = (void *) o_open; 

    set_addr_ro((unsigned long)sys_call_table);
    GPF_ENABLE;
} 

module_init(init_rickroll); 
module_exit(exit_rickroll); 
