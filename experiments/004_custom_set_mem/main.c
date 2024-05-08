```python
#include <linux/init.h>     // module_{init,exit}()
#include <linux/module.h>   // THIS_MODULE, MODULE_VERSION, ...
#include <linux/kernel.h>   // printk(), pr_*()
#include <linux/kallsyms.h> // kallsyms_lookup_name()
#include <asm/syscall.h>    // syscall_fn_t, __NR_*
#include <asm/ptrace.h>     // struct pt_regs
#include <asm/tlbflush.h>   // flush_tlb_kernel_range()
#include <asm/pgtable.h>    // {clear,set}_pte_bit(), set_pte()
#include <linux/vmalloc.h>  // vm_unmap_aliases()
#include <linux/mm.h>       // struct mm_struct, apply_to_page_range()
#include <linux/kconfig.h>  // IS_ENABLED()
#include <linux/memory.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h> // cpu_replace_ttbr1

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

static struct mm_struct *init_mm_ptr;
static unsigned long pil_boot;

/********** HELPERS **********/

void show_pte(unsigned long addr)
{
	struct mm_struct *mm = init_mm_ptr;
	pgd_t *pgd;

	pr_alert(" pgtable: %luk pages, %u-bit VAs, pgd = %p\n",
		 PAGE_SIZE / SZ_1K,
		 VA_BITS, mm->pgd);
	pgd = pgd_offset(mm, addr);
	pr_alert("[%016lx] *pgd=%016llx", addr, pgd_val(*pgd));

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd) || pgd_bad(*pgd))
			break;

		pud = pud_offset(pgd, addr);
		pr_cont(", *pud=%016llx", pud_val(*pud));
		if (pud_none(*pud) || pud_bad(*pud))
			break;

		pmd = pmd_offset(pud, addr);
		pr_cont(", *pmd=%016llx", pmd_val(*pmd));
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			break;

		pte = pte_offset_map(pmd, addr);
		pr_cont(", *pte=%016llx", pte_val(*pte));
		pte_unmap(pte);
	} while(0);

	pr_cont("\n");
}

/*
 * Do a quick page-table lookup for a single page.
 */
static pte_t * follow_page2(struct mm_struct *mm, unsigned long address)
{
    //https://github.com/lorenzo-stoakes/linux-gorman-book-notes/blob/master/3.md
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out;

    pud_t *pud = pud_offset(pgd, address);
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

	ptep = pte_offset_kernel(pmd, address);
	if (!ptep)
		goto out;

    return ptep;

out:
	return NULL;
}

int find_physical_pte(unsigned long long addr, struct mm_struct *mm)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    unsigned long long address;

    address = (unsigned long long)addr;

    pgd = pgd_offset(mm, address);
    printk(KERN_INFO "\npgd is: %p\n", (void *)pgd);
    printk(KERN_INFO "pgd value: %llx\n", *pgd);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) 
        return -1;
    //check if (*pgd) is a table entry. Exit here if you get the table entry.

    pud = pud_offset(pgd, address);
    printk(KERN_INFO "\npud is: %p\n", (void *)pud);
    printk(KERN_INFO "pud value: %llx\n", (*pud).pgd);
    if (pud_none(*pud) || pud_bad(*pud))
        return -2;
    //check if (*pud) is a table entry. Exit here if you get the table entry.   

    pmd = pmd_offset(pud, address);
    printk(KERN_INFO "\npmd is: %p\n", (void *)pmd);
    printk(KERN_INFO "pmd value: %llx\n",*pmd);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -3;
    //check if (*pmd) is a table entry. Exit here if you get the table entry.

    ptep = pte_offset_kernel(pmd, address);
    printk(KERN_INFO "\npte is: %p\n", (void *)ptep);
    printk(KERN_INFO "pte value: %llx\n",*ptep);
    if (!ptep)
        return -4;

    return 1;
}

static void print_pmd( pud_t *pud, long unsigned start) 
{
	pmd_t *pmd = pmd_offset(pud, 0UL);
    unsigned long addr;
	unsigned i;

	for (i = 0; i < PTRS_PER_PMD; i++, pmd++) {
		addr = start + i * PMD_SIZE;
		if (pmd_none(*pmd) || pmd_sect(*pmd)) {
            printk(KERN_ERR "ENTRY %d, PMD: %lu - DOES NOT EXIST OR BAD\n", i, pmd->pmd);
		} else {
            printk(KERN_INFO "ENTRY %d, PMD: %lu", i, pmd->pmd);
		}
	}

}

static void print_pud( pgd_t *pgd, long unsigned vm_start) 
{
    pud_t *pud = pud_offset(pgd, 0UL);
	unsigned long addr;
	unsigned i;

	for (i = 0; i < PTRS_PER_PUD; i++, pud++) {
		addr = vm_start + i * PUD_SIZE;
		if (pud_none(*pud) || pud_sect(*pud)) {
            printk(KERN_ERR "ENTRY %d, PUD: %lu - DOES NOT EXIST OR BAD\n", i, pud->pgd);

		} else {
            printk(KERN_INFO "ENTRY %d, PUD: %lu", i, pud->pgd);

			// walk_pmd(st, pud, addr);
		}
	}
}
// given the memory descriptor and the begin address of virtual memory, prints out the top level page table
static void print_pgd(struct mm_struct *mm, long unsigned vm_start) {
    //https://github.com/eneskeles/pgd-kernel-module/blob/master/pgd_module.c
	long unsigned current_addr = vm_start;
	long unsigned inc = 1LU << 39;

	pgd_t *pgd; 
	int i; 
	printk(KERN_ERR "TOP LEVEL PAGE TABLE ENTRIES:\n");
    for (i = 0; i < PTRS_PER_PGD; i++, pgd++) {

		pgd = pgd_offset(mm, current_addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd)) {
			printk(KERN_ERR "ENTRY %d, PGD: %lu - DOES NOT EXIST OR BAD\n", i, pgd->pgd);
			break;
		}
		else {
			// printk(KERN_INFO "ENTRY %d, PGD: %lu", i, pgd->pgd);
            pud_t *pud = pud_offset(pgd, 0UL);
            print_pmd(pud, current_addr);// pmd instead of pud, as we only have 3 levels, not 4, so pud==pgd
		}
		current_addr += inc;
	}
} 

// From arch/arm64/mm/pageattr.c.
struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

// From arch/arm64/mm/pageattr.c.
static int change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr, void *data)
{
    struct page_change_data *cdata = data;
    printk(KERN_INFO "[i] change_page_range callback (%lx)\n", addr);
    printk(KERN_INFO "[i] PTE @ %lx\n", (unsigned long) ptep);
    printk(KERN_INFO "[i] PTE @ PHYS %lx\n", virt_to_phys((unsigned long) ptep));

    printk(KERN_INFO "[i] PTE is now: %s\n", pte_write(*ptep)!=0 ? "writable" : "read-only" );

    // pte_t* p = follow_page2(init_mm_ptr, (unsigned long) ptep);

    // printk(KERN_INFO "[i] loc is now: %s\n", pte_write(*p)!=0 ? "writable" : "read-only" );

    show_pte(addr);

    pte_t pte = READ_ONCE(*ptep);

    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);

// 	asm("tlbi	vmalle1is");
// dsb(ish);
// isb();
    printk(KERN_INFO "[i] Set PTE to: %s\n", pte_write(pte)!=0 ? "writable" : "read-only" );

    set_pte(ptep, pte);
    // TODO ISB +DSB + TLBI?
    printk(KERN_INFO "[i] change_page_range done\n");

    return 0;
}

// From arch/arm64/mm/pageattr.c.
static int __change_memory_common(unsigned long start, unsigned long size,
                  pgprot_t set_mask, pgprot_t clear_mask)
{
    struct page_change_data data;
    int ret;

    data.set_mask = set_mask;
    data.clear_mask = clear_mask;

    ret = apply_to_page_range(init_mm_ptr, start, size, change_page_range, &data);

    flush_tlb_kernel_range(start, start + size);
    return ret;
}

// Simplified set_memory_rw() from arch/arm64/mm/pageattr.c.
static int set_page_rw(unsigned long addr)
{
    vm_unmap_aliases();    
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE), __pgprot(PTE_RDONLY));
}

// Simplified set_memory_ro() from arch/arm64/mm/pageattr.c.
static int set_page_ro(unsigned long addr)
{
    vm_unmap_aliases();
    return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY), __pgprot(PTE_WRITE));
}

void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);

static inline uint64_t read_ttbr0_el1(void)
{
    uint64_t val;
    asm volatile("mov %0, xzr; mrs %0, ttbr0_el1" : "=r" (val));
    return val;
}

static inline uint64_t read_ttbr1_el1(void)
{
    uint64_t val;
    asm volatile("mov %0, xzr; mrs %0, ttbr1_el1" : "=r" (val));
    return val;
}

static inline uint64_t read_tcr_el1(void)
{
    uint64_t val;
    asm volatile("mov %0, xzr; mrs %0, tcr_el1" : "=r" (val));
    return val;
}

static inline uint64_t read_currentEL(void)
{
    uint64_t val;
    asm volatile("mov %0, xzr; mrs %0, CurrentEL" : "=r" (val));
    return val >> 2;
}

static inline uint64_t ttbr0_base_address(void)
{
    uint64_t val = read_ttbr0_el1();
    return (val & 0xffffffffffc0) | ((val & 0x3c) << 46);
}

static inline uint64_t ttbr1_base_address(void)
{
     uint64_t val = read_ttbr1_el1();
    return (val & 0xffffffffffc0) | ((val & 0x3c) << 46);
}

char copied_swapper_pg_dir[2048*8] __aligned(PGD_SIZE);

static int __init modinit(void)
{
    int res;

    pr_info("init\n");

    init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
    pil_boot = kallsyms_lookup_name("pil_boot");
    update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");

    printk(KERN_INFO "[i] init_mm @ %lx\n", (unsigned long)(init_mm_ptr));
    printk(KERN_INFO "[i] pil_boot @ %lx\n", (unsigned long)pil_boot);

    printk(KERN_INFO "[i] swapper_pg_dir (pgd) @ %lx\n", (unsigned long)(init_mm_ptr->pgd));
    printk(KERN_INFO "[i] swapper_pg_dir (pgd) PHYS @ %lx\n", virt_to_phys((unsigned long)(init_mm_ptr->pgd)));

	// TODO init_mm derefence and find actual table

    printk(KERN_INFO "[i] init_mm PHYS @ %lx\n", virt_to_phys(init_mm_ptr));
    printk(KERN_INFO "[i] pil_boot PHYS @ %lx\n", virt_to_phys(pil_boot));

	
    printk(KERN_INFO "[i] EL = %u\n", read_currentEL());

	printk(KERN_INFO "[i] TTBR0_EL1 = 0x%08x", read_ttbr0_el1());
	printk(KERN_INFO "[i] TTBR1_EL1 = 0x%08x", read_ttbr1_el1());

	printk(KERN_INFO "[i] TTBR0 base = 0x%08x", ttbr0_base_address());
	printk(KERN_INFO "[i] TTBR1 base = 0x%08x", ttbr1_base_address());

	printk(KERN_INFO "[i] TTBR0 virt = 0x%08x", phys_to_virt(ttbr0_base_address()));
	printk(KERN_INFO "[i] TTBR1 virt = 0x%08x", phys_to_virt(ttbr1_base_address()));

	printk(KERN_INFO "[i] tcr_el1 = 0x%08x", read_tcr_el1());

    if (init_mm_ptr == NULL || pil_boot == NULL || update_mapping_prot == NULL) {
        return -EFAULT;
    }

    // set_page_prot(swapper_pg_dir, PAGE_KERNEL);

//     memcpy((void *)copied_swapper_pg_dir, (void *) init_mm_ptr->pgd, 2048*4);

//     printk(KERN_INFO "[i] compared page tables:  0x%08x", memcmp(copied_swapper_pg_dir, init_mm_ptr->pgd,  PTRS_PER_PGD * sizeof(pgd_t)));

// 	// // cpu_replace_ttbr1(lm_alias(copied_swapper_pg_dir));

//     uint64_t val = virt_to_phys( (unsigned long)copied_swapper_pg_dir);
//     asm volatile("mov %0, xzr; msr ttbr1_el1, %0; isb;" : "=r" (val));
//   dsb(nshst);
// 	__tlbi(vmalle1);
// 	dsb(nsh);
// 	isb();
//     dsb(ishst);
// 	__tlbi(vmalle1is);
// 	dsb(ish);
// 	isb();

    // print_pgd(init_mm_ptr, VA_START);
   // find_physical_pte(pil_boot, init_mm_ptr);

// echo 0 > /proc/sys/kernel/kptr_restrict && cat /proc/kmsg
    // Make pagetable rw
    // update_mapping_prot(__pa_symbol(init_mm_ptr->pgd), (unsigned long)init_mm_ptr->pgd,
	// 		4096, PAGE_KERNEL);
    // res = set_page_rw((unsigned long)((init_mm_ptr->pgd)) & PAGE_MASK);
    // if (res != 0) {
    //     pr_err("set_page_rw() failed: %d\n", res);
    //     return res;
    // }

    // res = set_page_rw((unsigned long)((unsigned long)(pil_boot)) & PAGE_MASK);
    // if (res != 0) {
    //     pr_err("set_page_rw() failed: %d\n", res);
    //     return res;
    // }

// // preempt_disable();
// update_mapping_prot(__pa_symbol(pil_boot), (unsigned long)pil_boot,
// 			4096, PAGE_KERNEL);
// // preempt_enable();

	// // Don't change ? 
    // // char* data = (char*) pil_boot;
    // // *data = 0x10;

// update_mapping_prot(__pa_symbol(pil_boot), (unsigned long)pil_boot,
// 			4096, PAGE_KERNEL_EXEC);

    // res = set_page_ro((unsigned long)(pil_boot) & PAGE_MASK);
    // if (res != 0) {
    //     pr_err("set_page_ro() failed: %d\n", res);
    //     return res;
    // }

    pr_info("init done\n");

    return 0;
}

static void __exit modexit(void)
{
    pr_info("exit\n");
    return;
}

module_init(modinit);
module_exit(modexit);
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hijack on arm64.");
MODULE_AUTHOR("Henk de la Bric");
MODULE_LICENSE("GPL");
```