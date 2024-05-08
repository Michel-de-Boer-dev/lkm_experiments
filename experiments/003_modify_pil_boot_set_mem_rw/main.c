#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/string.h>


#define KP_PRINT_COLUMNS    16
void kp_print(void * addr, unsigned long size)
{
	int i;
	char * t = (char *)addr;

	printk(KERN_INFO "Dumping memory at %pK:\n", addr);

	for(i = 0 ; i < KP_PRINT_COLUMNS; i++) {
		if(i % KP_PRINT_COLUMNS == 0) {
			printk(KERN_CONT "       ");
		}

		printk(KERN_CONT "%02d ", i);
	}

	printk(KERN_CONT "\n\n");

	for(i = 0 ; i < size; i++) {
		if(i % KP_PRINT_COLUMNS == 0) {
			if(i) {
				printk(KERN_CONT "\n");
			}

			printk("%04x   ", i / KP_PRINT_COLUMNS);
		}

		printk(KERN_CONT "%02x ", (unsigned char)t[i]);
	}

	printk(KERN_CONT "\n");
}

int (* smem_rw) (unsigned long addr, int pages);
int (* smem_ro) (unsigned long addr, int pages);


int target(void)
{
	return 1;
}

static int __init kp_init(void)
{

	unsigned long b;/* Base of the page. */
	int nof_p = 1; 	/* Nof pages. */

	unsigned long rw = kallsyms_lookup_name("set_memory_rw");
	unsigned long ro = kallsyms_lookup_name("set_memory_ro");

	unsigned long pill_boot = kallsyms_lookup_name("pil_boot");
	char * m = ((char *)pill_boot);


	if(!rw || !ro || !pill_boot) {
		printk(KERN_INFO "Cannot resolve procedures!\n");
		return 0;
	}

	smem_rw = (void *)rw;
	smem_ro = (void *)ro;

	/* Locate the start of the memory page which contains our target. */
	b = ((unsigned long)m - ((unsigned long)m % PAGE_SIZE));


	kp_print(target, 16);

	smem_rw(b, nof_p);
	*m = 2; // Modify pil_boot 
	smem_ro(b, nof_p);
/* -------------------------------------------------------------------------- */
	kp_print(target, 16);

	return 0;
}

static void __exit kp_exit(void)
{
	return;
}

module_init(kp_init);
module_exit(kp_exit);

MODULE_LICENSE("GPL");