#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>

#define MODULE_NAME "Baseband_debug_module"
MODULE_AUTHOR("Michel");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Baseband debug module");
MODULE_VERSION("0.1");

unsigned long long* pil_boot_location = 0xffffffb176c1f008;


static struct kprobe kp = {
    .symbol_name = "pil_boot",
    .offset = 0x00
};

static void __kprobes handler_post(struct kprobe *k, struct pt_regs *regs, unsigned long flags)
{
    return;
}

static int handler_fault(struct kprobe *k, struct pt_regs *regs, int trapnr)
{
    printk(KERN_ERR, "Kprobe error baseband module\n");
    return 0;
}



static int __init kprobe_init(void)
{
    int ret;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;
    ret = register_kprobe(&kp);
    if(ret < 0)
    {
        printk(KERN_ERR, "krpobe init error baseband module\n");
        return ret;
    }
    return 0;
}


static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
}


module_init(kprobe_init);
module_exit(kprobe_exit);