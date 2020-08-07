/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <net/llc.h>
#include <net/stp.h>

#include "br_private.h"

int (*br_should_route_hook)(struct sk_buff *skb);

static const struct stp_proto br_stp_proto = {
	.rcv	= br_stp_rcv,
};

static struct pernet_operations br_net_ops = {
	.exit	= br_net_exit,
};

#ifdef CONFIG_SCM_SUPPORT
extern unsigned char sc_first_wlan_client_mac[];
static ssize_t proc_read_firstwlanclient_fops(char *page, char **start, off_t off, int count, int *eof, void *data)
{
        int len;
       if(off > 0)
       {
               *eof = 1;
               return 0;
       }
    if (sc_first_wlan_client_mac[0]==0 && sc_first_wlan_client_mac[1] == 0 && sc_first_wlan_client_mac[2] == 0 && 
	sc_first_wlan_client_mac[3] == 0 && sc_first_wlan_client_mac[4] == 0 && sc_first_wlan_client_mac[5] == 0)
	{
		len = sprintf( page, "none\n");
	} else
	{
		len = sprintf( page, "%x:%x:%x:%x:%x:%x\n", sc_first_wlan_client_mac[0], sc_first_wlan_client_mac[1], sc_first_wlan_client_mac[2],
															sc_first_wlan_client_mac[3], sc_first_wlan_client_mac[4], sc_first_wlan_client_mac[5]);
	}
        return len;
}

static ssize_t proc_write_firstwlanclient_fops(struct file *file, const char *buffer, unsigned long count, void *data)
{
       return count;
}
static struct proc_dir_entry *firstwlanclient_file = NULL;
#endif

static int __init br_init(void)
{
	int err;

	err = stp_proto_register(&br_stp_proto);
	if (err < 0) {
		pr_err("bridge: can't register sap for STP\n");
		return err;
	}

	err = br_fdb_init();
	if (err)
		goto err_out;

	err = register_pernet_subsys(&br_net_ops);
	if (err)
		goto err_out1;

	err = br_netfilter_init();
	if (err)
		goto err_out2;

	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto err_out3;

	err = br_netlink_init();
	if (err)
		goto err_out4;

	brioctl_set(br_ioctl_deviceless_stub);

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_test_addr_hook = br_fdb_test_addr;
#endif

#ifdef CONFIG_SCM_SUPPORT
       {
               firstwlanclient_file=create_proc_entry("wlanclient_for_pot", 0666, NULL);
               if (firstwlanclient_file)
               {
                       //firstwlanclient_file->owner = THIS_MODULE;
                       //firstwlanclient_file->proc_fops = &firstwlanclient_fops;
                       firstwlanclient_file->read_proc = proc_read_firstwlanclient_fops;
                       firstwlanclient_file->write_proc = proc_write_firstwlanclient_fops;
               }        
       }
#endif
	return 0;
err_out4:
	unregister_netdevice_notifier(&br_device_notifier);
err_out3:
	br_netfilter_fini();
err_out2:
	unregister_pernet_subsys(&br_net_ops);
err_out1:
	br_fdb_fini();
err_out:
	stp_proto_unregister(&br_stp_proto);
	return err;
}

static void __exit br_deinit(void)
{
	stp_proto_unregister(&br_stp_proto);

	br_netlink_fini();
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);

	unregister_pernet_subsys(&br_net_ops);

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	br_netfilter_fini();
#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_test_addr_hook = NULL;
#endif

	br_fdb_fini();
#ifdef CONFIG_SCM_SUPPORT
	if (firstwlanclient_file)
	{
	       remove_proc_entry("wlanclient_for_pot", NULL);
	       firstwlanclient_file = NULL;
	}
#endif		
}

EXPORT_SYMBOL(br_should_route_hook);

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
