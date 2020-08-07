
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include "if_name.h"

#if 1
#define dbgMsg  printk
#else
#define dbgMsg(...)
#endif

extern int (*bt_igmp_forward_hook) (struct sk_buff *skb);

enum
{
	DEBUGMSG_NONE,
	DEBUGMSG_INFO,
	DEBUGMSG_TRACE, 
	DEBUGMSG_DUMP,
};

static int config_done = 0;
static __be32 group1_ip_addr = 0, ethwan_ip_addr = 0;
static unsigned char ethwan_mac_addr[ETH_ALEN] = {0}, group1_mac_addr[ETH_ALEN] = {0};
static int force_bt_igmp_packet = 0;
static int debug_level = 0;

void debug_msg(int level, char *format, ...)
{
	if (level <= debug_level)
	{
#define SYSTEM_BUF_SIZE 512
		char buf[SYSTEM_BUF_SIZE]="";
		va_list arg;
		
		va_start(arg, format);
		vsnprintf(buf,SYSTEM_BUF_SIZE, format, arg);
		va_end(arg);
		
		printk(buf);
	}
}

void dump_skb(struct sk_buff *skb_new)
{
	int i = 0;
	unsigned char *p = skb_new->data;
	int max_len = ((skb_new->len)>60)?60:(skb_new->len);
	
	if (debug_level < DEBUGMSG_DUMP)
	{
		return;	
	}
	
	printk("dump length %d, skb length %d\n", max_len, skb_new->len);
	for(i=0; i<max_len; i++)
	{
		printk("%2x ", p[i]);
		if ((i!=0) && (i%16 == 0))
		{
			printk("\n");
		}
	}
	printk("\ndump skb done\n");
}

void update_skb_ip(struct sk_buff *skb_new, int is_from_group1)
{
	struct iphdr *iph = ip_hdr(skb_new);
	struct ethhdr *ethhdr = eth_hdr(skb_new);
	
	dump_skb(skb_new);
	debug_msg(DEBUGMSG_TRACE, "iph:%x, iph->saddr:%x, iph->daddr:%x, iph->ihl:%x\n", 
			(unsigned int)iph, iph->saddr, iph->daddr, iph->ihl);
	if (iph)
	{
		iph->ttl = ((iph->ttl)>1)?(iph->ttl-1):1;
		if (is_from_group1)
		{
			debug_msg(DEBUGMSG_INFO, "receive from lan, replace ip %x\n", (unsigned int)ethwan_ip_addr);
			iph->saddr = ethwan_ip_addr;
			memcpy(ethhdr->h_source, ethwan_mac_addr, ETH_ALEN);
		} else
		{
			//debug_msg(DEBUGMSG_INFO, "receive from wan, replace ip %x\n", (unsigned int)group1_ip_addr);
			//iph->saddr = group1_ip_addr;
			memcpy(ethhdr->h_source, group1_mac_addr, ETH_ALEN);
		}
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	}
	dump_skb(skb_new);
	debug_msg(DEBUGMSG_TRACE, "iph:%x iph->check:%x done\n", (unsigned int)iph, iph->check);
}

static void deliver_skb_by_if(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *skb_new = NULL;
	int ret;
	
	skb_new = skb_copy(skb, GFP_ATOMIC);
	if(!skb_new)
	{
		debug_msg(DEBUGMSG_INFO, "Error when skb_copy !\n");
		return;
	}
	
	skb_push(skb_new, ETH_HLEN);
	skb_new->dev = dev;
	update_skb_ip(skb_new, (strcmp(skb->dev->name, LAN_LOG_IFNAME) == 0));
	debug_msg(DEBUGMSG_TRACE, "send packet that from indev %s outdev %s\n", skb->dev->name, skb_new->dev->name);
	
	ret = dev_queue_xmit(skb_new);
	debug_msg(DEBUGMSG_TRACE, "send packet ret %d\n", ret);
	if (ret)
	{
		/* let gcc463 not complain. */
	}
}

int is_well_known_muticast_dst(__be32 daddr)
{
	int well_known_muticast_packet = 0;
	__be32 ip1 = in_aton("224.0.0.252");
	__be32 ip2 = in_aton("239.255.255.250");
	__be32 ip3 = in_aton("224.0.0.251");
	if (daddr == ip1 || daddr == ip2 || daddr == ip3)
	{
		well_known_muticast_packet = 1;
	}
	return well_known_muticast_packet;
}

int is_bt_igmp_packet(struct sk_buff *skb)
{
	int bt_igmp_packet = 0;
	struct iphdr *iph = ip_hdr(skb);
	if (iph)
	{
		/* packet from group1, only deliver IGMP packet */
		if (strcmp(skb->dev->name, LAN_LOG_IFNAME) == 0)
		{
			if (iph->protocol == IPPROTO_IGMP)	
			{
				bt_igmp_packet = 1;	
			}
		}	
		
		/* packet from eth3, deliver IGMP, also the multicast packet which dst has been JOIN. */
		if (strcmp(skb->dev->name, WAN_PHY_IFNAME) == 0)
		{
			bt_igmp_packet = 1;
			if (is_well_known_muticast_dst(iph->daddr))
			{
				debug_msg(DEBUGMSG_INFO, "from wan but this is LLMR/MDNS/SSDP\n");
				bt_igmp_packet = 0;	
			}
		}
	}
	
	if (bt_igmp_packet == 0 && force_bt_igmp_packet == 1)
	{
		debug_msg(DEBUGMSG_INFO, "not bt_igmp_packet but force it for debug\n");
		bt_igmp_packet = 1;
	}
	
	return bt_igmp_packet;
}

static int bt_igmp_forward_handler(struct sk_buff *skb)
{
	unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_device *indev = skb->dev;
	struct net_device *outdev = NULL;
	char *outdevname = NULL;

	if (config_done == 0)
	{
		debug_msg(DEBUGMSG_NONE, "ip or mac not set\n");
		return -1;						
	}
	if ( skb->pkt_type == PACKET_HOST || skb->pkt_type == PACKET_LOOPBACK)
	{
		debug_msg(DEBUGMSG_INFO, "%s: %s, ignore!\n", __FUNCTION__, skb->pkt_type == PACKET_HOST?"PACKET_HOST":"PACKET_LOOPBACK");
		return -1;
	}
	if(!indev)
	{
		debug_msg(DEBUGMSG_INFO, "Can't find net-work interface dev!\n");
		return -1;
	}
	if(skb->protocol != __constant_htons(ETH_P_IP))
	{
		debug_msg(DEBUGMSG_INFO, "not ipv4 packet, ignore\n");
		return -1;
	}
	if (is_multicast_ether_addr(dest) == 0)
	{
		debug_msg(DEBUGMSG_INFO, "packet not multicast\n");
		return -1;
	}
	if (is_broadcast_ether_addr(dest))
	{
		debug_msg(DEBUGMSG_INFO, "ignore broadcast\n");
		return -1;
	}
	if ((skb->len) < 20) // at least there should be large than ip header
	{
		debug_msg(DEBUGMSG_NONE, "%s: skb len %d, ignore!\n", __FUNCTION__, skb->len);
		return -1;
	}	
	debug_msg(DEBUGMSG_TRACE, "INPUT Dev name : %s, skb->len:%d\n", skb->dev->name, skb->len);

	if (indev->name && strcmp(indev->name, LAN_LOG_IFNAME) == 0)
	{
		outdevname = WAN_PHY_IFNAME;
	} else if (indev->name && strcmp(indev->name, WAN_PHY_IFNAME) == 0)
	{
		outdevname = LAN_LOG_IFNAME;
	} else
	{
		outdevname = NULL;
		debug_msg(DEBUGMSG_INFO, "multicast packet %s\n", indev->name);
	}
	
	if (outdevname)
	{
		if (is_bt_igmp_packet(skb))
		{
			outdev = dev_get_by_name(&init_net, outdevname);
			if (outdev)
			{
				deliver_skb_by_if(skb, outdev);
				dev_put(outdev);
			} else
			{
				debug_msg(DEBUGMSG_INFO, "fail dev_get_by_name %s\n", indev->name);
			}
		} else
		{
			debug_msg(DEBUGMSG_INFO, "not bt_igmp packet\n");
		}
	}

	return 0;
}

static ssize_t bt_igmp_forward_read(struct file *filp, char __user *buf, 
								size_t count, loff_t * offp)
{
	char data[512];
	int len = 0;
	
	/*Only return a ZERO, this func will be stopped.*/
	if (*offp > 0)
	return 0;

	len = snprintf(data, sizeof(data), "config_done:%d\ngroup1_ip_addr:%x\nethwan_ip_addr:%x\nethwan_mac_addr:%x:%x:%x:%x:%x:%x\ngroup1_mac_addr:%x:%x:%x:%x:%x:%x\nforce_bt_igmp_packet:%d\ndebug_level:%x\n",
				config_done, group1_ip_addr, ethwan_ip_addr,
				ethwan_mac_addr[0], ethwan_mac_addr[1], ethwan_mac_addr[2], ethwan_mac_addr[3], ethwan_mac_addr[4], ethwan_mac_addr[5],
				group1_mac_addr[0], group1_mac_addr[1], group1_mac_addr[2], group1_mac_addr[3], group1_mac_addr[4], group1_mac_addr[5], 
				force_bt_igmp_packet,
				debug_level);
	if (copy_to_user(buf, data, len)) {
		return -EFAULT;
	}

	*offp = len;
	return len;
}

static ssize_t bt_igmp_forward_write(struct file *filp, const char *buffer,
                                   size_t count, loff_t * offp)
{
	char line[128];
	int ret;
	char *p = NULL;
	
	if ( count >= sizeof(line) ) {
		debug_msg(DEBUGMSG_NONE, "command too long.\n");
		return -EFAULT;
	}

	if (copy_from_user(line, buffer, count))
		return -EFAULT;
	
	if(count > 1)
		line[count-1] = 0;
	debug_msg(DEBUGMSG_NONE, "command: %s, len:%d\n", line, count);
	
	if (strstr(line, "debug="))
	{
		char *p = strchr(line, '=');
		if (p)
		{
			p = p+1;
			if (*p == '1')
				debug_level = 1;
			else if (*p == '2')
				debug_level = 2;
			else if (*p == '3')
				debug_level = 3;
			else 
				debug_level = 0;
		}
		debug_msg(DEBUGMSG_NONE, "set debug level %d\n", debug_level);
	} else if (strstr(line, "force=0"))
	{
		debug_msg(DEBUGMSG_NONE, "force off\n");
		force_bt_igmp_packet = 0;
	} else if (strstr(line, "force=1"))
	{
		debug_msg(DEBUGMSG_NONE, "force on\n");
		force_bt_igmp_packet = 1;
	} else
	{
		if (strstr(line, "."))
		{
			if ((p=strchr(line, ',')) !=NULL)
			{
				ethwan_ip_addr = in_aton(p+1);
				*p = 0;
				group1_ip_addr = in_aton(line);
			}
		}
		{
			struct net_device *_dev = dev_get_by_name(&init_net, WAN_PHY_IFNAME);
			if (_dev)
			{
				memcpy((void*)ethwan_mac_addr, _dev->dev_addr, ETH_ALEN);
				dev_put(_dev);
			}
			_dev = dev_get_by_name(&init_net, LAN_LOG_IFNAME);
			if (_dev)
			{
				memcpy((void*)group1_mac_addr, _dev->dev_addr, ETH_ALEN);
				dev_put(_dev);
			}		
		}
	}
	
	debug_msg(DEBUGMSG_NONE, "group1_ip_addr:%x, ethwan_ip_addr:%x. group1_mac_addr:%x:%x:%x:%x:%x:%x, ethwan_mac_addr:%x:%x:%x:%x:%x:%x\n", 
				group1_ip_addr, ethwan_ip_addr, 
				group1_mac_addr[0], group1_mac_addr[1], group1_mac_addr[2], group1_mac_addr[3], group1_mac_addr[4], group1_mac_addr[5],
				ethwan_mac_addr[0], ethwan_mac_addr[1], ethwan_mac_addr[2], ethwan_mac_addr[3], ethwan_mac_addr[4], ethwan_mac_addr[5]);
	if (ethwan_ip_addr && group1_ip_addr && is_valid_ether_addr(ethwan_mac_addr) && is_valid_ether_addr(group1_mac_addr))
	{
		config_done = 1;
		debug_msg(DEBUGMSG_NONE, "config done\n");
	}

	ret = count;

	return ret;
}

static struct file_operations fops = {
	.owner	= THIS_MODULE,
	.read	= bt_igmp_forward_read,
	.write	= bt_igmp_forward_write,
};


static int __init init (void)
{
	struct proc_dir_entry *file;
	
	printk("LAN_LOG_IFNAME:%s, WAN_PHY_IFNAME:%s\n", LAN_LOG_IFNAME, WAN_PHY_IFNAME);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	if(!(file = proc_create("bt_igmp_forward", 0666, init_net.proc_net, &fops)))
#else
	if(!(file = proc_net_fops_create(&init_net, "bt_igmp_forward", 0666, &fops)))
#endif
	{
		return -ENOMEM;
	}	

	bt_igmp_forward_hook = bt_igmp_forward_handler;
	return 0;
}

static void __exit fini (void)
{
	bt_igmp_forward_hook = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	remove_proc_entry("bt_igmp_forward", init_net.proc_net /* parent dir */);
#else
	proc_net_remove(&init_net, "bt_igmp_forward");
#endif
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
