/*
 * Copyright (c) 2018 SerComm Corporation. All Rights Reserved.
 *
 * SERCOMM CORPORATION RESERVES THE RIGHT TO MAKE CHANGES TO THIS DOCUMENT
 * WITHOUT NOTICE. SERCOMM CORPORATION MAKES NO WARRANTY, REPRESENTATION OR
 * GUARANTEE REGARDING THE SUITABILITY OF ITS PRODUCTS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * SERCOMM CORPORATION ASSUMES NO LIABILITY ARISING OUT OF THE APPLICATION OR
 * USE OF ANY PRODUCT OR CIRCUIT.
 *
 * SERCOMM CORPORATION SPECIFICALLY DISCLAIMS ANY AND ALL LIABILITY, INCLUDING
 * WITHOUT LIMITATION CONSEQUENTIAL OR INCIDENTAL DAMAGES; NEITHER DOES IT CONVEY
 * ANY LICENSE UNDER ITS PATENT RIGHTS, NOR THE RIGHTS OF OTHERS.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/version.h>
#include "if_name.h"

MODULE_LICENSE("Sercomm Corporation");
MODULE_DESCRIPTION("Make blocked devices unable to access network resource");

/* Uncomment the next line if you want to output debug message */
//#define ACCESSCTL_DEBUG
#ifdef ACCESSCTL_DEBUG
#define DEBUG_PRI                   (2)
#define KDEBUG(pri, format, ...)    printk("<%d>"format, pri, ##__VA_ARGS__)
#else
#define KDEBUG(pri, format, ...)
#endif

#define MACADDR_BUF_SIZE    (18)
#define MACADDR_MAX_ENTRY    (80)//calculated by nvram value max length
#define BOOTP_SERVER_PORT           (0x0043)
#define BOOTP_CLIENT_PORT           (0x0044)

extern accessctl_listen_in_kernel accessctl_listen_forward_cb;

static char block_mac_list[MACADDR_MAX_ENTRY][MACADDR_BUF_SIZE] = {{0}};
static int block_state;
static int total_entry;
static int need_bypass_dhcp_arp;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
static int _accessctl_proc_read(char *buffer, char **start, off_t offset, int length, int *eof, void *data);
#else
static int accessctl_proc_read(char *buffer, char **start, off_t offset, int length, int *eof, void *data);
static int accessctl_proc_write(struct file *file, const char __user *buf, unsigned long count, void *data);
#endif

/*
 * @brief:
 *      Get IP packet's port number.
 */
static int get_packet_ports(struct sk_buff *skb,
                            unsigned short *src_port,
                            unsigned short *dest_port)
{
	char *udp_h = skb->data + ((ip_hdr(skb))->ihl) * sizeof(unsigned long);
	struct udphdr *head = (struct udphdr *)udp_h;

	*src_port = head->source;
	*dest_port = head->dest;

	return 0;
}

/*
 * @return:
 *      return 1 - this module is not setup completely, not check anything.
 *      return 0 - this module is setup OK, will do packet check.
 */
static inline int check_module_state(void)
{
	if(block_state == -1 || total_entry == -1){
		KDEBUG(DEBUG_PRI,"this module is not setup properly!\n");
		return 1;
	}
	return 0;
}
/*
 * @return:
 *      return 1 - packet is from the interface that we don't check. need pass up.
 *      return 0 - packet is from the interface that we need check.
 */
static inline int check_interface(struct sk_buff *skb)
{
	KDEBUG(DEBUG_PRI,"skb->skb_iif = %d, skb->dev->name = %s", skb->skb_iif, skb->dev->name);
	if(strstr(skb->dev->name,"ra") || strcmp(skb->dev->name, LAN_PHY_IFNAME) == 0){
		return 0;
	}
    return 1;
}
/*
 * @return:
 *      return 1 - packet is not from blocked mac, need pass up.
 *      return 0 - packet is from blocked mac, need drop.
 */
static inline int check_mac_addr(struct sk_buff *skb)
{
	int i=0;
	char buf[MACADDR_BUF_SIZE];
	u8 addr[MACADDR_BUF_SIZE];
	struct ethhdr *eth;
	
	eth=(struct ethhdr *)skb_mac_header(skb);
	memcpy(addr,eth->h_source,6);
	sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
	KDEBUG(DEBUG_PRI,"skb souce mac = %s", buf);
	if(*buf=='\0')
		return 1;

	if(block_state == 1){	//black-list
		while(i <= total_entry){
			if(strncasecmp(block_mac_list[i],buf,17) == 0)
				return 0;
			i++;
		}
		return 1;
	}else if(block_state == 0){	//white-list
		while(i <= total_entry){
			if(strncasecmp(block_mac_list[i],buf,17) == 0)
				return 1;
			i++;
		}
		return 0;
	}
    return 1;//should not be here.
}

/* @brief:
 * 		 Additional check in AP/Bridge Mode, let DHCP/ARP packet pass.
 * @return:
 *      return 1 - packet is DHCP/ARP packet, need pass up.
 *      return 0 - packet is not DHCP/ARP packet, need drop.
 */
static inline int check_packet_type(struct sk_buff *skb)
{
	if(skb->protocol == __constant_htons(ETH_P_IP))  /* IP packet */
    {
		unsigned short s_port = 0, d_port = 0;
		struct iphdr *iph = ip_hdr(skb);
		if(skb->network_header && iph && (iph->protocol==IPPROTO_UDP))
		{
			get_packet_ports(skb, &s_port, &d_port);
			if(s_port == __constant_ntohs(BOOTP_CLIENT_PORT)
				&& d_port ==  __constant_ntohs(BOOTP_SERVER_PORT))
			{
				KDEBUG(DEBUG_PRI, "This is a bootp packet\n");
				return 1;
			}
		}
    }
	else if(skb->protocol == __constant_htons(ETH_P_ARP)) /* ARP packet */
    {
		KDEBUG(DEBUG_PRI, "This is a ARP packet\n");
        return 1;
    }
    else if(skb->protocol == __constant_htons(ETH_P_RARP)) /* RARP packet */
    {
		KDEBUG(DEBUG_PRI, "This is a RARP packet\n");
        return 1;
    }
	return 0;
}

/*
 * @brief:
 *      Do filter to all forward packets.
 * @return:
 *      return 1 - This packet should be discard.
 *      return 0 - This packet should be passed up.
 */
int forward_packet_filter(struct sk_buff *skb)
{
	if(check_module_state())
	{
		return 0;
	}
	if(check_interface(skb))
	{
		return 0;
	}
	if(check_mac_addr(skb))
	{
		return 0;
	}
	// Additional check in AP/Bridge Mode, let DHCP/ARP packet pass.
	if(need_bypass_dhcp_arp == 1 && check_packet_type(skb))
	{
		return 0;
	}
	KDEBUG(DEBUG_PRI,"block!");
	return 1;
}

/*
 * @brief:
 *      Show current module global variable info when you cat /proc/accessctl_block
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
static ssize_t accessctl_proc_read(struct file *file, char __user *user, size_t count, loff_t *f_pos)
{
	int len = 0;
	int i_ret = 0;
	char buf[512];

	if (*f_pos > 0) {
		len = 0;
	} else {
		len = _accessctl_proc_read(buf, NULL, 0, 0, NULL, NULL);
		i_ret = copy_to_user(user, buf, len);
		if (i_ret) {
			printk("copy to buffer failed, ret:%d\n", i_ret);
			len = -EFAULT;
			goto err_exit;
		}
		*f_pos += len;
	}
err_exit:
	return len;
}
static int _accessctl_proc_read(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
#else
static int accessctl_proc_read(char *buffer, char **start, off_t offset, int length, int *eof, void *data)
#endif
{
    int size = 0;
    int i = 0;

    size += sprintf(buffer+size, "block_state=%d\n",block_state);
    size += sprintf(buffer+size, "total_entry=%d\n",total_entry);
    size += sprintf(buffer+size, "need_bypass_dhcp_arp=%d\n",need_bypass_dhcp_arp);
    while(i <= total_entry){
		size += sprintf(buffer+size, "block_mac_list[%d]=%s\n", i, block_mac_list[i]);
		i++;
	}   

    return size;
}

/*
 * @brief:
 *      Set current module global variable info when you echo to /proc/accessctl_block
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
static ssize_t accessctl_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
#else
static int accessctl_proc_write(struct file *file,
                                   const char __user *buf,
                                   unsigned long count,
                                   void *data)
#endif
{
    char line[256];
    ssize_t size;
    int idx = 0;
    char block_mac[20] = {0};

    size = (count >= sizeof(line)) ? (sizeof(line) - 1) : count;
    copy_from_user(line, buf, size);
    line[size] = '\0';
    if(sscanf(line, "need_bypass_dhcp_arp=%u", &need_bypass_dhcp_arp) == 1)
    {
        KDEBUG(DEBUG_PRI, "get need_bypass_dhcp_arp=%u\n", need_bypass_dhcp_arp);
    }
    if(sscanf(line, "block_state=%u", &block_state) == 1){
		KDEBUG(DEBUG_PRI, "get block_state=%u\n", block_state);
    }
    if(sscanf(line, "block_list=%u-%20s", &idx, block_mac) == 2){
		if(idx < MACADDR_MAX_ENTRY){
			strcpy(block_mac_list[idx], block_mac);
			KDEBUG(DEBUG_PRI, "get block_list(%d)=%s\n", idx, block_mac_list[idx]);
			if(total_entry < idx){
				total_entry = idx;
			}
		}
    }
    return size;
}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
static const struct file_operations accessctl_fops= {
	.read		= accessctl_proc_read,
	.write		= accessctl_proc_write
};
#endif
static int __init accessctl_block_init(void)
{
    struct proc_dir_entry *entry_accessctl;

    /* Init global value, set default value */
    need_bypass_dhcp_arp = -1;
    block_state = -1;
    total_entry = -1;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
    entry_accessctl = proc_create("accessctl_block", S_IRUSR, NULL, &accessctl_fops);
#else
    entry_accessctl = create_proc_entry("accessctl_block", S_IRUSR, NULL);
    if(entry_accessctl){
        entry_accessctl->read_proc = accessctl_proc_read;
        entry_accessctl->write_proc = accessctl_proc_write;
    }
#endif
    accessctl_listen_forward_cb = forward_packet_filter;

	return 0;
}

static void __exit accessctl_block_exit(void)
{
    accessctl_listen_forward_cb = NULL;
    remove_proc_entry("accessctl_block", 0);
}

module_init(accessctl_block_init);
module_exit(accessctl_block_exit);
