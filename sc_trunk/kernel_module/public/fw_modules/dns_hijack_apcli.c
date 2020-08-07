/*
 * dns_hijack.c 
 */

#define EXPORT_SYMTAB

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <asm/checksum.h>
#include <asm/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include "net/bridge/br_private.h"
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>

#define DNS_PORT 53
#define MESSAGE_LEN 256
#define IPADDR_LEN 16
#define IPHEAD_LEN 20
#define UDPHEAD_LEN 8
#define OFFSET 4
#define BRIDGE_NUM	3
#define DNS_TYPE_A 0x0001
#define DNS_TYPE_AAAA	0x001c

#ifdef Amped
const char dns_match[] = {0x05, 's', 'e', 't', 'u', 'p', 0x0d, 'a', 'm', 'p', 'e', 'd', 'w', 'i', 'r', 'e', 'l', 'e', 's', 's', 0x03, 'c', 'o', 'm', 0x00};
#else
const char dns_match_1[] = {0x03, 'w','w','w', 0x0b, 'r', 'o','u', 't', 'e', 'r','l', 'o', 'g', 'i', 'n', 0x03, 'c', 'o', 'm', 0x00};
const char dns_match_2[] = {0x0b, 'r', 'o', 'u', 't', 'e', 'r', 'l' ,'o', 'g', 'i', 'n', 0x03, 'c', 'o', 'm', 0x00};
const char dns_match_3[] = {0x03, 'w', 'w', 'w', 0x0b, 'r', 'o', 'u', 't','e','r', 'l', 'o', 'g', 'i', 'n', 0x03, 'n', 'e', 't', 0x00} ;
const char dns_match_4[] = {0x0b, 'r', 'o', 'u', 't','e','r', 'l', 'o', 'g', 'i', 'n', 0x03, 'n', 'e', 't', 0x00};
const char dns_match_5[] = {0x0a, 'r','e','a', 'd','y','s', 'h','a','r', 'e', 0x0b, 'r', 'o', 'u', 't','e','r', 'l', 'o', 'g', 'i', 'n', 0x03, 'n', 'e', 't', 0x00};
#endif

const char dns_match_apple[] = {0x05, 'a', 'p', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00};

//static struct dns_hijack_s DnsHijack;
extern int (*dns_hijack_hook)(struct sk_buff *);

struct dns_from_proc {
	char bridge_name[64];
	char dns_ip[16];
	char dns_ip6[64];
};

//static char test[256];

struct dns_from_proc dns_setting[BRIDGE_NUM];
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 13)
static DEFINE_RWLOCK(sc_dns_hj_lock);
#else
static rwlock_t sc_dns_hj_lock = RW_LOCK_UNLOCKED;
#endif

struct dns_tail_s {
	__be16 name;
	__be16 type;
	__be16 class;
	__be32 ttl;
	__be16 len;
	__be32 ans;
}__attribute__((__packed__));

struct v6_dns_tail_s {
	__be16 name;
	__be16 type;
	__be16 class;
	__be32 ttl;
	__be16 len;
	__u8   ans[16];
}__attribute__((__packed__));

struct dns_head_s {
	__be16 id;
	__be16 flag;
	__be16 quest_n;
	__be16 ans_n;
	__be16 author_n;
	__be16 addit_n;
}__attribute__((__packed__));

static inline void initial_dns_tail(__be32 dnsip, struct dns_tail_s *dns_tail)
{
	dns_tail->name = 0x0cc0;
	dns_tail->type = 0x0100;
	dns_tail->class = 0x0100;
	dns_tail->ttl = 0x01000000;
	dns_tail->len = 0x0400;
	dns_tail->ans = dnsip;
}

static inline void initial_v6_dns_tail(struct in6_addr *addr, struct v6_dns_tail_s *v6_dns_tail)
{
	v6_dns_tail->name = 0x0cc0;
	v6_dns_tail->type = 0x1c00;
	v6_dns_tail->class = 0x0100;
	v6_dns_tail->ttl = 0x01000000;

	if (addr) 
	{
		v6_dns_tail->len = 0x1000;
		ipv6_addr_copy((struct in6_addr *)&v6_dns_tail->ans[0], addr);
	}
	else
	{
		v6_dns_tail->len = 0;
	}
}

static inline void initial_dns_head(const char *buf, struct dns_head_s *dns_head)
{
	dns_head->id = *((__be16 *)buf);
	dns_head->flag = 0x0080;
	dns_head->quest_n = 0x0100;
	dns_head->ans_n = 0x0100;
	dns_head->author_n = 0x0000;
	dns_head->addit_n = 0x0000;
}


/*struct single_if_info {
	char name[16];
	struct net_device *dev;
	struct single_if_info *next;
};

struct dns_hjctl_header {
	spinlock_t lock;
	struct single_if_info *head;
};


static struct dns_hjctl_header dns_hjctl_head_obj;

static struct single_if_info *looup_if_byaddr_inlist(struct dns_hjctl_header *dns_ctl, const struct net_device *indev)
{
	struct single_in_info *dnsif;
	dnsif = dns_ctl->head;
	while(dnsif)
	{
		if(dnsif->dev && dnsif->dev == indev)
		{
			return dns_if;
		}
		dnsif = dnsif->next;
	}
	return NULL;
}

static struct single_if_info *lookup_if_byname_inlist(struct dns_hjctl_header *dns_ctl, const char *name)
{
	struct single_if_info  *dnsif;
	dnsif = dns_ctl->head;
	while(dnsif)
	{
		if(strcmp(dnsif->name, name) == 0)
		{
			return dns_if;
		}
		dns_if = dns_if->next;
	}
	return NULL;
}*/
static inline void initial_iphd(const struct iphdr *recv_iphd, struct iphdr *dns_iphd, u16 iplen)
{
	dns_iphd->ihl = recv_iphd->ihl;
	dns_iphd->version = recv_iphd->version;
	dns_iphd->tos = 0;
	dns_iphd->tot_len = htons(iplen);
	dns_iphd->id = 0x0100;
	dns_iphd->frag_off = 0x0040;
	dns_iphd->ttl = 0x40;
	dns_iphd->protocol = IPPROTO_UDP;
	dns_iphd->saddr = recv_iphd->daddr;
	dns_iphd->daddr = recv_iphd->saddr;
	dns_iphd->check = 0;
	dns_iphd->check = ip_fast_csum((u8 *)dns_iphd, dns_iphd->ihl);
}

static inline void initial_ip6hdr(const struct ipv6hdr *recv_iphd, struct ipv6hdr *dns_ip6hd, u16 payload_len)
{
	memcpy((u8 *)dns_ip6hd, (u8 *)recv_iphd, 4);
	dns_ip6hd->version = 6;
	dns_ip6hd->hop_limit = 1;
	dns_ip6hd->nexthdr = IPPROTO_UDP;
	dns_ip6hd->payload_len = htons(payload_len);
	ipv6_addr_copy(&dns_ip6hd->saddr, &recv_iphd->daddr);
	ipv6_addr_copy(&dns_ip6hd->daddr, &recv_iphd->saddr);
}

static inline void initial_udphd(const struct udphdr *recv_udphd, struct udphdr *dns_udphd, 
	const struct iphdr *dns_iphd, const struct ipv6hdr *dns_ip6hd, 
	u16 udplen, __wsum data_csum, struct ipv6hdr *recv_ip6hdr)
{
	dns_udphd->source = recv_udphd->dest;
	dns_udphd->dest = recv_udphd->source;
	dns_udphd->len = htons(udplen);
	dns_udphd->check = 0;
	data_csum = csum_partial((u8 *)dns_udphd, 8, data_csum);

	/* whether it is IPv6 */
	if (recv_ip6hdr) 
		dns_udphd->check = csum_ipv6_magic(&dns_ip6hd->saddr, &dns_ip6hd->daddr,
				udplen, IPPROTO_UDP, data_csum);
	else
		dns_udphd->check = csum_tcpudp_magic(dns_iphd->saddr, dns_iphd->daddr, 
			udplen, IPPROTO_UDP, data_csum);
}

static void cup_destroy(struct sk_buff *skb)
{
	dev_put(skb->dev);
}

static inline void initial_dns_skb(struct sk_buff *dns_skb, struct net_device *dev, __be16 protocol)
{
	dns_skb->dev = dev;
	dns_skb->pkt_type = PACKET_OTHERHOST;
	dns_skb->ip_summed = CHECKSUM_NONE;
	dns_skb->destructor = cup_destroy;
	dns_skb->priority = 0;
	dns_skb->protocol = protocol; //htons(ETH_P_IP);
}

int deliver_dns_skb(struct sk_buff *dns_skb)
{
	int num;
	struct net_device *dev;
	
	dev = dns_skb->dev;
	if((num = dev_queue_xmit(dns_skb))<0) {
		kfree(dns_skb);
		dev_put(dev);
		printk("dev_xmit error\n");
		return -1;
		}
		//printk("dev_ximt sucess\n");
	return num;
}

static int get_dev_ipv6_addr(struct net_device *dev, struct in6_addr *addr)
{
	int ret = 0;
	struct inet6_dev *idev;
	rcu_read_lock();
	idev = in6_dev_get(dev);
	if (idev)
	{
		struct inet6_ifaddr *ifp;
		read_lock_bh(&idev->lock);
		list_for_each_entry(ifp, &idev->addr_list, if_list)
		{
			if (!(ifp->flags & IFA_F_TENTATIVE) && ipv6_addr_src_scope(&ifp->addr) == IPV6_ADDR_SCOPE_LINKLOCAL)
			{
				ipv6_addr_copy(addr, &ifp->addr);
				ret = 1;
				break;
			}
		}
		read_unlock_bh(&idev->lock);
	}
	rcu_read_unlock();
	return ret;
}

static int
get_ipv6_addr(const char *src, size_t dlen, struct in6_addr *dst, u_int8_t term)
{
        const char *end;
        int ret = in6_pton(src, min_t(size_t, dlen, 0xffff), (u8 *)dst, term, &end);
        if (ret > 0)
                return (int)(end - src);
        return 0;
}

static struct udphdr *get_udphdr_from_ipv6(struct sk_buff *skb, struct ipv6hdr * ip6hdr)
{
	int offset;
	u8 nexthdr = ip6hdr->nexthdr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	offset = ipv6_skip_exthdr(skb, sizeof(*ip6hdr),           
			&nexthdr, &frag_off);    
#else
	offset = ipv6_skip_exthdr(skb, sizeof(*ip6hdr),           
			&nexthdr);    
#endif
	if (offset < 0)
	{
		printk("%s:%d ERROR: Can not find IPv6 header!\n", __func__, __LINE__);
		return NULL;
	}

	if (nexthdr != IPPROTO_UDP)
	{
		return NULL;
	}

	if (!pskb_may_pull(skb, (skb_network_header(skb) +                                                              
					offset + 1 - skb->data)))                             
	{
		return NULL;
	}

	return (struct udphdr *)(skb_network_header(skb) + offset);
}


#define DNS_SRCIP_FOR_ATTACHDEVICE_NUM 255
unsigned int dns_srcip_for_attachdevice[DNS_SRCIP_FOR_ATTACHDEVICE_NUM] = {0};
int dns_srcip_for_attachdevice_reading = 0;

void dns_srcip_for_attachdevice_save(unsigned int srcip)
{
	if (srcip)
	{
		int i = 0;
		for(i=0; i<DNS_SRCIP_FOR_ATTACHDEVICE_NUM; i++)
		{
			if (dns_srcip_for_attachdevice[i] == srcip)
			{
				//printk("dns ip 0x%x exist %d\n", srcip, i);
				return;
			} else
			{
				if (dns_srcip_for_attachdevice[i] == 0)
				{
					dns_srcip_for_attachdevice[i] = srcip;
					printk("dns ip 0x%x %d\n", srcip, i);
					return;
				} else
				{
					if (i == (DNS_SRCIP_FOR_ATTACHDEVICE_NUM-1))
					{
						printk("save ip full 0x%x\n", srcip);
					}
				}
			}
		}
	}
}

extern accessctl_listen_in_kernel accessctl_listen_forward_cb;

static int dns_hijack_handle(struct sk_buff *skb)
{
	int ret, query_len;
	struct udphdr *recv_udphd = NULL;
	struct iphdr *recv_iphd = NULL;
	struct ethhdr *recv_ethhd = NULL;
	struct net_device *dev = NULL;
	unsigned char *recv_data = NULL;
	unsigned char *query_name = NULL;
	unsigned char *p_type = NULL;
	struct net_device *br_dev = NULL;

	u16 datalen, iplen, udplen, skblen, recv_udplen, query_type;
	struct dns_tail_s dns_tail;
	struct v6_dns_tail_s v6_dns_tail;
	struct dns_head_s dns_head;
	struct iphdr dns_iphd;
	struct ipv6hdr dns_ip6hd;
	struct udphdr dns_udphd;
	struct ethhdr dns_ethhd;

	struct net_bridge_port *br_port;
			
	struct sk_buff *dns_skb = NULL;
	u8 dns_data[512];
	__be32 dns_ans;
	__wsum data_csum;

	struct ipv6hdr *recv_ip6hdr = NULL;

	int access_block = 0;

	recv_ethhd = eth_hdr(skb);

	if (skb->protocol == htons(ETH_P_IPV6))
	{
		recv_ip6hdr = (struct ipv6hdr *)(skb->data);
		recv_udphd = get_udphdr_from_ipv6(skb, recv_ip6hdr);
	}
	else
	{
		recv_iphd = (struct iphdr *)(skb->data);
		if(recv_iphd->protocol == IPPROTO_UDP)
			recv_udphd = (struct udphdr *)(skb->data + IPHEAD_LEN);
	}
	  
	if(recv_udphd)
	{
		
		if(ntohs(recv_udphd->dest) == DNS_PORT)
		{
			data_csum = 0;
	
			dev = skb->dev;

			if((recv_udplen = ntohs(recv_udphd->len))<20) {
				printk(KERN_ALERT "incorrect dns packet. \n");
				return 0;
			}
			
			if (dns_srcip_for_attachdevice_reading)
			{
				printk(KERN_ALERT "dns srcip for attachdevice reading, not save for this packet\n");
			} else
			{
				dns_srcip_for_attachdevice_save(ntohl(recv_iphd->saddr));
			}

			recv_data = (unsigned char *) recv_udphd + UDPHEAD_LEN;
			query_name = recv_data + 12;

			br_port = br_port_get_rcu(skb->dev);

			if(accessctl_listen_forward_cb)
				access_block = accessctl_listen_forward_cb(skb);

			if(
#ifdef Amped			
			strcmp(query_name, dns_match) == 0 || (br_port && strcmp(br_port->br->dev->name, "group1") == 0 && strstr(query_name, dns_match_apple))
#else
			(access_block || strcmp(query_name, dns_match_1) == 0 || strcmp(query_name, dns_match_2) == 0  || strcmp(query_name, dns_match_3) == 0 || strcmp(query_name, dns_match_4) == 0 || strcmp(query_name, dns_match_5) == 0 )
#endif			
			) {
				int i, found = 0;
				query_len = strlen(query_name) + 1;
				p_type = query_name + query_len;
				memcpy(&query_type, p_type, 2);
				memcpy(&dns_data[12], query_name, recv_udplen -20);
				initial_dns_head(recv_data, &dns_head);
				memcpy(dns_data, &dns_head, sizeof(dns_head));
				/* handle dns query for ipv6 address */
				if (ntohs(query_type) == DNS_TYPE_AAAA)
				{
					struct in6_addr dns_ans6;
					int length = 0;
					//printk("info: Received interested AAAA DNS query from dev %s\n", 
					//	br_port->br->dev->name);
					
					/* check profile */
					read_lock_bh(&sc_dns_hj_lock);
					for (i = 0; i < BRIDGE_NUM; i++)
					{	
						br_dev = br_port->br->dev;
						length = get_ipv6_addr(dns_setting[i].dns_ip6, 64, &dns_ans6, '\n');
						if (strcmp(dns_setting[i].bridge_name, br_dev->name) == 0 && length > 0)
						{
							//printk("info: Get IPv6 address %pI6 from profile.\n", &dns_ans6);
							found = 1;
							break;
						}
					}
					read_unlock_bh(&sc_dns_hj_lock);

					/* check dev */
					if (!found)
					{
						//printk("info: not found in profile, check dev.\n");
						if (get_dev_ipv6_addr(br_dev, &dns_ans6) > 0)
						{
							found = 1;
							//printk("info: Get IPv6 address %pI6 from dev %s, update profile.\n", &dns_ans6, br_dev->name);
							/* update profile */
							write_lock_bh(&sc_dns_hj_lock);
							sprintf(dns_setting[0].dns_ip6, "%pI6", &dns_ans6);
							write_unlock_bh(&sc_dns_hj_lock);
						}
						else
						{
							//printk("info: also not found in dev.\n");
						}
					}

					/* whether we have answer for IPv6 address. */
					if (found)
					{
						//printk("info: DNS matched and IPv6 address is available!\n");
						initial_v6_dns_tail(&dns_ans6, &v6_dns_tail);
						memcpy(&dns_data[recv_udplen - 8], &v6_dns_tail, sizeof(v6_dns_tail));
						udplen = recv_udplen + sizeof(v6_dns_tail);
					}
					else
					{ 
						//printk("info: no IPv6 address result, create empty DNS response.\n");
						initial_v6_dns_tail(NULL, &v6_dns_tail);
						memcpy(&dns_data[recv_udplen - 8], &v6_dns_tail, sizeof(v6_dns_tail) - sizeof(struct in6_addr));
						udplen = recv_udplen + sizeof(v6_dns_tail) - sizeof(struct in6_addr);
					}
				}
				else
				{
					read_lock_bh(&sc_dns_hj_lock);
					// printk("Received Packet from dev %s\n", br_port->br->dev->name);
					for (i = 0; i < BRIDGE_NUM; i++)
					{	
						found = 0;
						br_dev = br_port->br->dev;
						dns_ans = in_aton(dns_setting[i].dns_ip);
						if (strcmp(dns_setting[i].bridge_name, br_dev->name) == 0 && dns_ans != 0)
						{
							initial_dns_tail(dns_ans, &dns_tail);
							found = 1;
							break;
						}
					}
					read_unlock_bh(&sc_dns_hj_lock);
					if (found == 0)
					{
						goto error;
					}
					memcpy(&dns_data[recv_udplen - 8], &dns_tail, sizeof(dns_tail));
	
					udplen = recv_udplen + sizeof(dns_tail);
				}
				
				if (recv_ip6hdr)
					iplen = udplen + sizeof(struct ipv6hdr);
				else
					iplen = udplen + IPHEAD_LEN;

				datalen = udplen - UDPHEAD_LEN;

				memcpy(dns_ethhd.h_dest, recv_ethhd->h_source, ETH_ALEN);
				memcpy(dns_ethhd.h_source, recv_ethhd->h_dest, ETH_ALEN);
				dns_ethhd.h_proto = recv_ethhd->h_proto;
					
				if (recv_ip6hdr)
					initial_ip6hdr(recv_ip6hdr, &dns_ip6hd, udplen);
				else 
					initial_iphd(recv_iphd, &dns_iphd, iplen);
	
				data_csum = csum_partial(dns_data, datalen, 0);

				initial_udphd(recv_udphd, &dns_udphd, &dns_iphd, &dns_ip6hd, 
					udplen, data_csum, recv_ip6hdr);

				skblen = iplen + ETH_HLEN + LL_RESERVED_SPACE(dev);

				if((dns_skb = alloc_skb(skblen, GFP_ATOMIC)) == NULL)
				{
					printk(KERN_ALERT "Memory low\n");
					return -1; //NOMEM
				} 
	
				initial_dns_skb(dns_skb, dev, skb->protocol);
				
				skb_reserve(dns_skb, ETH_HLEN);
	
				memcpy(skb_push(dns_skb, ETH_HLEN), (u8 *)(&dns_ethhd), ETH_HLEN);

				if (recv_ip6hdr)
				{
					dns_skb->network_header = skb_put(dns_skb, sizeof(struct ipv6hdr));

					memcpy(dns_skb->network_header, (u8 *)(&dns_ip6hd), sizeof(struct ipv6hdr));
				}
				else
				{
					dns_skb->network_header = skb_put(dns_skb, sizeof(struct iphdr));

					memcpy(dns_skb->network_header, (u8 *)(&dns_iphd), sizeof(struct iphdr));
				}

				dns_skb->transport_header = skb_put(dns_skb, sizeof(struct udphdr));
				memcpy(dns_skb->transport_header, (u8 *)(&dns_udphd), sizeof(struct udphdr));
	
				memcpy(skb_put(dns_skb, datalen), dns_data, datalen);
/*	
				printk("skb->network_header = %p\n", dns_skb->network_header);
				printk("skb->data = %p\n", dns_skb->data);
				printk("skb->tail = %p\n", dns_skb->tail);
				printk("skb->tail = %p\n", dns_skb->tail);
*/				

				ret = deliver_dns_skb(dns_skb);

				if(ret > 0)
					return ret;
				else
error:
					return -1;
			}
		}
	}	
	return 0;
}		

static ssize_t dns_hijack_read(struct file *flip, char __user *buf, size_t count, loff_t *offp)
{
	char data[MESSAGE_LEN];
	int len =0, i;
	if(*offp>0)
	return 0;

	read_lock_bh(&sc_dns_hj_lock);
	for (i = 0; i < BRIDGE_NUM; i++) {
		if (strlen(dns_setting[i].bridge_name) > 0)
			len += sprintf(data + len, "%s %s %s\n", dns_setting[i].bridge_name, 
				dns_setting[i].dns_ip, dns_setting[i].dns_ip6);
	}
	read_unlock_bh(&sc_dns_hj_lock);

	if(copy_to_user(buf, data, len)) {
		return -EFAULT;
	}
	*offp = len;

	return len;
}

static ssize_t dns_srcip_for_attachdevice_read(struct file *flip, char __user *buf, size_t count, loff_t *offp)
{
	char data[100*11];
	int len =0, i;
	if(*offp>0)
	return 0;
	
	dns_srcip_for_attachdevice_reading = 1;
	memset(data, 0, sizeof(data));
	for (i = 0; i < DNS_SRCIP_FOR_ATTACHDEVICE_NUM; i++) 
	{
		if (dns_srcip_for_attachdevice[i])
		{
			len += sprintf(data + len, "0x%x#", dns_srcip_for_attachdevice[i]);
			if (len > (sizeof(data)-100))
			{
				printk("client ip many\n");
				break;
			}
		}
	}
	dns_srcip_for_attachdevice_reading = 0;
	
	if(copy_to_user(buf, data, len)) {
		return -EFAULT;
	}
	*offp = len;

	return len;
}

static int read_info(char *src, char *name, char *ip, char *ip6)
{
	int i = 0;
/* go to the name part */
	while (*src != ' ' && *src != '\0' && i < 64) {
		*name++ = *src++;
		i++;
	}
/* go to the ip part */
	while (*src == ' ')
		src++;

	i = 0;
	while (((*src <= '9' && *src >= '0') || *src == '.') && i < 16) {
		*ip++ = *src++;
		i++;
	}
	
	*name = '\0';
	*ip = '\0';

/* go to the ipv6 part */
	while (*src == ' ')
		src++;

	i = 0;
	while (((*src <= '9' && *src >= '0') || (*src <= 'f' && *src >= 'a') || *src == ':') && i < 64) {
		*ip6++ = *src++;
		i++;
	}
	*ip6 = '\0';

	return 0;
}

static ssize_t dns_hijack_write(struct file *filp, const char *buffer, size_t count, loff_t *offp)
{
	int i, exist = 0, ret;
	char buf[256];
	char dns_ip[256] = "";
	char dns_ip6[256] = "";
	char br_name[256] = "";

	if (count > 255) {
		printk(KERN_ALERT "Arguments too long\n");
		return -EFAULT;
	}
	if(copy_from_user(buf, buffer, count)) {
		printk(KERN_ALERT "Can't get dns ip\n");
		return -EFAULT;
	}

	memset(dns_ip, 0, sizeof(dns_ip));
	memset(dns_ip6, 0, sizeof(dns_ip6));

	read_info(buf, br_name, dns_ip, dns_ip6);
	write_lock_bh(&sc_dns_hj_lock);
	// sscanf(line, "%[^ ]%s", br_name, dns_ip);
	for (i = 0; i < BRIDGE_NUM; i++)
	{
		printk(KERN_ALERT "br_name = %s, dns_ip = %s, dns_ip6 = %s\n", br_name, dns_ip, dns_ip6);
		if (strncmp(br_name, dns_setting[i].bridge_name, 64) == 0)
		{
			strncpy(dns_setting[i].dns_ip, dns_ip, 16);
			dns_setting[i].dns_ip[15] = '\0';
			strncpy(dns_setting[i].dns_ip6, dns_ip6, 64);
			dns_setting[i].dns_ip6[63] = '\0';
			exist = 1;
			break;
		}
	}
	if (exist == 0) {
		for (i = 0; i < BRIDGE_NUM; i++)
		{
			if (strlen(dns_setting[i].bridge_name) == 0)
			{
				strncpy(dns_setting[i].bridge_name, br_name, 64);
				dns_setting[i].bridge_name[63] = '\0';
				strncpy(dns_setting[i].dns_ip, dns_ip, 16);
				dns_setting[i].dns_ip[15] = '\0';
				strncpy(dns_setting[i].dns_ip6, dns_ip6, 64);
				dns_setting[i].dns_ip6[63] = '\0';
				break;
			}
		}
	}
	write_unlock_bh(&sc_dns_hj_lock);
	ret = count;
	return ret;	
}		

static ssize_t dns_srcip_for_attachdevice_write(struct file *filp, const char *buffer, size_t count, loff_t *offp)
{
	int ret;
	char buf[256];

	if (count > 255) {
		printk(KERN_ALERT "Arguments too long\n");
		return -EFAULT;
	}
	if(copy_from_user(buf, buffer, count)) {
		printk(KERN_ALERT "Can't get dns ip\n");
		return -EFAULT;
	}

	ret = count;
	return ret;	
}		

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = dns_hijack_read,
	.write = dns_hijack_write,
};

static struct file_operations fops_dns_srcip_for_attachdevice = {
	.owner = THIS_MODULE,
	.read = dns_srcip_for_attachdevice_read,
	.write = dns_srcip_for_attachdevice_write,
};

/*static struct notifier_block if_netdev_notifier = {
	.notifier_call = if_netdev_event,
};*/

static int __init dns_hijack_init(void)
{
	struct proc_dir_entry *proc_file;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	if(!(proc_file = proc_create("dns_hijack_apcli", 0666, init_net.proc_net, &fops)))
#else
	if(!(proc_file = proc_net_fops_create(&init_net, "dns_hijack_apcli", 0666, &fops)))
#endif
	{
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	if(!(proc_file = proc_create("dns_hijack_apcli_for_attachdevice", 0666, init_net.proc_net, &fops_dns_srcip_for_attachdevice)))
#else
	if(!(proc_file = proc_net_fops_create(&init_net, "dns_hijack_apcli_for_attachdevice", 0666, &fops_dns_srcip_for_attachdevice)))
#endif
	{
		return -ENOMEM;
	}


	write_lock_bh(&sc_dns_hj_lock);
	memset(dns_setting, 0, sizeof(dns_setting));
	write_unlock_bh(&sc_dns_hj_lock);

	dns_hijack_hook = dns_hijack_handle;
	printk(KERN_ALERT "dns_hijack_module installed.\n");
	
	return 0;
}
static void __exit dns_hijack_cleanup(void)
{
	dns_hijack_hook = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	remove_proc_entry("dns_hijack_apcli", init_net.proc_net /* parent dir */);
#else
	proc_net_remove(&init_net, "dns_hijack_apcli");
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,13)
	remove_proc_entry("dns_hijack_apcli_for_attachdevice", init_net.proc_net /* parent dir */);
#else
	proc_net_remove(&init_net, "dns_hijack_apcli_for_attachdevice");
#endif
	printk(KERN_ALERT "dns_hijack_module removed.\n");
}

module_init(dns_hijack_init);
module_exit(dns_hijack_cleanup);
MODULE_LICENSE("GPL");
