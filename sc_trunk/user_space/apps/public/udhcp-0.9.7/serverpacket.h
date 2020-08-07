#ifndef _SERVERPACKET_H
#define _SERVERPACKET_H

#ifdef GUEST_LEASE_TIME
int check_if_guest(struct dhcpMessage *oldpacket);
#endif

int sendOffer(struct dhcpMessage *oldpacket, int ifid);
int sendNAK(struct dhcpMessage *oldpacket, int ifid);
int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr, int ifid);
int send_inform(struct dhcpMessage *oldpacket, int ifid);
#ifdef TR069
void delete_vendor_list(u_int32_t caddr);
#endif

#endif