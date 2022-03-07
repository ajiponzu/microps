#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include "net.h"
#include "ip.h"

#define ARP_RESOLVE_ERROR -1
#define ARP_RESOLVE_INCOMPLETE 0
#define ARP_RESOLVE_FOUND 1

// arp要求の解決
extern int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha);

// arpの初期化
extern int arp_init(void);

#endif