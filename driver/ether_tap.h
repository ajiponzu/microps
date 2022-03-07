#ifndef ETHER_TAP_H
#define ETHER_TAP_H

#include "net.h"

// tapを生成し, デバイスのプライベートデータとして保持する
extern struct net_device *ether_tap_init(const char *name, const char *addr);

#endif