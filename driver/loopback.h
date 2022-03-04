#ifndef LOOPBACK_H
#define LOOPBACK_H

#include "net.h"

// ループバックデバイスの初期化
extern struct net_device *loopback_init(void);

#endif