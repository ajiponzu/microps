#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

// udpデータグラムの出力・送信
extern ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *buf, size_t len);

// udpの初期化. ipの上位プロトコルとして登録
extern int udp_init(void);

#endif