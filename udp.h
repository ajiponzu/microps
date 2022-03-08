#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

// udpデータグラムの出力・送信
extern ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *buf, size_t len);

// udpの初期化. ipの上位プロトコルとして登録
extern int udp_init(void);

// ソケットオープン. コントロールブロックの確保と初期化(アプリケーション)
extern int udp_open(void);

// ソケットクローズ. コントロールブロックの解放(アプリケーション)
extern int udp_close(int id);

// ソケットバインド. アドレスとポートの紐づけ(アプリケーション)
extern int udp_bind(int index, struct ip_endpoint *local);

// send関数(アプリケーション)
extern ssize_t udp_sendto(int id, uint8_t *buf, size_t len, struct ip_endpoint *foreign);

// recv関数(アプリケーション)
extern ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign);

#endif