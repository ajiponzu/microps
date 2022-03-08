#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define IP_VERSION_IPV4 4

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60

#define IP_TOTAL_SIZE_MAX UINT16_MAX
#define IP_PAYLOAD_SIZE_MAX (IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN)

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 // "ddd.ddd.ddd.ddd\0"

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

typedef uint32_t ip_addr_t; // 型エイリアスを用いて, 32bit符号なし整数をアドレス型として定義

// IPインタフェース構造体
struct ip_iface
{
  struct net_iface iface; // インタフェース構造体
  struct ip_iface *next;  // 次のIPインタフェース構造体
  ip_addr_t unicast;      // ユニキャストアドレス
  ip_addr_t netmask;      // サブネットマスク
  ip_addr_t broadcast;    // ブロードキャストアドレス. ネットワークアドレスが共通のホスト全てが宛先となる
};

extern const ip_addr_t IP_ADDR_ANY;
extern const ip_addr_t IP_ADDR_BROADCAST;

// IPアドレスを, 文字列からネットワークバイトオーダーのバイナリ値(ビッグエンディアン, 見やすい)に変換
extern int ip_addr_pton(const char *p, ip_addr_t *n);

// IPアドレスを, ネットワークバイトオーダーのバイナリ値(ビッグエンディアン, 見やすい)から文字列に変換
extern char *ip_addr_ntop(ip_addr_t n, char *p, size_t size);

extern int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway);
extern struct ip_iface *ip_route_get_iface(ip_addr_t dst);

// IPインタフェース構造体のメモリ確保
extern struct ip_iface *ip_iface_alloc(const char *addr, const char *netmask);

// デバイスにIPインタフェースを登録. IPインタフェースリストにも追加
extern int ip_iface_register(struct net_device *dev, struct ip_iface *iface);

// ユニキャストアドレスからIPインタフェースを検索
extern struct ip_iface *ip_iface_select(ip_addr_t addr);

// データ送信
extern ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst);

// 上位プロトコルの登録
extern int ip_protocol_register(uint8_t type,
                                void (*handler)(const uint8_t *data, size_t len, ip_addr_t src,
                                                ip_addr_t dst, struct ip_iface *iface));

// ipの初期化
extern int ip_init(void);

#endif