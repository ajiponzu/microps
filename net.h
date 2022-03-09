#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#ifndef IFNASMSIZ
#define IFNASMSIZ 16
#endif

#define NET_DEVICE_TYPE_DUMMY 0x0000
#define NET_DEVICE_TYPE_LOOPBACK 0x0001
#define NET_DEVICE_TYPE_ETHERNET 0x0002

#define NET_DEVICE_FLAG_UP 0x0001
#define NET_DEVICE_FLAG_LOOPBACK 0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P 0x0040
#define NET_DEVICE_FLAG_NEED_ARP 0x0100

#define NET_DEVICE_ADDR_LEN 16

/* Cプリプロセッサマクロによる高速化 */
#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")
/* end */

#define NET_PROTOCOL_TYPE_IP 0x0800
#define NET_PROTOCOL_TYPE_ARP 0x0806
#define NET_PROTOCOL_TYPE_IPV6 0x086dd

/* インタフェースのファミリ(種別) */
#define NET_IFACE_FAMILY_IP 1
#define NET_IFACE_FAMILY_IPV6 2
/* end */

#define NET_IFACE(x) ((struct net_iface *)(x))

// デバイス構造体
struct net_device
{
  struct net_device *next;  // 次のデバイスへのポインタ
  struct net_iface *ifaces; // デバイスに実装されているインタフェースリスト
  unsigned int index;
  char name[IFNASMSIZ];
  uint16_t type; // NET_DEVICE_TYPE_XXX
  /* デバイスタイプによって変化する値  */
  uint16_t mtu;
  uint16_t flags;
  uint16_t hlen;
  uint16_t alen;
  /*end*/
  /* デバイスのハードウェアアドレス等 */
  uint8_t addr[NET_DEVICE_ADDR_LEN];
  union
  {
    uint8_t peer[NET_DEVICE_ADDR_LEN];
    uint8_t broadcast[NET_DEVICE_ADDR_LEN];
  };
  /* end */
  struct net_device_ops *ops; // デバイスドライバ関数群へのポインタ
  void *priv;                 // デバイスドライバが使うプライベートデータへのポインタ
};

// インタフェース構造体. デバイスに紐づけるだけなので, どのファミリにも共通のデータを取り扱うときに使用.
struct net_iface
{
  struct net_iface *next; // 次のインタフェースへのポインタ
  struct net_device *dev; // インタフェースが紐づけられているデバイスへのポインタ
  int family;             // インタフェースファミリ
};

/* デバイスドライバ関数のポインタ群 */
struct net_device_ops
{
  int (*open)(struct net_device *dev);
  int (*close)(struct net_device *dev);
  int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};
/* end */

// デバイスの領域を確保
extern struct net_device *net_device_alloc(void);

// デバイスをリストに登録
extern int net_device_register(struct net_device *dev);

// デバイスにインタフェースを紐づける
extern int net_device_add_iface(struct net_device *dev, struct net_iface *iface);

// デバイスに紐づいたインタフェースを取得する
extern struct net_iface *net_device_get_iface(struct net_device *dev, int family);

extern int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

// デバイスへの出力
extern int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

// プロトコル登録
extern int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev));

// タイマーの登録
extern int net_timer_register(struct timeval interval, void (*handler)(void));

// タイマーのコールバック関数呼び出し
extern int net_timer_handler(void);

// デバイスからの入力ハンドラ
extern int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);

// ソフトウェア割り込みハンドラ
extern int net_softirq_handler(void);

extern int net_event_subscribe(void (*handler)(void *arg), void *arg);
extern int net_event_handler(void);
extern void net_raise_event(void);

// プロトコルスタックの起動
extern int net_run(void);

// プロトコルスタックの停止
extern void net_shutdown(void);

// プロトコルスタックの初期化
extern int net_init(void);

#endif