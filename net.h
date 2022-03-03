#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

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

struct net_device
{
  struct net_device *next; // 次のデバイスへのポインタ
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

// デバイスへの出力
extern int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

// デバイスからの入力
extern int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);

// プロトコルスタックの起動
extern int net_run(void);

// プロトコルスタックの停止
extern void net_shutdown(void);

// プロトコルスタックの初期化
extern int net_init(void);

#endif