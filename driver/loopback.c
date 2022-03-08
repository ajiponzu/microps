#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define LOOPBACK_MTU UINT16_MAX /* maximum size of IP datagram */
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback *)x->priv)

/* ループバックデバイスのドライバ内で使用するプライベートデータを格納する構造体 */
struct loopback
{
  int irq;
  mutex_t mutex;
  struct queue_head queue;
};
/* end */

// キューのエントリの構造体. フレキシブル配列メンバをもつ構造体の領域確保には, 確保時のデータサイズ分だけ余分に確保する必要がある.
struct loopback_queue_entry
{
  uint16_t type;
  size_t len;     // 下記の配列サイズを記憶しておく
  uint8_t data[]; /* フレキシブル配列メンバ. 構造体のサイズに含まれない. 扱いに注意. */
  // data: 本体データ, type・len: メタデータ(情報)
};

// ループバックデバイスの送信関数
static int loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
  struct loopback_queue_entry *entry;
  unsigned int num;

  mutex_lock(&PRIV(dev)->mutex); // キューへのアクセスをmutexで保護
  /* キューの上限を超えていたらエラーを返す */
  if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT)
  {
    mutex_unlock(&PRIV(dev)->mutex);
    errorf("queue is full");
    return -1;
  }
  /* end */
  /* キューに格納するエントリのメモリを確保 */
  entry = memory_alloc(sizeof(*entry) + len); // entry->dataは確保しないので注意
  if (!entry)
  {
    mutex_unlock(&PRIV(dev)->mutex);
    errorf("memory_alloc() failure");
    return -1;
  }
  /* end */
  /* データ・メタデータのコピー */
  entry->type = type;
  entry->len = len;
  memcpy(entry->data, data, len);
  /* end */
  /* エントリをキューへ格納 */
  void *ret = queue_push(&PRIV(dev)->queue, entry);
  if (!ret)
  {
    mutex_unlock(&PRIV(dev)->mutex);
    errorf("queue_push() failure");
    return -1;
  }
  /* end */
  num = PRIV(dev)->queue.num;
  mutex_unlock(&PRIV(dev)->mutex); // キューへのアクセスが終わったので, アクセス保護解除
  debugf("queue pushed (num: %u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
  debugdump(data, len);
  intr_raise_irq(PRIV(dev)->irq); // 割り込み発生

  return 0;
}

// ループバックデバイスの割り込みハンドラ
static int loopback_isr(unsigned int irq, void *id)
{
  struct net_device *dev;
  struct loopback_queue_entry *entry;

  dev = (struct net_device *)id;
  mutex_lock(&PRIV(dev)->mutex); // アクセス保護
  while (1)
  {
    entry = queue_pop(&PRIV(dev)->queue); // エントリの取り出し
    if (!entry)
    {
      break; // emptyならループ終了
    }
    debugf("queue poped (num:%u), dev=%s, tyep=0x%04x, len=%zd", PRIV(dev)->queue.num, dev->name, entry->type, entry->len);
    debugdump(entry->data, entry->len);
    net_input_handler(entry->type, entry->data, entry->len, dev); // デバイスハンドラに受信データ本体とメタデータを渡す
    memory_free(entry);
  }
  mutex_unlock(&PRIV(dev)->mutex); // アクセス保護解除を忘れると永遠に他のスレッドからアクセスできない

  return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

struct net_device *loopback_init(void)
{
  struct net_device *dev;
  struct loopback *lo; // ip show とかで確認したときにローカルホストなどのループバックデバイスがloと表示されることにちなむ

  /* デバイスの生成とパラメータの設定 */
  dev = net_device_alloc();
  if (!dev)
  {
    errorf("net_device_alloc() failure");
    return NULL;
  }
  dev->type = NET_DEVICE_TYPE_LOOPBACK;
  dev->mtu = LOOPBACK_MTU;
  dev->hlen = 0;
  dev->alen = 0;
  dev->flags = NET_DEVICE_FLAG_LOOPBACK;
  dev->ops = &loopback_ops;
  /* end */

  /* プライベートデータの準備 */
  lo = memory_alloc(sizeof(*lo));
  if (!lo)
  {
    errorf("memory_alloc() failure");
    return NULL;
  }
  lo->irq = LOOPBACK_IRQ;
  mutex_init(&lo->mutex);
  queue_init(&lo->queue);
  /* end */
  dev->priv = lo; // プライベートデータの格納

  /* デバイス登録と割り込みハンドラの設定 */
  /* デバイスを登録 */
  if (net_device_register(dev) == -1)
  {
    errorf("net_device_register() failure");
    return NULL;
  }
  /* end */
  intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev); // 割り込みハンドラ登録
  /* end */

  debugf("initialized, dev=%s", dev->name);

  return dev;
}
