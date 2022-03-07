#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"

// プロトコル構造体
struct net_protocol
{
  struct net_protocol *next;                                                // 次のプロトコルへのポインタ, なお他もそうだが, 新しい要素が先頭に来るタイプの連結リスト
  uint16_t type;                                                            // プロトコルの種類(TCPとかARPとか). NET_PROTOCOL_TYPE_XXX
  struct queue_head queue;                                                  // 受信キュー
  void (*handler)(const uint8_t *data, size_t len, struct net_device *dev); // プロトコルの入力関数ポインタ
};

// 受信キューのエントリ構造体
struct net_protocol_queue_entry
{
  struct net_device *dev; // 要求してきたデバイス
  size_t len;             // 下記データサイズ
  uint8_t data[];         // フレキシブル配列
};

// タイマーの構造体
struct net_timer
{
  struct net_timer *next;  // 次のタイマーへのポインタ
  struct timeval interval; // 発火のインターバル
  struct timeval last;     // 最後の発火時間
  void (*handler)(void);   // 発火時に呼び出す関数へのポインタ
};

static struct net_device *devices;     // デバイスリスト(のヘッドポインタ)
static struct net_protocol *protocols; // 登録済みのプロトコルリスト(のヘッドポインタ)
static struct net_timer *timers;       // タイマーリスト(のヘッドポインタ)

struct net_device *net_device_alloc(void)
{
  struct net_device *dev;

  /* デバイス構造体のサイズだけメモリを確保 */
  dev = memory_alloc(sizeof(*dev)); // mallocが使用できない場合もあるので -> デバイス非依存関数(糖衣)
  if (!dev)
  {
    errorf("memory_alloc() failure");
    return NULL;
  }
  /* end */

  return dev;
}

int net_device_register(struct net_device *dev)
{
  static unsigned int index = 0; // この関数からのみアクセスできるstatic変数. 初期化は一回だけなので, 関数が呼ばれても値は保持される.

  dev->index = index++;                                        // 初期デバイス番号は0
  snprintf(dev->name, sizeof(dev->name), "net%d", dev->index); // デバイス名生成
  /* デバイスリストの先頭に追加 */
  dev->next = devices;
  devices = dev;
  /* end */
  infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);

  return 0;
}

// デバイスオープン
static int net_device_open(struct net_device *dev)
{
  /* デバイスの状態を確認 */
  if (NET_DEVICE_IS_UP(dev))
  {
    errorf("already opened, dev=%s", dev->name);
    return -1;
  }
  /* end */
  /* デバイスドライバのオープン関数実行 */
  if (dev->ops->open)
  {
    if (dev->ops->open(dev) == -1)
    {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }
  /* end */
  dev->flags |= NET_DEVICE_FLAG_UP; // UPフラグを立てる -> 末尾1ビットだけ1なので, 確実に末尾が1になる
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

  return 0;
}

// デバイスクローズ
static int net_device_close(struct net_device *dev)
{
  /* デバイスの状態を確認 */
  if (!NET_DEVICE_IS_UP(dev))
  {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  /* end */
  /* デバイスドライバのクローズ関数実行 */
  if (dev->ops->close)
  {
    if (dev->ops->close(dev) == -1)
    {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }
  /* end */
  dev->flags &= ~NET_DEVICE_FLAG_UP; // UPフラグをおろす. 論理否定によって末尾以外が1のマスクを生成し, 論理積によって確実に末尾を0にする
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

  return 0;
}

int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
  struct net_iface *entry;

  /* インタフェースの重複登録のチェック */
  for (entry = dev->ifaces; entry; entry = entry->next)
  {
    if (entry->family == iface->family)
    {
      errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
      return -1;
    }
  }
  /* end */
  iface->dev = dev; // インタフェース
  /* デバイスのインタフェースリストにifaceを追加 */
  iface->next = dev->ifaces; // インタフェースリストの先頭と連結
  dev->ifaces = iface;       // その後, インタフェースリストの先頭アドレスを更新
  /* end */

  return 0;
}

struct net_iface *net_device_get_iface(struct net_device *dev, int family)
{
  struct net_iface *entry;

  /* デバイスのインターフェースリストを巡回 */
  for (entry = dev->ifaces; entry; entry = entry->next)
  {
    if (entry->family == family) // ファミリが一致したら
    {
      return entry; // そのインタフェースを返す
    }
  }
  /* end */

  return NULL; // どのインタフェースもファミリが一致しない場合はNULLを返す
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
  /* デバイスの状態を確認 */
  if (!NET_DEVICE_IS_UP(dev))
  {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }
  /* end */
  /* データサイズ確認 */
  if (len > dev->mtu)
  {
    errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
    return -1;
  }
  /* end */
  debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
  debugdump(data, len);
  /* デバイスドライバの出力関数実行 */
  if (dev->ops->transmit(dev, type, data, len, dst) == -1)
  {
    errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
    return -1;
  }
  /* end */

  return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
  struct net_protocol *proto;

  /* 重複登録の確認 */
  for (proto = protocols; proto; proto = proto->next)
  {
    if (type == proto->type)
    {
      errorf("already registered, type=0x%04x", type);
      return -1;
    }
  }
  /* end */
  /* プロトコル構造体のメモリ確保 */
  proto = memory_alloc(sizeof(*proto));
  if (!proto)
  {
    errorf("memory_alloc() failure");
    return -1;
  }
  /* end */
  /* データ設定 */
  proto->type = type;
  proto->handler = handler;
  /* end */
  proto->next = protocols; // プロトコルリストの先頭に追加
  protocols = proto;
  infof("registered, type=0x%04x", type);

  return 0;
}

int net_timer_register(struct timeval interval, void (*handler)(void))
{
  struct net_timer *timer;

  /* タイマー構造体のメモリを確保 */
  timer = memory_alloc(sizeof(*timer));
  if (!timer)
  {
    errorf("memory_alloc() failure");
    return -1;
  }
  /* end */
  /* タイマーに値を設定 */
  gettimeofday(&timer->last, NULL);
  timer->handler = handler;
  timer->interval = interval;
  /* end */
  /* タイマーリストの先頭に追加 */
  timer->next = timers;
  timers = timer;
  /* end */

  infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
  return 0;
}

int net_timer_handler(void)
{
  struct net_timer *timer;
  struct timeval now, diff;

  for (timer = timers; timer; timer = timer->next) // タイマーリストを巡回
  {
    /* 最後の発火からの経過時間を求める */
    gettimeofday(&now, NULL);
    timersub(&now, &timer->last, &diff);
    /* end */
    if (timercmp(&timer->interval, &diff, <) != 0) // 発火時刻を迎えているかどうかの確認
    /* true (!0) or false (0) */
    {
      /* タイマーの発火 */
      timer->handler();
      gettimeofday(&timer->last, NULL);
      /* end */
    }
  }
  return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
  struct net_protocol *proto;
  struct net_protocol_queue_entry *entry;

  for (proto = protocols; proto; proto = proto->next)
  {
    if (proto->type == type)
    {
      /* プロトコルの受信キューにエントリを挿入 */
      /* エントリのメモリ確保 */
      entry = memory_alloc(sizeof(*entry) + len); // 必ずデータサイズ分だけ余分に確保
      if (!entry)
      {
        errorf("memory_alloc() failure");
        return -1;
      }
      /* end */
      /* データ・メタデータのコピー */
      entry->dev = dev;
      entry->len = len;
      memcpy(entry->data, data, len);
      /* end */
      void *ret = queue_push(&(proto->queue), entry); // 受信キューにプッシュ
      if (!ret)
      {
        errorf("queue_push() failure");
        return -1;
      }
      /* end */
      debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%lu", proto->queue.num, dev->name, type, entry->len);
      debugdump(data, len);
      intr_raise_irq(INTR_IRQ_SOFTIRQ); // プロトコルの受信キューへエントリを追加した後, ソフトウェア割り込みを発生させる

      /* プロトコルが見つからなかったら捨てる */
      return 0;
    }
  }

  return 0;
}

int net_softirq_handler(void)
{
  struct net_protocol *proto;
  struct net_protocol_queue_entry *entry;

  for (proto = protocols; proto; proto = proto->next) // プロトコルリストを巡回
  {
    while (1)
    {
      /* 受信キューからエントリを取り出す */
      entry = queue_pop(&proto->queue);
      if (!entry)
      {
        break; // emptyならループを終了
      }
      debugf("queue popped (num: %u), dev=%s, type=0x%04x, len=%zd", proto->queue.num, entry->dev->name, proto->type, entry->len);
      debugdump(entry->data, entry->len);
      proto->handler(entry->data, entry->len, entry->dev); // プロトコルの入力関数を呼び出す
      memory_free(entry);                                  // 使い終わったエントリのメモリを開放
    }
  }

  return 0;
}

int net_run(void)
{
  struct net_device *dev;

  /* 割り込み機構の起動 */
  if (intr_run() == -1)
  {
    errorf("intr_run() failure");
    return -1;
  }
  /* end */

  debugf("open all devices...");
  /* 登録済みのデバイスを全てオープン */
  for (dev = devices; dev; dev = dev->next)
  {
    net_device_open(dev);
  }
  /* end */
  debugf("running...");
  return 0;
}

void net_shutdown(void)
{
  struct net_device *dev;

  debugf("close all devices...");
  /* 登録済みのデバイスを全てクローズ */
  for (dev = devices; dev; dev = dev->next)
  {
    net_device_close(dev);
  }
  /* end */
  intr_shutdown(); // 割り込み機構の終了
  debugf("shutting down");
}

int net_init(void)
{
  /* 割り込み機構の初期化 */
  if (intr_init() == -1)
  {
    errorf("intr_init() failure");
    return -1;
  }
  /* end */
  /* ipの初期化 */
  if (ip_init() == -1)
  {
    errorf("ip_init() failure");
    return -1;
  }
  /* end */
  /* icmpの初期化 */
  if (icmp_init() == -1)
  {
    errorf("icmp_init() failure");
    return -1;
  }
  /* end */
  /* arpの初期化 */
  if (arp_init() == -1)
  {
    errorf("arp_init() failure");
    return -1;
  }
  /* end */
  infof("initialized");

  return 0;
}
