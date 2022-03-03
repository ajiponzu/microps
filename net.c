#include <stdio.h>

#include "platform.h"

#include "util.h"
#include "net.h"

static struct net_device *devices; // デバイスリスト(のヘッダポインタ)

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
  /* デバイスリストの末尾に追加 */
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

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
  debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
  debugdump(data, len);

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
  infof("initialized");

  return 0;
}
