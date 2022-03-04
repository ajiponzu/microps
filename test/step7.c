#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "driver/loopback.h"
#include "test.h"
#include "ip.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
  (void)s;
  terminate = 1;
}

int main(int argc, char *argv[])
{
  struct net_device *dev;
  struct ip_iface *iface;

  signal(SIGINT, on_signal); // シグナルハンドラの設定
  /* プロトコルスタックの初期化 */
  if (net_init() == -1)
  {
    errorf("net_init() failure");
    return -1;
  }
  /* end */
  /* ループバックデバイスの初期化 */
  dev = loopback_init();
  if (!dev)
  {
    errorf("loopback_init() failure");
    return -1;
  }
  /* end */
  /* IPアドレスとサブネットマスクを指定してIPインタフェースを生成 */
  iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
  if (!iface)
  {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  /* end */
  /* IPインタフェースの登録 */
  if (ip_iface_register(dev, iface) == -1)
  {
    errorf("ip_iface_register() failure");
    return -1;
  }
  /* end */
  /* プロトコルスタックの軌道 */
  if (net_run() == -1)
  {
    errorf("net_run() failure");
    return -1;
  }
  /* end */

  /* Ctrl+cが押されるまで続ける */
  while (!terminate)
  {
    if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1)
    {
      errorf("net_device_output() failure");
      break;
    }
    sleep(1); // 1秒ごとに1ループ
  }
  net_shutdown(); // プロトコルスタックの停止

  return 0;
}