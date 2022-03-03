#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "driver/loopback.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s)
{
  (void)s;
  terminate = 1;
}

int main(int argc, char *argv[])
{
  struct net_device *dev;

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
    if (net_device_output(dev, 0x0800, test_data, sizeof(test_data), NULL) == -1)
    {
      errorf("net_device_output() failure");
      break;
    }
    sleep(1); // 1秒ごとに1ループ
  }
  net_shutdown(); // プロトコルスタックの停止

  return 0;
}