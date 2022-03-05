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

static int setup(void)
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

  return 0;
}

static void cleanup(void)
{
  net_shutdown();
}

int main(int argc, char *argv[])
{
  ip_addr_t src, dst;
  size_t offset = IP_HDR_SIZE_MIN; // IPヘッダは自分で生成するので, 実データの開始番地へのオフセットとしてヘッダサイズを設定

  /* プロトコルスタックの初期化～デバイス登録～起動までのセットアップ */
  if (setup() == -1)
  {
    errorf("setup() failure");
    return -1;
  }
  /* end */
  ip_addr_pton(LOOPBACK_IP_ADDR, &src); // IPアドレスを文字列からネットワークバイトオーダーのバイナリ値へ変換
  dst = src;                            // 宛先は送信元と同じIPアドレス -> ループバックデバイスを使用するから？

  /* Ctrl+cが押されるまで続ける */
  while (!terminate)
  {
    if (ip_output(1, test_data + offset, sizeof(test_data) - offset, src, dst) == -1)
    {
      errorf("net_device_output() failure");
      break;
    }
    sleep(1); // 1秒ごとに1ループ
  }
  cleanup();

  return 0;
}