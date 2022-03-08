#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "test.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

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

  /* ループバックデバイス関連 */
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
  /* end */

  /* Ethernetデバイス関連 */
  /* デバイス生成 */
  dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
  if (!dev)
  {
    errorf("ether_tap_init() failure");
    return -1;
  }
  /* end */
  /* 対応するIPインタフェースの生成 */
  iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
  if (!iface)
  {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  /* end */
  /* インタフェースへの紐づけ */
  if (ip_iface_register(dev, iface) == -1)
  {
    errorf("ip_iface_register() failure");
    return -1;
  }
  /* end */
  /* end */

  /* デフォルトゲートウェイを登録 (192.0.2.1) */
  if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1)
  {
    errorf("ip_route_set_default_gateway() failure");
    return -1;
  }
  /* end */

  /* プロトコルスタックの起動 */
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
  struct ip_endpoint src, dst;
  size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

  if (setup() == -1)
  {
    errorf("setup() failure");
    return -1;
  }
  ip_endpoint_pton("127.0.0.1:10000", &src);
  ip_endpoint_pton("127.0.0.1:7", &dst);
  while (!terminate)
  {
    if (udp_output(&src, &dst, test_data + offset, sizeof(test_data) - offset) == -1)
    {
      errorf("udp_output() failure");
      break;
    }
    sleep(1);
  }
  cleanup();
  return 0;
}

/* step17の事前準備の前に, tapデバイスの生成を行っておく(step12参照)
> sudo ip tuntap add mode tap user $USER name tap0
> sudo ip addr add 192.0.2.1/24 dev tap0
> sudo ip link set tap0 up
*/