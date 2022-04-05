#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
  (void)s;
  terminate = 1;
  net_raise_event();
}

static int
setup(void)
{
  struct net_device *dev;
  struct ip_iface *iface;

  signal(SIGINT, on_signal);
  if (net_init() == -1)
  {
    errorf("net_init() failure");
    return -1;
  }
  dev = loopback_init();
  if (!dev)
  {
    errorf("loopback_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
  if (!iface)
  {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev, iface) == -1)
  {
    errorf("ip_iface_register() failure");
    return -1;
  }
  dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
  if (!dev)
  {
    errorf("ether_tap_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
  if (!iface)
  {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev, iface) == -1)
  {
    errorf("ip_iface_register() failure");
    return -1;
  }
  if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1)
  {
    errorf("ip_route_set_default_gateway() failure");
    return -1;
  }
  if (net_run() == -1)
  {
    errorf("net_run() failure");
    return -1;
  }
  return 0;
}

static void
cleanup(void)
{
  sleep(1);
  net_shutdown();
}

int main(int argc, char *argv[])
{
  struct ip_endpoint local, foreign;
  int soc;
  uint8_t buf[2048];
  ssize_t ret;

  if (setup() == -1)
  {
    errorf("setup() failure");
    return -1;
  }
  ip_endpoint_pton("192.0.2.2:7", &local);
  ip_endpoint_pton("192.0.2.1:10007", &foreign);
  soc = tcp_open_rfc793(&local, &foreign, 1);
  if (soc == -1)
  {
    errorf("tcp_open_rfc793() failure");
    return -1;
  }
  while (!terminate)
  {
    ret = tcp_receive(soc, buf, sizeof(buf));
    if (ret <= 0)
    {
      break;
    }
    debugf("%zd bytes data received", ret);
    hexdump(stderr, buf, ret);
    tcp_send(soc, buf, ret);
  }
  tcp_close(soc);
  cleanup();
  return 0;
}

/* step17の事前準備の前に, tapデバイスの生成を行っておく(step12参照)
> sudo ip tuntap add mode tap user $USER name tap0
> sudo ip addr add 192.0.2.1/24 dev tap0
> sudo ip link set tap0 up
*/

/* step17の事前準備
> sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
> sudo iptables -A FORWARD -o tap0 -j ACCEPT
> sudo iptables -A FORWARD -i tap0 -j ACCEPT
> sudo iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o eth0 -j MASQUERADE
*/
