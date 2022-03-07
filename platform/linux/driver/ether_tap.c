#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE + 2)

struct ether_tap
{
  char name[IFNAMSIZ]; // TAPデバイスの名前
  int fd;              // ファイルディスクリプタ
  unsigned int irq;    // IRQ番号
};

#define PRIV(x) ((struct ether_tap *)x->priv)

// Ethernetデバイス(TAP)のハードウェアアドレスを取得
static int ether_tap_addr(struct net_device *dev)
{
  int soc;
  struct ifreq ifr = {}; // ioctl()で使うリクエスト/レスポンス兼用の構造体

  /* なんでもいいのでソケットをオープンする. つまりsocはダミーソケット */
  soc = socket(AF_INET, SOCK_DGRAM, 0);
  if (soc == -1)
  {
    errorf("socket: %s, dev=%s", strerror(errno), dev->name);
    return -1;
  }
  /* end */
  strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1); // ハードウェアアドレスを取得したいデバイスの名前を設定する
  /* ハードウェアアドレスの取得を要求する */
  if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) // SIOCGIFHWADDRはソケットのディスクリプタを渡したときのみ有効. だからダミーソケットを生成した.
  {
    errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
    close(soc);
    return -1;
  }
  /* end */
  memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN); // 取得したアドレスをデバイス構造体へコピー
  close(soc);                                                // 使い終わったソケットをクローズ

  return 0;
}

// Ethernetデバイス<tap(オープン・クローズ)>. デバイスに紐づいたtapをオープン・クローズする
static int ether_tap_open(struct net_device *dev)
{
  struct ether_tap *tap;
  struct ifreq ifr = {}; // ioctl()で使うリクエスト/レスポンス兼用の構造体

  /* TUN/TAPの制御用デバイスをオープン */
  tap = PRIV(dev); // デバイスのプライベートデータにtap情報を格納するための準備
  tap->fd = open(CLONE_DEVICE, O_RDWR);
  if (tap->fd == -1)
  {
    errorf("open: %s, dev=%s", strerror(errno), dev->name);
    return -1;
  }
  /* end */
  strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1); // TAPデバイスの名前を設定
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;                        // フラグ設定(IFF_TAP: TAPモード, IFF_NO_PI: パケット情報ヘッダをつけない)
  /* TAPデバイスの登録を要求 */
  if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) // ioctl: デバイスドライバに信号を送る
  {
    errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  /* end */
  /* シグナル駆動I/Oのための設定 */ // シグナル駆動I/O: データが入力可能な状態になったらシグナルを発生させて知らせてくれる
  /* Set Asynchronous I/O signal delivery destination */
  if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) // シグナルの配送先を設定
  {
    errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  /* Enable Asynchronous I/O */
  if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) // シグナル駆動I/Oを有効にする
  {
    errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  /* Use other signal instead of SIGIO */
  if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) // 送信するシグナルを指定
  {
    errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  /* end */
  if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) // HWアドレスが明示的に設定されていなかったら
  {
    /* OS側から見えているTAPデバイスのHW(ハードウェア)アドレスを取得して使用する */
    if (ether_tap_addr(dev) == -1)
    {
      errorf("ether_tap_addr() failure, dev=%s", dev->name);
      close(tap->fd);
      return -1;
    }
    /* end */
  }
  return 0;
}

// tapのfdをクローズ
static int ether_tap_close(struct net_device *dev)
{
  close(PRIV(dev)->fd); // ファイルディスクリプタをクローズ
  return 0;
}

// tapでハックした場所にデータを書き込む.
static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
  return write(PRIV(dev)->fd, frame, flen); // write()で書き出すだけ
}

// Ethernetデバイスのデータ送信関数ポインタに登録するための関数
int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
  return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write); // ether_transmit_helper() を呼び出す. コールバック関数としてether_tap_write()のアドレスを渡す
}

// tapでハックした場所が書き込み, 送信したデータを読みだす
static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
  ssize_t len;

  len = read(PRIV(dev)->fd, buf, size); // read()で読みだすだけ
  if (len <= 0)
  {
    if (len == -1 && errno != EINTR)
    {
      errorf("read: %s, dev=%s", strerror(errno), dev->name);
    }
    return -1;
  }
  return len;
}

// 割り込みして, データが読み込み可能かをpollによって判断し, 可能な場合はフレームの読み込みと解析を行う
static int ether_tap_isr(unsigned int irq, void *id)
{
  struct net_device *dev;
  struct pollfd pfd;
  int ret;

  dev = (struct net_device *)id;
  pfd.fd = PRIV(dev)->fd;
  pfd.events = POLLIN;
  while (1)
  {
    ret = poll(&pfd, 1, 0); // タイムアウト時間を0に設定した poll() で読み込み可能なデータの存在を確認
    if (ret == -1)
    {
      if (errno == EINTR)
      {
        continue; // errno が EINTR の場合は再試行（シグナルに割り込まれたという回復可能なエラー）
      }
      errorf("poll: %s, dev=%s", strerror(errno), dev->name);
      return -1;
    }
    if (ret == 0) // 戻り値が0だったらタイムアウト（読み込み可能なデータなし）と判断し, ループを抜ける
    {
      /* No frames to input immediately. */
      break;
    }
    ether_input_helper(dev, ether_tap_read); // 読み込み可能な場合, コールバックを呼び出して, データフレームの解析を行う
  }
  return 0;
}

// tapデバイス関数ポインタ群
static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

struct net_device *ether_tap_init(const char *name, const char *addr)
{
  struct net_device *dev;
  struct ether_tap *tap;

  /* デバイスを生成 */
  dev = net_device_alloc();
  if (!dev)
  {
    errorf("net_device_alloc() failure");
    return NULL;
  }
  /* end */
  ether_setup_helper(dev); // Ethernetデバイスの共通パラメータを設定
  /* 引数でハードウェアアドレスの文字列が渡されたら, それをバイト列に変換して設定 */
  if (addr)
  {
    if (ether_addr_pton(addr, dev->addr) == -1)
    {
      errorf("invalid address, addr=%s", addr);
      return NULL;
    }
  }
  /* end */
  dev->ops = &ether_tap_ops; // ドライバの関数群を設定
  /* ドライバ内部で使用するプライベートデータの生成・保持. Ethernetデバイスならtapにあたる */
  tap = memory_alloc(sizeof(*tap));
  if (!tap)
  {
    errorf("memory_alloc() failure");
    return NULL;
  }
  strncpy(tap->name, name, sizeof(tap->name) - 1);
  tap->fd = -1; // 初期値として無効なディスクリプタを設定. 0とかだと変なところに繋がりかねない
  tap->irq = ETHER_TAP_IRQ;
  dev->priv = tap;
  /* end */
  /* デバイスをプロトコルスタックに登録 */
  if (net_device_register(dev) == -1)
  {
    errorf("net_device_register() failure");
    memory_free(tap);
    return NULL;
  }
  /* end */
  intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev); // 割り込みハンドラの登録
  infof("ethernet device initialized, dev=%s", dev->name);

  return dev;
}