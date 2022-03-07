#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

#include "platform.h"

// IPヘッダを表現するための構造体. uint8_t[]バイト列をこの構造体にキャストするとIPヘッダとみなすことができる.
struct ip_hdr
{
  uint8_t vhl;    // xxxxyyyy: 上位ビットx->バージョン, 下位ビットy->IPヘッダ長(4bitで一つの塊が何個あるか)
  uint8_t tos;    // type of service-> precedence:3bit, delay:1bit, throughput:1bit, relibility:1bit, reserved:2bit
  uint16_t total; // total length: IPヘッダサイズ(=iph*4bit)+データサイズ
  uint16_t id;
  uint16_t offset;  // Flags(3bit)とFragmentOffset(13bit)を一まとまりで扱う
  uint8_t ttl;      // time to live
  uint8_t protocol; // Ethernetフレームヘッダのプロトコルタイプと混同しないように注意
  uint16_t sum;     // チェックサム
  ip_addr_t src;    // 送信元アドレス (ネットワークバイトオーダーのバイナリ値)
  ip_addr_t dst;    // 宛先アドレス (ネットワークバイトオーダーのバイナリ値)
  uint8_t options[];
};

// IPの上位プロトコルを管理するための構造体
struct ip_protocol
{
  struct ip_protocol *next;
  uint8_t type;
  void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       // 0.0.0.0
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; // 255.255.255.255

static struct ip_iface *ifaces;       // 登録されているIPインタフェースのリスト
static struct ip_protocol *protocols; // 登録されているプロトコルのリスト

int ip_addr_pton(const char *p, ip_addr_t *n)
{
  char *sp, *ep;
  int idx;
  long ret;

  sp = (char *)p;
  for (idx = 0; idx < 4; idx++)
  {
    ret = strtol(sp, &ep, 10);
    if (ret < 0 || ret > 255)
    {
      return -1;
    }
    if (ep == sp)
    {
      return -1;
    }
    if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
    {
      return -1;
    }
    ((uint8_t *)n)[idx] = ret;
    sp = ep + 1;
  }

  return 0;
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask)
{
  struct ip_iface *iface;
  int failed = 0;

  /* IPインタフェース構造体のメモリを確保 */
  iface = memory_alloc(sizeof(*iface));
  if (!iface)
  {
    errorf("memory_alloc() failure");
    return NULL;
  }
  /* end */
  NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP; // インタフェース構造体にファミリを設定

  /* IPインタフェースにアドレス情報を設定 */
  /* ユニキャストアドレスを文字列から取得 */
  if (ip_addr_pton(unicast, &(iface->unicast)) < 0)
  {
    errorf("failed to convert unicast string");
    failed = 1;
  }
  /* end */
  /* サブネットマスクを文字列から取得 */
  if (!failed && ip_addr_pton(netmask, &(iface->netmask)) < 0)
  {
    errorf("failed to convert netmask string");
    failed = 1;
  }
  /* end */
  /* ブロードキャストアドレスの算出 */
  if (failed) // ユニキャスト，サブネットマスクのいずれかの変換に失敗した際
  {
    memory_free(iface); // 不要なデータになったので開放
    return NULL;        // 失敗したのでNULLを返す
  }
  else // ユニキャストとサブネットマスクを取得できた際
  {
    ip_addr_t network = iface->unicast & iface->netmask; // ネットワークアドレスを求め
    iface->broadcast = network | (~iface->netmask);      // さらにブロードキャストアドレスを求めて保存
  }
  /* end */
  /* end */

  return iface;
}

int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  char addr3[IP_ADDR_STR_LEN];

  /* IPインタフェースの登録 */
  /* デバイスへの登録. ついでに重複登録にならないかチェック.
  デバイスのifaceはip_ifaceではなくnet_ifaceであることに注意.
  なので NET_IFACEマクロを使用. */
  if (net_device_add_iface(dev, NET_IFACE(iface)) < 0)
  {
    errorf("failed to add interface");
    return -1;
  }
  /* end */
  iface->next = ifaces;
  ifaces = iface; // デバイスに登録できたインタフェースだけインタフェースリストに登録
  /* end */

  infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

  return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr)
{
  struct ip_iface *entry;

  /* IPインタフェースの検索 */
  for (entry = ifaces; entry; entry = entry->next)
  {
    if (entry->unicast == addr) // 一致したら
    {
      return entry; // 値を返す
    }
  }
  /* end */

  return NULL;
}

char *ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
  uint8_t *u8;

  u8 = (uint8_t *)&n;
  snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);

  return p;
}

static void ip_dump(const uint8_t *data, size_t len)
{
  struct ip_hdr *hdr;
  uint8_t v, hl, hlen;
  uint16_t total, offset;
  char addr[IP_ADDR_STR_LEN];

  flockfile(stderr);
  hdr = (struct ip_hdr *)data;
  v = (hdr->vhl & 0xf0) >> 4; // 下位ビットを0にしてから右に4シフトすることで上位ビットを得る
  hl = hdr->vhl & 0x0f;       // 上位ビットを0にすることで下位ビットを得る
  hlen = hl << 2;             // 実際のIPヘッダサイズはhl一つにつき4bitとして4*hl. 左2シフトは*4と同じ
  fprintf(stderr, "       vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
  fprintf(stderr, "       tos: 0x%02x\n", hdr->tos);
  total = ntoh16(hdr->total);                                             // 多バイト長のデータはバイトオーダーの変換が必須
  fprintf(stderr, "     total: %u (payload: %u)\n", total, total - hlen); // 運搬データ(ペイロード)のサイズは, トータルサイズからヘッダサイズを引いた値
  fprintf(stderr, "        id: %u\n", ntoh16(hdr->id));
  offset = ntoh16(hdr->offset);
  fprintf(stderr, "    offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff); // 上位ビットだけ, 下位ビットだけを取り出すテクニック
  fprintf(stderr, "       ttl: %u\n", hdr->ttl);
  fprintf(stderr, "  protocol: %u\n", hdr->protocol);
  fprintf(stderr, "       sum: 0x%04x\n", ntoh16(hdr->sum));
  fprintf(stderr, "       src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
  fprintf(stderr, "       dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

int ip_protocol_register(uint8_t type,
                         void (*handler)(const uint8_t *data, size_t len, ip_addr_t src,
                                         ip_addr_t dst, struct ip_iface *iface))
{
  struct ip_protocol *entry;

  /* 重複登録の確認 */
  for (entry = protocols; entry; entry = entry->next)
  {
    if (entry->type == type)
    {
      errorf("already registered, type=0x%04x", type);
      return -1;
    }
  }
  /* end */
  /* プロトコルの登録 */
  entry = memory_alloc(sizeof(*entry));
  if (!entry)
  {
    errorf("memory_alloc() failure");
    return -1;
  }
  entry->type = type;
  entry->handler = handler;
  entry->next = protocols;
  protocols = entry;
  /* end */

  infof("registered, type=%u", entry->type);
  return 0;
}

// ipの入力関数
static void ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
  struct ip_hdr *hdr;
  uint8_t v;
  uint16_t hlen, total, offset;
  struct ip_iface *iface;
  char addr[IP_ADDR_STR_LEN];

  /* 入力データサイズがIPヘッダの最小サイズより小さい場合はエラー */
  if (len < IP_HDR_SIZE_MIN)
  {
    errorf("too short");
    return;
  }
  /* end */
  hdr = (struct ip_hdr *)data; // バイナリデータをIPヘッダとして扱うためのキャスト. hdrに実体は持たせない
  /* IPデータグラムの検証 */
  /* バージョン検証 */
  v = (hdr->vhl & 0xf0) >> 4; // バージョン導出
  if (v != IP_VERSION_IPV4)
  {
    errorf("this version is not ipv4 version");
    return;
  }
  /* end */
  /* ヘッダ長検証 */
  hlen = (hdr->vhl & 0x0f) << 2;
  if (len < hlen)
  {
    errorf("input length is shorter than header's length");
    return;
  }
  /* end */
  /* トータル長検証 */
  total = ntoh16(hdr->total);
  if (len < total)
  {
    errorf("input length is shorter than total length");
    return;
  }
  /* end */
  /* チェックサム */
  if (cksum16((uint16_t *)data, hlen, 0) != 0)
  {
    errorf("this checksum is incorrect");
    return;
  }
  /* end */
  /* end */
  offset = ntoh16(hdr->offset);
  if (offset & 0x2000 || offset & 0x1fff)
  {
    errorf("fragments does not support");
    return;
  }
  /* IPデータグラムのフィルタリング */
  /* デバイスに紐づくIPインタフェースを取得 */
  iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  /* ip_ifaceからdeviceは辿れても, 逆は無理のように思える.
  c++のようにnet_ifaceがip_ifaceを継承しているわけでもない.
  しかし, 構造体のメモリ配置の法則から, ip_iface構造体のポインタと, その最初のメンバであるnet_ifaceのポインタは同じである.
  このことから, ip_ifaceのメンバであるnet_ifaceをdeviceに登録することで紐づけていたため,
  そのnet_ifaceのポインタをip_ifaceポインタにキャストすると, すでに代入済みのユニキャスト等も把握できるようになる.
  つまり, ip_ifaceの最初のメンバであるnet_ifaceに限っては, net_iface*とip_iface*の違いはどこまでを確保された領域とみるかだけ,ということになる.
  */
  if (!iface)
  {
    errorf("failed to get ip_iface");
    return;
  }
  /* end */
  /* 宛先IPアドレスの検証 */
  if (hdr->dst != iface->unicast && hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST)
  {
    return;
  }
  /* end */
  /* end */

  debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name,
         ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
  ip_dump(data, total);

  /* 上位プロトコルの検索 */
  for (struct ip_protocol *entry = protocols; entry; entry = entry->next)
  {
    if (entry->type == hdr->protocol)
    {
      entry->handler(data + hlen, total - hlen, hdr->src, hdr->dst, iface);
      return;
    }
  }
  /* end */
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
  uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
  int ret;

  if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) // ARP によるアドレス解決が必要なデバイスのための処理
  {
    /* 宛先がブロードキャストIPアドレスの場合には ARP によるアドレス解決は行わずに
    そのデバイスのブロードキャストHWアドレスを使う */
    if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST)
    {
      memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
    }
    /* end */
    else
    {
      /* arp_resolve()を呼び出してアドレスを解決する */
      ret = arp_resolve((struct net_iface *)iface, dst, hwaddr);
      if (ret != ARP_RESOLVE_FOUND)
      {
        return ret;
      }
      /* end */
    }
  }

  return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, &dst); // デバイスから送信
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
  uint8_t buf[IP_TOTAL_SIZE_MAX];
  struct ip_hdr *hdr;
  uint16_t hlen, total;
  char addr[IP_ADDR_STR_LEN];

  hdr = (struct ip_hdr *)buf;

  /* IPデータグラムの生成 */
  hlen = IP_HDR_SIZE_MIN;
  total = hlen + len;
  hdr->sum = 0; // 送信なので, チェックサムは0. メモリ確保時に初期値は0と限らないので初期化はきっちりしておく

  hdr->vhl = (IP_VERSION_IPV4 << 4) + (hlen >> 2);
  hdr->tos = 0;
  hdr->total = hton16(total);
  hdr->id = hton16(id);
  hdr->offset = offset;
  hdr->ttl = 255;
  hdr->protocol = protocol;
  hdr->src = src; // ネットワークバイトオーダーのバイナリ値を渡されているので, 送信時は変換不要
  hdr->dst = dst;
  hdr->sum = cksum16((uint16_t *)hdr, hlen, 0); // チェックサムはヘッダ値が出そろってから計算しないと意味がない
  memcpy(hdr + 1, data, len);                   // srcポインタはbuf基準で渡すことに注意. hdrにオフセットを足すと, hdrサイズ*オフセット足してしまう
  /* end */

  debugf("dev=%s, dst=%s, protocol=%u, len=%u",
         NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
  ip_dump(buf, total);

  return ip_output_device(iface, buf, total, dst); // 生成したIPデータグラムを実際にデバイスから送信するための関数に渡す
}

static uint16_t ip_generate_id(void)
{
  static mutex_t mutex = MUTEX_INITIALIZER;
  static uint16_t id = 128;
  uint16_t ret;

  mutex_lock(&mutex);
  ret = id++;
  mutex_unlock(&mutex);
  return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
  struct ip_iface *iface;
  // char addr[IP_ADDR_STR_LEN];
  uint16_t id;

  if (src == IP_ADDR_ANY)
  {
    errorf("ip routing does not implement");
    return -1;
  }
  else
  {
    /* IPインタフェースの検索 */
    iface = ip_iface_select(src);
    if (!iface)
    {
      errorf("ip_iface_select() failure");
      return -1;
    }
    /* end */
    /* 宛先へ到達可能か確認 */
    if (dst != IP_ADDR_BROADCAST && (dst < (iface->unicast & iface->netmask) || dst > iface->broadcast))
    {
      errorf("not achievement");
      return -1;
    }
    /* end */
  }
  if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len)
  {
    errorf("too long, dev=%s, mtu=%u < %zu",
           NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
    return -1;
  }
  id = ip_generate_id(); // IPデータグラムのIDを採番
  /* IPデータグラム生成・出力関数実行 */
  if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1)
  {
    errorf("ip_output_core() failure");
    return -1;
  }
  /* end */

  return len;
}

int ip_init(void)
{
  if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) // プロトコルスタックにipの入力関数を登録
  {
    errorf("net_protocol_register() failure");
    return -1;
  }

  return 0;
}
