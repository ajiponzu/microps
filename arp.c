#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

// arpヘッダの構造体
struct arp_hdr
{
  uint16_t hrd;
  uint16_t pro;
  uint8_t hln;
  uint8_t pln;
  uint16_t op;
};

#define MSG_ARP_HDR(x) ((struct arp_hdr *)(&x->hdr))

// Ethernet/IPペアのためのarpメッセージ構造体
struct arp_ether_ip
{
  struct arp_hdr hdr;          // メンバが1byte単位, そして32bit(4byte)単位でそろっている.
  uint8_t sha[ETHER_ADDR_LEN]; // 6byte(48bit) -> 16bitあまる
  uint8_t spa[IP_ADDR_LEN];    // 4byte(32bit) -> uint32で定義すると, shaのせいで変数が境界をまたぐため, パディングが発生してしまう. 1バイト配列なら変数間, 要素間で隙間なく埋めることができる
  uint8_t tha[ETHER_ADDR_LEN]; // 6byte
  uint8_t tpa[IP_ADDR_LEN];    // 4byte. spaと同様の理由でバイト配列
};

// arpオペコードのバイナリ値を文字列に変換
static char *arp_opcode_ntoa(uint16_t opcode)
{
  switch (ntoh16(opcode))
  {
  case ARP_OP_REQUEST:
    return "Request";
  case ARP_OP_REPLY:
    return "Reply";
  }
  return "Unknown";
}

// arpデータデバッグ出力
static void arp_dump(const uint8_t *data, size_t len)
{
  struct arp_ether_ip *message;
  ip_addr_t spa, tpa;
  char addr[128];

  message = (struct arp_ether_ip *)data; // dataをethernet/ipペアのメッセージとみなす
  flockfile(stderr);
  fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
  fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
  fprintf(stderr, "        hln: %u\n", message->hdr.hln);
  fprintf(stderr, "        pln: %u\n", message->hdr.pln);
  fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
  /* sha/tha -> ハードウェアアドレス. Ethernet(Mac)アドレス
    spa/tpa -> プロトコルアドレス. IPアドレス
    */
  fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
  memcpy(&spa, message->spa, sizeof(spa)); // spaがuint8_t[4]なので, 一旦memcpy()でip_addr_tの変数へ取り出す
  fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
  fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
  memcpy(&tpa, message->tpa, sizeof(tpa)); // tpaもspaと同様. バイト配列を詰めて配置することはできたが, アクセスはやはり32bit単位で行った方が安全なため.
  fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
  /* end */
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

// arp応答
static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
  struct arp_ether_ip reply;

  /* arp応答メッセージの生成 */
  /* arpヘッダ */
  reply.hdr.hrd = hton16(ARP_HRD_ETHER);
  reply.hdr.pro = hton16(ARP_PRO_IP);
  reply.hdr.hln = ETHER_ADDR_LEN;
  reply.hdr.pln = IP_ADDR_LEN;
  reply.hdr.op = hton16(ARP_OP_REPLY);
  /* end */
  memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
  memcpy(reply.tha, tha, ETHER_ADDR_LEN);
  memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
  /* end */

  debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
  arp_dump((uint8_t *)&reply, sizeof(reply));

  return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst); // arpメッセージ送信
}

// arp応答の準備・実行
static void arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
  struct arp_ether_ip *msg;
  ip_addr_t spa, tpa;
  struct net_iface *iface;

  if (len < sizeof(*msg)) // 期待するArpメッセージのサイズより小さかったらエラー
  {
    errorf("too short");
    return;
  }
  msg = (struct arp_ether_ip *)data;

  /* 対応可能なアドレスペアのメッセージのみ受け入れる */
  /* ハードウェアアドレスのチェック */
  if (ntoh16(MSG_ARP_HDR(msg)->hrd) != ARP_HRD_ETHER || MSG_ARP_HDR(msg)->hln != ETHER_ADDR_LEN)
  {
    errorf("failure");
    return;
  }
  /* end */
  /* プロトコルアドレスのチェック */
  if (ntoh16(MSG_ARP_HDR(msg)->pro) != ARP_PRO_IP || MSG_ARP_HDR(msg)->pln != IP_ADDR_LEN)
  {
    errorf("failure");
    return;
  }
  /* end */
  /* end */

  debugf("dev=%s, len=%zu", dev->name, len);
  arp_dump(data, len);
  memcpy(&spa, msg->spa, sizeof(spa));
  memcpy(&tpa, msg->tpa, sizeof(tpa));
  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (iface && ((struct ip_iface *)iface)->unicast == tpa)
  {
    /* arp要求への応答 */
    if (ntoh16(MSG_ARP_HDR(msg)->op) == ARP_OP_REQUEST)
    {
      arp_reply(iface, msg->sha, spa, msg->sha); // 応答・返信なので宛先にはmsgの送信元アドレスを渡す
    }
    /* end */
  }
}

int arp_init(void)
{
  if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) < 0)
  {
    errorf("net_protocol_register() failure");
    return -1;
  }

  return 0;
}
