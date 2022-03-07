#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "platform.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

/* ARPキャッシュの状態を表す定数 */
#define ARP_CACHE_STATE_FREE 0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED 2
#define ARP_CACHE_STATE_STATIC 3
/* end */

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

// キャッシュ構造体
struct arp_cache
{
  unsigned char state;        // キャッシュの状態
  ip_addr_t pa;               // プロトコルアドレス
  uint8_t ha[ETHER_ADDR_LEN]; // ハードウェアアドレス
  struct timeval timestamp;   // 最終更新時刻
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; // arpテーブル(キャッシュ配列)

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

// キャッシュデータの削除
static void arp_cache_delete(struct arp_cache *cache)
{
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

  /* キャッシュのエントリを削除する */
  cache->state = ARP_CACHE_STATE_FREE;
  cache->pa = 0;
  memset(cache->ha, 0, ETHER_ADDR_LEN); // 配列の要素全てを特定の値にするときはmemsetを使用する
  timerclear(&(cache->timestamp));
  /* end */
}

// キャッシュデータの領域を確保
static struct arp_cache *arp_cache_alloc(void)
{
  struct arp_cache *entry, *oldest = NULL;

  for (entry = caches; entry < tailof(caches); entry++) // arpテーブル巡回
  {
    if (entry->state == ARP_CACHE_STATE_FREE)
    {
      return entry; // 使用されていないエントリを返す
    }
    if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >))
    {
      oldest = entry; // 使用されていない空きエントリがない場合は, 古いエントリを探す
    }
  }
  arp_cache_delete(oldest); // 古いエントリを削除
  return oldest;            // 空っぽになった領域を返す
}

// キャッシュテーブルに要求されたプロトコルアドレスが存在するか検索する
static struct arp_cache *arp_cache_select(ip_addr_t pa)
{
  struct arp_cache *entry;

  for (entry = caches; entry < tailof(caches); entry++)
  {
    if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa)
    {
      return entry;
    }
  }

  return NULL;
}

// テーブルに存在する, プロトコルアドレスに対応する情報を更新する
static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  /* エントリの検索 */
  cache = arp_cache_select(pa);
  if (!cache)
  {
    errorf("arp_cache_select() failure");
    return NULL;
  }
  /* end */
  /* 情報を更新する. タイムスタンプとか */
  memcpy(cache->ha, ha, ETHER_ADDR_LEN);
  cache->state = ARP_CACHE_STATE_RESOLVED;
  gettimeofday(&(cache->timestamp), NULL);
  /* end */

  debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

// arpテーブルにキャッシュを登録する
static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  /* エントリの登録スペースを確保 */
  cache = arp_cache_alloc();
  if (!cache)
  {
    errorf("arp_cache_alloc() failure");
    return NULL;
  }
  /* end */
  /* 情報の設定 */
  cache->state = ARP_CACHE_STATE_RESOLVED;
  cache->pa = pa;
  memcpy(cache->ha, ha, ETHER_ADDR_LEN);
  gettimeofday(&(cache->timestamp), NULL);
  /* end */

  debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

// arp要求
static int arp_request(struct net_iface *iface, ip_addr_t tpa)
{
  struct arp_ether_ip request;

  /* arp要求のメッセージを生成する */
  request.hdr.hrd = hton16(ARP_HRD_ETHER);
  request.hdr.pro = hton16(ARP_PRO_IP);
  request.hdr.hln = ETHER_ADDR_LEN;
  request.hdr.pln = IP_ADDR_LEN;
  request.hdr.op = hton16(ARP_OP_REQUEST);
  memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
  memset(request.tha, 0, ETHER_ADDR_LEN);
  memcpy(request.tpa, &tpa, IP_ADDR_LEN);
  /* end */

  debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
  arp_dump((uint8_t *)&request, sizeof(request));

  /* デバイスの送信関数を呼び出してarp要求のメッセージを送信する */
  return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)(&request), sizeof(request), iface->dev->broadcast);
  /* end */
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
  int merge = 0; // 更新の可否を示すフラグ

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

  /* テーブルアクセスはアトミックに行う */
  mutex_lock(&mutex);
  if (arp_cache_update(spa, msg->sha))
  {
    merge = 1; // 更新したら1. 未登録なら0
  }
  mutex_unlock(&mutex);
  /* end */

  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if (iface && ((struct ip_iface *)iface)->unicast == tpa)
  {
    if (!merge) // 送信元アドレスのキャッシュ情報が上記の処理で更新されていないならば
    {
      mutex_lock(&mutex);
      arp_cache_insert(spa, msg->sha); // 未登録なので, 送信元アドレスのキャッシュ情報を登録する. テーブルは必ずアトミックに操作
      mutex_unlock(&mutex);
    }

    /* arp要求への応答 */
    if (ntoh16(MSG_ARP_HDR(msg)->op) == ARP_OP_REQUEST)
    {
      arp_reply(iface, msg->sha, spa, msg->sha); // 応答・返信なので宛先にはmsgの送信元アドレスを渡す
    }
    /* end */
  }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  /* 物理デバイスと論理インタフェースがそれぞれEthernetとIPであることを確認 */
  if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET)
  {
    debugf("unsupported hardware address type");
    return ARP_RESOLVE_ERROR;
  }
  if (iface->family != NET_IFACE_FAMILY_IP)
  {
    debugf("unsupported protocol address type");
    return ARP_RESOLVE_ERROR;
  }
  /* end */

  mutex_lock(&mutex);           // arpキャッシュへのアクセスをmutexで保護
  cache = arp_cache_select(pa); // プロトコルアドレスをキーとしてarpキャッシュを検索
  if (!cache)                   // 見つからないならエラー
  {
    char addr[IP_ADDR_STR_LEN];
    errorf("cache not found, pa=%s", ip_addr_ntop(pa, addr, IP_ADDR_STR_LEN));
    /* arpキャッシュに問い合わせ中のエントリを作成 */
    cache = arp_cache_alloc();
    if (!cache)
    {
      return ARP_RESOLVE_ERROR; // 確保失敗
    }
    cache->state = ARP_RESOLVE_INCOMPLETE;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    cache->pa = pa;
    gettimeofday(&(cache->timestamp), NULL);
    /* end */
    mutex_unlock(&mutex);
    arp_request(iface, pa);        // arp要求送信
    return ARP_RESOLVE_INCOMPLETE; // 問い合わせ中
  }
  /* 見つかったエントリが INCOMPLETE のままだったらパケロスしているかもしれないので念のため再送する. arp_request実行後なのにincompleteな場合
    ・タイムスタンプは更新しない
  */
  if (cache->state == ARP_CACHE_STATE_INCOMPLETE)
  {
    pthread_mutex_unlock(&mutex);
    arp_request(iface, pa); /* just in case packet loss */
    return ARP_RESOLVE_INCOMPLETE;
  }
  /* end */

  memcpy(ha, cache->ha, ETHER_ADDR_LEN); // 見つかったハードウェアアドレスをコピー
  mutex_unlock(&mutex);
  debugf("resolved, pa=%s, ha=%s",
         ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));

  return ARP_RESOLVE_FOUND; // 見つかった場合はfound. アドレスを解決した
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
