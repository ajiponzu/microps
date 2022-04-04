#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "ip.h"
#include "udp.h"

#include "platform.h"

#define UDP_PCB_SIZE 16

/* コントロールブロックの状態 */
#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2
/* end */

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

// 疑似ヘッダの構造体（チェックサム計算時に使用する）
struct pseudo_hdr
{
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

// UDPヘッダの構造体
struct udp_hdr
{
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t sum;
};

// コントロールブロック
struct udp_pcb
{
  int state;
  struct ip_endpoint local; // 自分のアドレスとポート
  struct queue_head queue;  /* receive queue */
  struct sched_ctx ctx;     // スケジューラのコンテキスト
};

// 受信キュー(受信データのプール)のノード
struct udp_queue_entry
{
  struct ip_endpoint foreign; // 送信元のアドレス&ポート番号
  uint16_t len;
  uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE]; // コントロールブロックの配列

// udpデータグラムのデバッグ出力
static void udp_dump(const uint8_t *data, size_t len)
{
  struct udp_hdr *hdr;

  flockfile(stderr);
  hdr = (struct udp_hdr *)data;
  fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
  fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
  fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

// コントロールブロックの領域確保. 確保されたpcbの状態はopenになり, pcbsにも登録されている
static struct udp_pcb *udp_pcb_alloc(void)
{
  struct udp_pcb *pcb;

  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    /* 使用されていないpcbを探して返す */
    if (pcb->state == UDP_PCB_STATE_FREE)
    {
      pcb->state = UDP_PCB_STATE_OPEN;
      sched_ctx_init(&pcb->ctx);
      return pcb;
    }
    /* end */
  }
  return NULL; // 空きがない時
}

// コントロールブロックの領域解放
static void udp_pcb_release(struct udp_pcb *pcb)
{
  struct queue_entry *entry;

  pcb->state = UDP_PCB_STATE_CLOSING;
  /* クローズされたことを休止中のタスクに知らせるために起床させる.
    ただし, shced_ctx_destroy() がエラーを返すのは休止中のタスクが存在する場合のみ
  */
  if (sched_ctx_destroy(&pcb->ctx) == -1)
  {
    sched_wakeup(&pcb->ctx);
    return;
  }

  /* end */

  /* 値をクリア. 空きを作らないと, 次のブロックの確保のとき困る */
  pcb->state = UDP_PCB_STATE_FREE;
  pcb->local.addr = IP_ADDR_ANY;
  pcb->local.port = 0;
  /* end */
  while (1)
  { /* Discard the entries in the queue. */
    /* 受信キューを空にする */
    entry = queue_pop(&pcb->queue);
    if (!entry)
    {
      break;
    }
    memory_free(entry);
    /* end */
  }
}

// コントロールブロックの検索
static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port)
{
  struct udp_pcb *pcb;

  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    if (pcb->state == UDP_PCB_STATE_OPEN) // open状態のpcbのみ対象とする
    {
      if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) // IPアドレスとポートが一致するpcbを探して返す
      // IP_ADDR_ANYはワイルドカードとなり, ローカル・宛先どちらか一方でも持っていたらアドレスは一致したものとする
      {
        return pcb;
      }
    }
  }
  return NULL;
}

// idに対応したpcbを取得
static struct udp_pcb *udp_pcb_get(int id)
{
  struct udp_pcb *pcb;

  /* 配列の範囲チェック */
  if (id < 0 || id >= (int)countof(pcbs))
  {
    /* out of range */
    return NULL;
  }
  /* end */
  pcb = &pcbs[id];
  if (pcb->state != UDP_PCB_STATE_OPEN) // open状態でないならNULL
  {
    return NULL;
  }
  return pcb;
}

// pcbsのどこに位置するpcbか, 添え字として取得する
static int udp_pcb_id(struct udp_pcb *pcb)
{
  return indexof(pcbs, pcb);
}

// udpデータグラムの入力
static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct pseudo_hdr pseudo;
  uint16_t psum = 0;
  struct udp_hdr *hdr;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  struct udp_pcb *pcb;
  struct udp_queue_entry *entry;

  /* ヘッダサイズに満たないデータはエラーとする */
  if (len < sizeof(*hdr))
  {
    errorf("too short");
    return;
  }
  /* end */
  hdr = (struct udp_hdr *)data;
  /* IPから渡されたデータ長（len）とUDPヘッダに含まれるデータグラム長（hdr->len）が一致しない場合はエラー */
  if (len != ntoh16(hdr->len))
  { /* just to make sure */
    errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
    return;
  }
  /* end */
  /* チェックサム計算のために疑似ヘッダを準備 */
  pseudo.src = src;
  pseudo.dst = dst;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_UDP;
  pseudo.len = hton16(len);
  /* end */
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0); // 疑似ヘッダ部分のチェックサムを計算（計算結果はビット反転されているので戻しておく. ここで求めているのは途中結果なので反転されると困る. 関数内で反転しちゃうから）
  if (cksum16((uint16_t *)hdr, len, psum) != 0)            // cksum16() の第三引数に psum を渡すことで続きを計算できる. ここは最終結果なので, 反転されているのが正解
  {
    errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
    return;
  }
  debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
         ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
         ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
         len, len - sizeof(*hdr));
  udp_dump(data, len);

  mutex_lock(&mutex);                  // pcbsはアトミックに操作
  pcb = udp_pcb_select(dst, hdr->dst); // 宛先アドレスとポート番号に対応するpcbを検索
  if (!pcb)                            // pcbが見つからなければ中断
  {
    /* port is not in use */
    mutex_unlock(&mutex);
    return;
  }

  /* 受信キューへデータを格納 */
  entry = memory_alloc(sizeof(*entry) + len - sizeof(*hdr));
  if (!entry)
  {
    mutex_unlock(&mutex);
    errorf("memory_alloc() failure");
    return;
  }

  entry->len = len - sizeof(*hdr); // なお, hdr->lenは意味的にはlenと同じだが, ネットワークバイトオーダーのため, そのまま使うととんでもないことになる
  entry->foreign.addr = src;
  entry->foreign.port = hdr->src;
  memcpy(entry->data, hdr + 1, entry->len);
  queue_push(&pcb->queue, entry);
  /* end */

  debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
  sched_wakeup(&pcb->ctx); // 受信キューにエントリが追加されたことを休止中のタスクに知らせるために再開させる
  mutex_unlock(&mutex);
}

int udp_open(void)
{
  struct udp_pcb *pcb;
  pcb = udp_pcb_alloc();
  if (!pcb)
  {
    errorf("udp_pcb_alloc() failure");
    return -1;
  }
  return udp_pcb_id(pcb);
}

int udp_close(int id)
{
  struct udp_pcb *pcb;
  pcb = udp_pcb_get(id);
  if (!pcb)
  {
    errorf("udp_pcb_get() failure");
    return -1;
  }
  udp_pcb_release(pcb);

  return 0;
}

int udp_bind(int id, struct ip_endpoint *local)
{
  struct udp_pcb *pcb, *exist;
  char ep1[IP_ENDPOINT_STR_LEN];
  // char ep2[IP_ENDPOINT_STR_LEN];

  mutex_lock(&mutex);

  /* udpソケットへアドレスとポート番号を紐づけ */
  pcb = udp_pcb_get(id);
  if (!pcb)
  {
    mutex_unlock(&mutex);
    errorf("udp_pcb_get() failure");
    return -1;
  }
  exist = udp_pcb_select(local->addr, local->port);
  if (exist)
  {
    mutex_unlock(&mutex);
    errorf("addr and port is already used");
    return -1;
  }
  pcb->local = *local;
  /* end */

  debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
  mutex_unlock(&mutex);
  return 0;
}

ssize_t udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
  struct udp_pcb *pcb;
  struct ip_endpoint local;
  struct ip_iface *iface;
  char addr[IP_ADDR_STR_LEN];
  uint32_t p;

  mutex_lock(&mutex); // pcbはアトミックに操作
  /* idからpcbを取得 */
  pcb = udp_pcb_get(id);
  if (!pcb)
  {
    errorf("pcb not found, id=%d", id);
    mutex_unlock(&mutex);
    return -1;
  }
  /* end */
  local.addr = pcb->local.addr;
  /* 自分のアドレスがワイルドカードなら, 宛先に応じて送信元アドレスを自動的に選択 */
  if (local.addr == IP_ADDR_ANY)
  {
    iface = ip_route_get_iface(foreign->addr); // ipのルーティング情報から宛先に到達可能なインタフェースを取得
    if (!iface)
    {
      errorf("iface not found that can reach foreign address, addr=%s",
             ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
      mutex_unlock(&mutex);
      return -1;
    }
    local.addr = iface->unicast; // 取得したインタフェースのアドレスを使用
    debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
  }
  /* end */
  /* 自分の使うポート番号が未設定なら送信元ポートを自動的に選択する */
  if (!pcb->local.port)
  {
    for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) // 送信元ポート番号の範囲から使用可能なポートを探す
    {
      if (!udp_pcb_select(local.addr, hton16(p))) // まだ使用されていないアドレスとポートならpcbに割り当てる
      {
        pcb->local.port = hton16(p);
        debugf("dynamic assign local port, port=%d", p);
        break;
      }
    }
    if (!pcb->local.port) // 探しても使用可能なポートが見つからなければエラー
    {
      debugf("failed to dynamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
      mutex_unlock(&mutex);
      return -1;
    }
  }
  /* end */
  local.port = pcb->local.port;
  mutex_unlock(&mutex);
  return udp_output(&local, foreign, data, len);
}

ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
  struct udp_pcb *pcb;
  struct udp_queue_entry *entry;
  ssize_t len;
  int err;

  mutex_lock(&mutex); // pcbはアトミックに操作
  /* idからpcbのポインタを取得 */
  pcb = udp_pcb_get(id);
  if (!pcb)
  {
    errorf("pcb not found, id=%d", id);
    mutex_unlock(&mutex);
    return -1;
  }
  /* end */

  /* 受信キューからエントリを取り出す */
  while (1)
  {
    entry = queue_pop(&pcb->queue); // エントリを取り出す
    if (entry)
    {
      break; // 取り出し成功後, ループを抜ける
    }
    err = sched_sleep(&pcb->ctx, &mutex, NULL); // sched_wakeup() or sched_interrupt()が呼ばれるまでタスク休止
    if (err)                                    // sched_interrup()による再開なので, errorならerrnoにeintrを設定してエラーを返す
    {
      debugf("interrupted");
      mutex_unlock(&mutex);
      errno = EINTR;
      return -1;
    }
    if (pcb->state == UDP_PCB_STATE_CLOSING) // stateがclosingのpcbを解放してエラーを返す
    {
      debugf("closed");
      udp_pcb_release(pcb);
      mutex_unlock(&mutex);
      return -1;
    }
  }
  /* end */

  mutex_unlock(&mutex);
  /* 送信元のアドレスとポートをコピー */
  if (foreign)
  {
    *foreign = entry->foreign;
  }
  /* end */
  /* バッファが小さかったら切り詰めて格納する */
  len = MIN(size, entry->len); /* truncate */
  memcpy(buf, entry->data, len);
  /* end */
  memory_free(entry);
  return len;
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
  uint8_t buf[IP_PAYLOAD_SIZE_MAX];
  struct udp_hdr *hdr;
  struct pseudo_hdr pseudo;
  uint16_t total = 0, psum = 0;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) // IPのペイロードに載せきれないほど大きなデータが渡されたらエラーを返す
  {
    errorf("too long");
    return -1;
  }
  hdr = (struct udp_hdr *)buf;

  /* UDPデータグラムの生成 */
  total = len + sizeof(*hdr);
  hdr->src = src->port;
  hdr->dst = dst->port;
  hdr->len = hton16(total);
  hdr->sum = 0;
  memcpy(hdr + 1, data, len);
  pseudo.src = src->addr;
  pseudo.dst = dst->addr;
  pseudo.zero = 0;
  pseudo.len = hdr->len;
  pseudo.protocol = IP_PROTOCOL_UDP;
  /* チェックサム導出 */
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
  hdr->sum = cksum16((uint16_t *)hdr, total, psum); // ただし, host環境でチェックするため, cksumのcountにはホストバイトオーダーのレングスを渡す
  /* end */
  /* end */

  debugf("%s => %s, len=%zu (payload=%zu)",
         ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
  udp_dump((uint8_t *)hdr, total);

  /* IPの送信関数を呼び出す */
  if (ip_output(pseudo.protocol, buf, total, src->addr, dst->addr) == -1)
  {
    errorf("ip_output() failure");
    return -1;
  }
  /* end */

  return len;
}

// イベントハンドラ
static void event_handler(void *arg)
{
  struct udp_pcb *pcb;

  (void)arg;
  mutex_lock(&mutex);
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    /* 有効なpcbのコンテキスト全てに割り込みを発生させる */
    if (pcb->state == UDP_PCB_STATE_OPEN)
    {
      sched_interrupt(&pcb->ctx);
    }
    /* end */
  }
  mutex_unlock(&mutex);
}

int udp_init(void)
{
  if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) < 0)
  {
    errorf("ip_protocol_register() failure");
    return -1;
  }

  /* イベントの購読 */
  if (net_event_subscribe(event_handler, NULL) == -1)
  {
    errorf("net_event_subscribe() failure");
    return -1;
  }
  /* end */

  return 0;
}
