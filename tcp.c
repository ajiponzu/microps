#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"
#include "platform.h"

/* TCPヘッダのフラグフィールドの値 */
#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20
/* end */

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

struct tcp_segment_info
{
  uint32_t seq;
  uint32_t ack;
  uint16_t len;
  uint16_t wnd;
  uint16_t up;
};

// コントロールブロック構造体
struct tcp_pcb
{
  int state;
  struct ip_endpoint local;
  struct ip_endpoint foreign;
  struct
  {
    uint32_t nxt;
    uint32_t una;
    uint16_t wnd;
    uint16_t up;
    uint32_t wl1;
    uint32_t wl2;
  } snd;
  uint32_t iss;
  struct
  {
    uint32_t nxt;
    uint16_t wnd;
    uint16_t up;
  } rcv;
  uint32_t irs;
  uint16_t mtu;
  uint16_t mss;
  uint8_t buf[65535]; /* receive buffer */
  struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

// 疑似ヘッダの構造体 (チェックサム計算時のみ使用)
struct pseudo_hdr
{
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

// TCPヘッダの構造体
struct tcp_hdr
{
  uint16_t src; // 送信先ポート
  uint16_t dst; // 宛先ポート
  uint32_t seq;
  uint32_t ack;
  uint8_t off;
  uint8_t flg;
  uint16_t wnd;
  uint16_t sum;
  uint16_t up;
};

static char *tcp_flg_ntoa(uint8_t flg)
{
  static char str[9];

  snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
           TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
           TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
           TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
           TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
           TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
           TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
  return str;
}

// tcpセグメントデバッグ出力
static void tcp_dump(const uint8_t *data, size_t len)
{
  struct tcp_hdr *hdr;

  flockfile(stderr);
  hdr = (struct tcp_hdr *)data;
  fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
  fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
  fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
  fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
  fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
  fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
  fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

// 新規コントロールブロックの領域確保
static struct tcp_pcb *tcp_pcb_alloc(void)
{
  struct tcp_pcb *pcb;

  /* FREE 状態のPCBを見つけて返す
    ・CLOSED状態に初期化する */
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    if (pcb->state == TCP_PCB_STATE_FREE)
    {
      pcb->state = TCP_PCB_STATE_CLOSED;
      sched_ctx_init(&pcb->ctx);
      return pcb;
    }
  }
  /* end */
  return NULL;
}

// コントロールブロックの領域解放
static void tcp_pcb_release(struct tcp_pcb *pcb)
{
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  /* pcb利用しているタスクがいたらこのタイミングでは解放できない
    ・タスクを起床させてる（他のタスクに解放を任せる）*/
  if (sched_ctx_destroy(&pcb->ctx) == -1)
  {
    sched_wakeup(&pcb->ctx);
    return;
  }
  /* end */
  debugf("released, local=%s, foreign=%s",
         ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
         ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
  memset(pcb, 0, sizeof(*pcb)); /* pcb->state is set to TCP_PCB_STATE_FREE (0) */
}

// コントロールブロックの選択
static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
  struct tcp_pcb *pcb, *listen_pcb = NULL;

  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port)
    {
      /* ローカルアドレスに bind 可能かどうか調べるときは外部アドレスを指定せずに呼ばれる
        ・ローカルアドレスがマッチしているので返す */
      if (!foreign)
      {
        return pcb;
      }
      /* end */
      /* ローカルアドレスと外部アドレスが共にマッチ */
      if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port)
      {
        return pcb;
      }
      /* end */
      /* 外部アドレスを指定せずに LISTEN していたらどんな外部アドレスでもマッチする
        ・ローカルアドレス/外部アドレス共にマッチしたものが優先されるのですぐには返さない */
      if (pcb->state == TCP_PCB_STATE_LISTEN)
      {
        if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0)
        {
          /* LISTENed with wildcard foreign address/port */
          listen_pcb = pcb;
        }
      }
      /* end */
    }
  }
  return listen_pcb;
}

static struct tcp_pcb *tcp_pcb_get(int id)
{
  struct tcp_pcb *pcb;

  if (id < 0 || id >= (int)countof(pcbs))
  {
    /* out of range */
    return NULL;
  }
  pcb = &pcbs[id];
  if (pcb->state == TCP_PCB_STATE_FREE)
  {
    return NULL;
  }
  return pcb;
}

static int tcp_pcb_id(struct tcp_pcb *pcb)
{
  return indexof(pcbs, pcb);
}

static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local,
                                  struct ip_endpoint *foreign)
{
  uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
  struct tcp_hdr *hdr;
  struct pseudo_hdr pseudo;
  uint16_t psum;
  uint16_t total;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  hdr = (struct tcp_hdr *)buf;

  /* TCPセグメントの生成 */
  hdr->src = local->port;
  hdr->dst = foreign->port;
  hdr->seq = hton32(seq);
  hdr->ack = hton32(ack);
  hdr->off = (sizeof(*hdr) >> 2) << 4; // ヘッダサイズを4バイト単位で表す
  hdr->flg = flg;
  hdr->wnd = hton16(wnd);
  hdr->up = 0;
  hdr->sum = 0;
  /* 疑似ヘッダの生成 */
  pseudo.src = local->addr;
  pseudo.dst = foreign->addr;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_TCP;
  pseudo.len = hton16(len);
  /* end */
  /* チェックサムの計算 */
  total = len + sizeof(*hdr);
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
  hdr->sum = cksum16((uint16_t *)hdr, total, psum);
  /* end */
  /* end */

  debugf("%s => %s, len=%zu (payload=%zu)",
         ip_endpoint_ntop(local, ep1, sizeof(ep1)),
         ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
         total, len);
  tcp_dump((uint8_t *)hdr, total);

  /* IPの送信関数を呼び出す */
  if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1)
  {
    errorf("ip_output() failure");
    return -1;
  };
  /* end */

  return len;
}

static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
  uint32_t seq;

  seq = pcb->snd.nxt;
  /* SYNフラグが指定されるのは初回送信時なので iss（初期送信シーケンス番号）を使う */
  if (TCP_FLG_ISSET(flg, TCP_FLG_SYN))
  {
    seq = pcb->iss;
  }
  /* end */
  if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len)
  {
    /* TODO: add retransmission queue */
  }
  return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign); // PCBの情報を使ってTCPセグメントを送信
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
  struct tcp_pcb *pcb;

  pcb = tcp_pcb_select(local, foreign);
  if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED)
  {
    if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
    {
      return;
    }
    /* 使用していないポートに何か飛んで来たら RST を返す */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
    {
      tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
    }
    else
    {
      tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
    }
    /* end */
    return;
  }
  switch (pcb->state)
  {
  case TCP_PCB_STATE_LISTEN:
    /*
     * 1st check for an RST
     */
    if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
    {
      return;
    }

    /*
     * 2nd check for an ACK
     */
    if (TCP_FLG_ISSET(flags, TCP_FLG_ACK))
    {
      tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
      return;
    }

    /*
     * 3rd check for an SYN
     */
    if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
    {
      /* ignore: security/compartment check */
      /* ignore: precedence check */
      pcb->local = *local;
      pcb->foreign = *foreign;
      pcb->rcv.wnd = sizeof(pcb->buf);
      pcb->rcv.nxt = seg->seq + 1;
      pcb->irs = seg->seq;
      pcb->iss = random();
      tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
      pcb->snd.nxt = pcb->iss + 1;
      pcb->snd.una = pcb->iss;
      pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
      /* ignore: Note that any other incoming control or data             */
      /* (combined with SYN) will be processed in the SYN-RECEIVED state, */
      /* but processing of SYN and ACK  should not be repeated            */
      return;
    }

    /*
     * 4th other text or control
     */

    /* drop segment */
    return;
  case TCP_PCB_STATE_SYN_SENT:
    /*
     * 1st check the ACK bit
     */

    /*
     * 2nd check the RST bit
     */

    /*
     * 3rd check security and precedence (ignore)
     */

    /*
     * 4th check the SYN bit
     */

    /*
     * 5th, if neither of the SYN or RST bits is set then drop the segment and return
     */

    /* drop segment */
    return;
  }
  /*
   * Otherwise
   */

  /*
   * 1st check sequence number
   */

  /*
   * 2nd check the RST bit
   */

  /*
   * 3rd check security and precedence (ignore)
   */

  /*
   * 4th check the SYN bit
   */

  /*
   * 5th check the ACK field
   */

  if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
  {
    /* drop segment */
    return;
  }
  switch (pcb->state)
  {
  case TCP_PCB_STATE_SYN_RECEIVED:
    if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt)
    {
      pcb->state = TCP_PCB_STATE_ESTABLISHED;
      sched_wakeup(&pcb->ctx);
    }
    else
    {
      tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
      return;
    }
    break;
  }

  /*
   * 6th, check the URG bit (ignore)
   */

  /*
   * 7th, process the segment text
   */

  /*
   * 8th, check the FIN bit
   */

  return;
}

// tcpセグメントの入力
static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct tcp_hdr *hdr;
  struct pseudo_hdr pseudo;
  uint16_t psum;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  struct ip_endpoint local, foreign;
  uint16_t hlen;
  struct tcp_segment_info seg;

  if (len < sizeof(*hdr))
  {
    errorf("too short");
    return;
  }
  hdr = (struct tcp_hdr *)data;
  /* 疑似ヘッダの構築 */
  pseudo.src = src;
  pseudo.dst = dst;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_TCP;
  pseudo.len = hton16(len);
  /* end */

  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
  /* チェックサムの検証 */
  if (cksum16((uint16_t *)hdr, len, psum) != 0)
  {
    errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
    return;
  }
  /* end */

  /* アドレスのチェック */
  if (src == iface->broadcast || dst == iface->broadcast)
  {
    errorf("This address is not a broadcast addres");
    return;
  }
  /* end */

  debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
         ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
         ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
         len, len - sizeof(*hdr));
  tcp_dump(data, len);
  /* endpointに入れなおす */
  local.addr = dst;
  local.port = hdr->dst;
  foreign.addr = src;
  foreign.port = hdr->src;
  /* end */
  /* tcp_segment_arrives() で必要な情報（SEG.XXX）を集める */
  hlen = (hdr->off >> 4) << 2;
  seg.seq = ntoh32(hdr->seq);
  seg.ack = ntoh32(hdr->ack);
  seg.len = len - hlen;
  if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN))
  {
    seg.len++; /* SYN flag consumes one sequence number */
  }
  if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN))
  {
    seg.len++; /* FIN flag consumes one sequence number */
  }
  seg.wnd = ntoh16(hdr->wnd);
  seg.up = ntoh16(hdr->up);
  /* end */
  mutex_lock(&mutex);
  tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
  mutex_unlock(&mutex);

  return;
}

static void event_handler(void *arg)
{
  struct tcp_pcb *pcb;

  mutex_lock(&mutex);
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
  {
    if (pcb->state != TCP_PCB_STATE_FREE)
    {
      sched_interrupt(&pcb->ctx);
    }
  }
  mutex_unlock(&mutex);
}

int tcp_init(void)
{
  if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) < 0)
  {
    errorf("ip_protocol_register() failure");
    return -1;
  }
  net_event_subscribe(event_handler, NULL);
  return 0;
}

/*
 * TCP User Command (RFC793)
 */

int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
  struct tcp_pcb *pcb;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];
  int state, id;

  mutex_lock(&mutex);
  pcb = tcp_pcb_alloc();
  if (!pcb)
  {
    errorf("tcp_pcb_alloc() failure");
    mutex_unlock(&mutex);
    return -1;
  }
  if (active)
  {
    errorf("active open does not implement");
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return -1;
  }
  else
  {
    debugf("passive open: local=%s, waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
    pcb->local = *local;
    if (foreign)
    {
      pcb->foreign = *foreign;
    }
    pcb->state = TCP_PCB_STATE_LISTEN;
  }
AGAIN:
  state = pcb->state;
  /* waiting for state changed */
  while (pcb->state == state)
  {
    if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
    {
      debugf("interrupted");
      pcb->state = TCP_PCB_STATE_CLOSED;
      tcp_pcb_release(pcb);
      mutex_unlock(&mutex);
      errno = EINTR;
      return -1;
    }
  }
  if (pcb->state != TCP_PCB_STATE_ESTABLISHED)
  {
    if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED)
    {
      goto AGAIN;
    }
    errorf("open error: %d", pcb->state);
    pcb->state = TCP_PCB_STATE_CLOSED;
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return -1;
  }
  id = tcp_pcb_id(pcb);
  debugf("connection established: local=%s, foreign=%s",
         ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
  pthread_mutex_unlock(&mutex);
  return id;
}

int tcp_close(int id)
{
  struct tcp_pcb *pcb;

  mutex_lock(&mutex);
  pcb = tcp_pcb_get(id);
  if (!pcb)
  {
    errorf("pcb not found");
    mutex_unlock(&mutex);
    return -1;
  }
  tcp_output(pcb, TCP_FLG_RST, NULL, 0);
  tcp_pcb_release(pcb);
  mutex_unlock(&mutex);
  return 0;
}
