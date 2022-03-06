#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

// ICMPヘッダ構造体（メッセージ固有のフィールドは単なる32bitの値として扱う）
struct icmp_hdr
{
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint32_t values;
};

// Echo / EchoReply メッセージ構造体（メッセージ種別が判別した段階でこちらにキャストする）
struct icmp_echo
{
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint16_t id;
  uint16_t seq;
};

// icmpタイプを文字列に変換してわかりやすくする
static char *icmp_type_ntoa(uint8_t type)
{
  switch (type)
  {
  case ICMP_TYPE_ECHOREPLY:
    return "EchoReply";
  case ICMP_TYPE_DEST_UNREACH:
    return "DestinationUnreachable";
  case ICMP_TYPE_SOURCE_QUENCH:
    return "SourceQuench";
  case ICMP_TYPE_REDIRECT:
    return "Redirect";
  case ICMP_TYPE_ECHO:
    return "Echo";
  case ICMP_TYPE_TIME_EXCEEDED:
    return "TimeExceeded";
  case ICMP_TYPE_PARAM_PROBLEM:
    return "ParameterProblem";
  case ICMP_TYPE_TIMESTAMP:
    return "Timestamp";
  case ICMP_TYPE_TIMESTAMPREPLY:
    return "TimestampReply";
  case ICMP_TYPE_INFO_REQUEST:
    return "InformationRequest";
  case ICMP_TYPE_INFO_REPLY:
    return "InformationReply";
  }
  return "Unknown";
}

// icmp情報出力
static void icmp_dump(const uint8_t *data, size_t len)
{
  struct icmp_hdr *hdr;
  struct icmp_echo *echo;

  flockfile(stderr);
  /* 全メッセージ共通のフィールド */
  hdr = (struct icmp_hdr *)data;
  fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
  fprintf(stderr, "       code: %u\n", hdr->code);
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  /* end */
  switch (hdr->type)
  {
  case ICMP_TYPE_ECHOREPLY:
  case ICMP_TYPE_ECHO: // Echo/EchoReply の場合には詳細を出力
    echo = (struct icmp_echo *)hdr;
    fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
    fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
    break;
  default: // その他のメッセージの場合には 32bit 値をそのまま出力
    fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
    break;
  }
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct icmp_hdr *hdr;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  /* ICMPメッセージの検証 */
  hdr = (struct icmp_hdr *)data;
  if (len < ICMP_HDR_SIZE) // データ全体がヘッダサイズより小さいのはおかしいのではじく
  {
    errorf("icmp_size is too short");
    return;
  }
  if (cksum16((uint16_t *)hdr, len, 0) != 0) // チェックサムの検証
  {
    errorf("this checksum is incorrect");
    return;
  }
  /* end */

  debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)),
         ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
  debugdump(data, len);
  icmp_dump(data, len);
}

int icmp_init(void)
{
  if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) < 0)
  {
    errorf("ip_protocol_register() failure");
    return -1;
  }

  return 0;
}
