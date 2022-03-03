#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "platform.h"

#include "util.h"
#include "net.h"

struct irq_entry
{
  struct irq_entry *next;
  unsigned int irq;
  int (*handler)(unsigned int irq, void *dev);
  int flags;
  char name[16];
  void *dev;
};

static struct irq_entry *irqs;

static sigset_t sigmask; // シグナルマスク用のシグナル集合

static pthread_t tid;             // 割り込みスレッドのスレッドID
static pthread_barrier_t barrier; // スレッド感の動機のためのバリア

int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
  struct irq_entry *entry;

  debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
  /* IRQ番号が登録されているなら, その番号の共有が許可されているかチェック */
  for (entry = irqs; entry; entry = entry->next)
  {
    if (entry->irq == irq)
    {
      if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
      {
        errorf("conflicts with already registered IRQs");
        return -1;
      }
    }
  }
  /* end */

  /* 新規エントリのメモリ確保 */
  entry = memory_alloc(sizeof(*entry));
  if (!entry)
  {
    errorf("memory_alloc() failure");
    return -1;
  }
  /* end */
  /* IRQ構造体に値を設定 */
  entry->irq = irq;
  entry->handler = handler;
  entry->flags = flags;
  strncpy(entry->name, name, sizeof(entry->name) - 1);
  entry->dev = dev;
  /* end */
  /* IRQリストの先頭へ挿入 */
  entry->next = irqs;
  irqs = entry;
  /* end */
  sigaddset(&sigmask, irq); // シグナル集合へ新規シグナルを追加
  debugf("registered: irq=%u, name=%s", irq, name);

  return 0;
}

int intr_raise_irq(unsigned int irq)
{
  return pthread_kill(tid, (int)irq); // 割り込み処理スレッドへシグナルを送信
}

// 割り込みスレッドのエントリポイント
static void *intr_thread(void *arg)
{
  int terminate = 0, sig, err;
  struct irq_entry *entry;

  debugf("start...");
  pthread_barrier_wait(&barrier); // メインスレッドと同期をとる
  while (!terminate)
  {
    /* 割り込みシグナルが発生するまで待機 */
    err = sigwait(&sigmask, &sig);
    if (err)
    {
      errorf("sigwait() %s", strerror(err));
      break;
    }
    /* end */
    switch (sig)
    {
    /* SIGHUP: 割り込みスレッドへ終了を通知するためのシグナル */
    case SIGHUP:
      terminate = 1;
      break;
    /* end */
    case SIGUSR1:
      net_softirq_handler();
      break;
    /* デバイス割り込み用のシグナル */
    default:
      for (entry = irqs; entry; entry = entry->next) // IRQリストを巡回
      {
        /* IRQ番号が一致するエントリの割り込みハンドラを実行 */
        if (entry->irq == (unsigned int)sig)
        {
          debugf("irq=%d, name=%s", entry->irq, entry->name);
          entry->handler(entry->irq, entry->dev);
        }
        /* end */
      }
      break;
    }
    /* end */
  }
  debugf("terminated");
  return NULL;
}

int intr_run(void)
{
  int err;

  /* シグナルマスクの設定 */
  err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
  if (err)
  {
    errorf("pthread_sigmask() %s", strerror(err));
    return -1;
  }
  /* end */
  /* 割り込みスレッドの起動 */
  err = pthread_create(&tid, NULL, intr_thread, NULL);
  if (err)
  {
    errorf("pthread_create() %s", strerror(err));
    return -1;
  }
  /* end */
  pthread_barrier_wait(&barrier); // スレッドが動き出すまで待つ. バリアは集団主義(遅刻者も待つ)

  return 0;
}

void intr_shutdown(void)
{
  /* 割り込み処理スレッドが起動済みか確認 */
  if (pthread_equal(tid, pthread_self()) != 0)
  {
    return;
  }
  /* end */
  pthread_kill(tid, SIGHUP); // 割り込みスレッドにシグナルを送信
  pthread_join(tid, NULL);   // 割り込みスレッドが完全に終了するのを待つ
}

int intr_init(void)
{
  tid = pthread_self();                    // スレッドIDの初期値をメインスレッドIDに設定
  pthread_barrier_init(&barrier, NULL, 2); // pthread_barrierの初期化(カウントが2になるまで待つバリア)
  sigemptyset(&sigmask);                   // シグナル集合を初期化(空)
  sigaddset(&sigmask, SIGHUP);             // シグナル集合にSIGHUPを追加 (割り込みスレッド終了通知用)
  sigaddset(&sigmask, SIGUSR1);

  return 0;
}
