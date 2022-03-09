#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int sched_ctx_init(struct sched_ctx *ctx)
{
  pthread_cond_init(&ctx->cond, NULL);
  ctx->interrupted = 0;
  ctx->wc = 0;

  return 0;
}

int sched_ctx_destroy(struct sched_ctx *ctx)
{
  return pthread_cond_destroy(&ctx->cond);
}

int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
  int ret;

  if (ctx->interrupted)
  {
    errno = EINTR; // 割り込まれただけなので, 復帰可能なエラー
    return -1;
  }
  ctx->wc++; // 待ちスレッド数のインクリメント
  /* pthread_cond_broadcast()が呼ばれるまでスレッドを休止させる. abstimeの有無によって休止方法が異なる */
  if (abstime)
  {
    ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
  }
  else
  {
    ret = pthread_cond_wait(&ctx->cond, mutex); // abstimeが設定されていたら, 指定時刻にタスクを再開させる関数を使用. この関数では, mutexが, 停止時にunlock, 再開時にlockされる
  }
  /* end */
  ctx->wc--;
  if (ctx->interrupted)
  {
    if (!ctx->wc) // 休止中だったスレッド全てが再開したら(待ちスレッドが0なら)interruptedフラグを下げる
    {
      ctx->interrupted = 0;
    }
    errno = EINTR;
    return -1;
  }

  return ret;
}

int sched_wakeup(struct sched_ctx *ctx)
{
  return pthread_cond_broadcast(&ctx->cond);
}

int sched_interrupt(struct sched_ctx *ctx)
{
  ctx->interrupted = 1;
  return pthread_cond_broadcast(&ctx->cond);
}