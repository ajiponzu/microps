#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>

/*
 * Memory
 */

static inline void *
memory_alloc(size_t size)
{
    return calloc(1, size);
}

static inline void
memory_free(void *ptr)
{
    free(ptr);
}

/*
 * Interrupt
 */

#define INTR_IRQ_BASE (SIGRTMIN + 1)
#define INTR_IRQ_SOFTIRQ SIGUSR1
#define INTR_IRQ_EVENT SIGUSR2

#define INTR_IRQ_SHARED 0x0001

// 割り込み要求
extern int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *id), int flags, const char *name, void *dev);

// 割り込み起動関数
extern int intr_raise_irq(unsigned int irq);

// 割り込み実行関数
extern int intr_run(void);

// 割り込み停止関数
extern void intr_shutdown(void);

// 割り込み初期化
extern int intr_init(void);

/*
 * Mutex
 */

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline int mutex_init(mutex_t *mutex)
{
    return pthread_mutex_init(mutex, NULL);
}

static inline int mutex_lock(mutex_t *mutex)
{
    return pthread_mutex_lock(mutex);
}

static inline int mutex_unlock(mutex_t *mutex)
{
    return pthread_mutex_unlock(mutex);
}

// タスクスケジューラ
struct sched_ctx
{
    pthread_cond_t cond;
    int interrupted;
    int wc; /* wait count */
};

#define SCHED_CTX_INITIALIZER          \
    {                                  \
        PTHREAD_COND_INITIALIZER, 0, 0 \
    }

// スケジューラの初期化
extern int sched_ctx_init(struct sched_ctx *ctx);

// 条件変数の破棄(待機中のスレッドが存在する場合はエラー)
extern int sched_ctx_destroy(struct sched_ctx *ctx);

// タスクの休止
extern int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime);

// 休止中タスクの再開
extern int sched_wakeup(struct sched_ctx *ctx);

// interruptedフラグを立てたうえで, 休止スレッドを再開させる. つまり割り込む
extern int sched_interrupt(struct sched_ctx *ctx);

#endif
