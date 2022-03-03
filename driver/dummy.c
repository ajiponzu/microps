#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX

// 送信関数
static int dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=0%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    /* データを破棄 */
    return 0;
}

// 送信関数を登録したデバイスメソッド群を作成
static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit,
};

struct net_device *dummy_init(void)
{
    struct net_device *dev;

    /* デバイス生成 */
    dev = net_device_alloc();
    if (!dev)
    {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    /* end */
    dev->type = NET_DEVICE_TYPE_DUMMY; // net.h参照
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->ops = &dummy_ops;
    /* デバイスを登録 */
    if (net_device_register(dev) == -1)
    {
        errorf("net_device_register() failure");
        return NULL;
    }
    /* end */
    debugf("initialized, dev=%s", dev->name);

    return dev;
}