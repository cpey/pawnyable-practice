#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("Angus - Vulnerable Kernel Driver for Pawnyable");

#define DEVICE_NAME "angus"
#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

long xor(XorCipher *ctx) {
  size_t i;

  if (!ctx->data || !ctx->key) return -EINVAL;
  for (i = 0; i < ctx->datalen; i++)
    ctx->data[i] ^= ctx->key[i % ctx->keylen];
  return 0;
}

static int module_open(struct inode *inode, struct file *filp) {
  filp->private_data = NULL;
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  XorCipher *ctx;

  if ((ctx = (XorCipher*)filp->private_data)) {
    if (ctx->data) kfree(ctx->data);
    if (ctx->key) kfree(ctx->key);
    kfree(filp->private_data);
  }

  return 0;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  request_t req;
  XorCipher *ctx;

  if (copy_from_user(&req, (void*)arg, sizeof(request_t)))
    return -EINVAL;

  ctx = (XorCipher*)filp->private_data;

  switch (cmd) {
    case CMD_INIT:
      if (!ctx)
        filp->private_data = (void*)kzalloc(sizeof(XorCipher), GFP_KERNEL);
      if (!filp->private_data) return -ENOMEM;
      break;

    case CMD_SETKEY:
      if (!ctx) return -EINVAL;
      if (!req.ptr || req.len > 0x1000) return -EINVAL;
      if (ctx->key) kfree(ctx->key);
      if (!(ctx->key = (char*)kmalloc(req.len, GFP_KERNEL))) return -ENOMEM;

      if (copy_from_user(ctx->key, req.ptr, req.len)) {
        kfree(ctx->key);
        ctx->key = NULL;
        return -EINVAL;
      }

      ctx->keylen = req.len;
      break;

    case CMD_SETDATA:
      if (!ctx) return -EINVAL;
      if (!req.ptr || req.len > 0x1000) return -EINVAL;
      if (ctx->data) kfree(ctx->data);
      if (!(ctx->data = (char*)kmalloc(req.len, GFP_KERNEL))) return -ENOMEM;
      
      if (copy_from_user(ctx->data, req.ptr, req.len)) {
        kfree(ctx->key);
        ctx->key = NULL;
        return -EINVAL;
      }

      ctx->datalen = req.len;
      break;

    case CMD_GETDATA:
      if (!ctx->data) return -EINVAL;
      if (!req.ptr || req.len > ctx->datalen) return -EINVAL;
      if (copy_to_user(req.ptr, ctx->data, req.len)) return -EINVAL;
      break;

    case CMD_ENCRYPT:
    case CMD_DECRYPT:
      return xor(ctx);

    default: return -EINVAL;
  }

  return 0;
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .unlocked_ioctl = module_ioctl
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);
