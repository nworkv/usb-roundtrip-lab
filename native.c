#include <linux/usb/raw_gadget.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
static int result(int r) { return r < 0 ? -errno : r; }
int rg_open(const char *driver, const char *device) {
    struct usb_raw_init init = {0};
    if (strlen(driver) >= 128 || strlen(device) >= 128) return -EINVAL;
    strcpy((char *)init.driver_name, driver);
    strcpy((char *)init.device_name, device);
    init.speed = USB_SPEED_FULL;
    int fd = open("/dev/raw-gadget", O_RDWR);
    if (fd < 0) return -errno;
    if (ioctl(fd, USB_RAW_IOCTL_INIT, &init) < 0 ||
        ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
        int e = errno; close(fd); return -e;
    }
    return fd;
}
int rg_event(int fd, unsigned char *setup) {
    struct usb_raw_event *e = calloc(1, sizeof(*e) + 256);
    if (!e) return -ENOMEM;
    e->length = 256;
    int r = ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, e);
    if (r < 0) r = -errno;
    else if (e->type == USB_RAW_EVENT_CONTROL && e->length != 8) r = -EPROTO;
    else { r = e->type; if (r == USB_RAW_EVENT_CONTROL) memcpy(setup, e->data, 8); }
    free(e); return r;
}
int rg_io(int fd, int in, unsigned char *data, unsigned int len, int zero) {
    if (len > 65535) return -EINVAL;
    struct usb_raw_ep_io *io = calloc(1, sizeof(*io) + len);
    if (!io) return -ENOMEM;
    io->length = len;
    io->flags = zero ? USB_RAW_IO_FLAGS_ZERO : 0;
    if (in && len) memcpy(io->data, data, len);
    int r = result(ioctl(fd, in ? USB_RAW_IOCTL_EP0_WRITE : USB_RAW_IOCTL_EP0_READ, io));
    if (!in && r > 0) memcpy(data, io->data, r);
    free(io); return r;
}
int rg_stall(int fd) { return result(ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0)); }
int rg_configure(int fd) { return result(ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0)); }
