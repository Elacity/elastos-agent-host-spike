/* TIOCGWINSZ on inherited fd 3 (pty opened before confine). */
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    struct winsize ws;
    int ret = ioctl(3, TIOCGWINSZ, &ws);
    if (ret == 0) {
        printf("inherit_ioctl ok rows=%u cols=%u\n", ws.ws_row, ws.ws_col);
    } else {
        printf("inherit_ioctl errno=%d\n", errno);
    }
    fflush(stdout);
    return ret == 0 ? 0 : 1;
}
