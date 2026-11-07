/* Static stand-in. Prints one line if a second image ran. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("payload pid=%d\n", (int)getpid());
    fflush(stdout);
    return 0;
}
