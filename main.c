#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>

#include <ps5/kernel.h>

// int kernel_copyout(unsigned long kaddr, void *uaddr, unsigned long len)

int main()
{
    signal(SIGPIPE, SIG_IGN);
    ///kdata size changes with 7.00 and up. 134 and 83 ???
    int buffer_size = 83 * 1024 * 1024;
    void* buffer = malloc(buffer_size);
    if (buffer == NULL)
    {
        printf("Failed to allocate buffer\n");
        return -1;
    }
    memset(buffer, 0, buffer_size);

    int ret = kernel_copyout(KERNEL_ADDRESS_DATA_BASE, buffer, buffer_size);
    if (ret != 0)
    {
        printf("Failed to copy out\n");
        free(buffer);
        return -1;
    }

    // write to file
    int fd = open("/data/kdata.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0)
    {
        printf("Failed to open file\n");
        free(buffer);
        return -1;
    }

    ret = write(fd, buffer, buffer_size);
    if (ret != buffer_size)
    {
        printf("Failed to write to file\n");
        free(buffer);
        close(fd);
        return -1;
    }

    close(fd);
    free(buffer);

    printf("Done\n");
    return 0;
}