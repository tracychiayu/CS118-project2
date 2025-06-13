#include <stdint.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>

void init_io() {
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags);
}

ssize_t input_io(uint8_t* buf, size_t max_length) {
    ssize_t len = read(STDIN_FILENO, buf, max_length);
    if (len <= 0){
        if (errno == EAGAIN || errno == EWOULDBLOCK){
            return -1;  // no data available yet
        }
        return 0;  // EOF or real error
    }
    return len;
}

void output_io(uint8_t* buf, size_t length) {
    write(STDOUT_FILENO, buf, length);
}
