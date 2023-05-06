#include <memory>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include "unotify.h"
#include "binder.h"

int main(int argc, char **argv) {
    if (argc <= 1) {
        std::cerr << "Usage: BIND_ADDRESS=<ip> ./binder <COMMAND> [ARG]...\n";
        return 1;
    }
    if (!RemoteProcess::detect_feature()) {
        std::cerr << "Warning: Linux 5.6 or higher is requried for binder.\n";
        if (execvp(argv[1], argv + 1) == -1) {
            throw Exception("failed to exec");
        }
        return 1;
    }
    const char *bind_address = getenv("BIND_ADDRESS");
    if (!bind_address) {
        throw Exception("failed to load BIND_ADDRESS");
    }
    std::unique_ptr<SocketPair> socket_pair(new SocketPair);
    pid_t pid = fork();
    if (pid == -1) {
        throw Exception("failed to fork");
    }
    if (pid == 0) {
        exec_with_unotify(argv[1], argv + 1, {SYS_bind, SYS_connect}, socket_pair.get());
    } else {
        int ufd = socket_pair->recv_fd();
        socket_pair.reset();
        Binder binder(bind_address, "/etc/resolv.conf");
        UNotifySupervisor supervisor(ufd);
        supervisor.add_syscall(SYS_bind, [&] (UNotifyEvent &event) {
            binder.bind(event);
        });
        supervisor.add_syscall(SYS_connect, [&] (UNotifyEvent &event) {
            binder.connect(event);
        });
        supervisor.run();
    }
    return 0;
}