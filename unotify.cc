#include <cstring>
#include <csignal>
#include <cinttypes>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <seccomp.h>
#include "unotify.h"

RemoteFile::RemoteFile(int fd_) : fd(fd_) {
}

RemoteFile::~RemoteFile() {
    close(fd);
}

RemoteProcess::RemoteProcess(pid_t pid_) : pid(pid_), fd(-1) {
    fd = syscall(SYS_pidfd_open, pid, 0);
    if (fd == -1) {
        throw Exception("failed to open pidfd");
    }
}

RemoteProcess::~RemoteProcess() {
    close(fd);
}

bool RemoteProcess::detect_feature() {
    return syscall(SYS_pidfd_getfd, -1, -1, 0) == 0 || errno != -ENOSYS;
}

std::shared_ptr<RemoteFile> RemoteProcess::get_file(int remote_fd) {
    int local_fd = syscall(SYS_pidfd_getfd, fd, remote_fd, 0);
    if (local_fd == -1) {
        return nullptr;
    }
    return std::make_shared<RemoteFile>(local_fd);
}

ssize_t RemoteProcess::read_memory(void *dst, const void *src, size_t len) {
    struct iovec liov, riov;
    liov.iov_base = dst;
    liov.iov_len = len;
    riov.iov_base = (void *)src;
    riov.iov_len = len;
    return process_vm_readv(pid, &liov, 1, &riov, 1, 0);
}

SocketPair::SocketPair() {
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == -1) {
        throw Exception("failed to create socket pair");
    }
}

SocketPair::~SocketPair() {
    if (fds[0] != -1) {
        close(fds[0]);
    }
    if (fds[1] != -1) {
        close(fds[1]);
    }
}

void SocketPair::send_fd(int fd) {
    struct msghdr msgh;
    struct iovec iov;
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg;
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    int data = 0;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = cmsg.buf;
    msgh.msg_controllen = sizeof(cmsg.buf);
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));
    if (sendmsg(fds[0], &msgh, 0) == -1) {
        throw Exception("failed to send fd");
    }
}

int SocketPair::recv_fd() {
    struct msghdr msgh;
    struct iovec iov;
    int data, fd;
    ssize_t nr;
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg;
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = cmsg.buf;
    msgh.msg_controllen = sizeof(cmsg.buf);
    nr = recvmsg(fds[1], &msgh, 0);
    if (nr == -1) {
        throw Exception("failed to recvmsg");
    }
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    if (!cmsgp || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
        throw Exception("corrupted msg");
    }
    memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
    return fd;
}

UNotifySupervisor::UNotifySupervisor(int notify_fd) : fd(notify_fd) {
}

UNotifySupervisor::~UNotifySupervisor() {
}

void UNotifySupervisor::add_syscall(int sysno, const SyscallHandler &handler) {
    handlers[sysno] = handler;
}

void UNotifySupervisor::run() {
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
        throw Exception("failed to get seccomp notif sizes");
    }
    if (seccomp_notify_alloc(&req, &resp) < 0) {
        throw Exception("failed to alloc seccomp notif");
    }

    struct sigaction sa;
    sa.sa_handler = [] (int sig) {
        _exit(0);
    };
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw Exception("failed to set handler for SIGCHLD");
    }
    sigset_t set;
    sigfillset(&set);
    sigdelset(&set, SIGCHLD);
    sigprocmask(SIG_BLOCK, &set, nullptr);

    while (true) {
        memset(req, 0, sizes.seccomp_notif);
        if (seccomp_notify_receive(fd, req) < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw Exception("failed to recv seccomp notif");
        }
        UNotifyEvent event(req, resp);
        int sysno = req->data.nr;
        auto it = handlers.find(sysno);
        if (it != handlers.end()) {
            it->second(event);
        } else {
            event.fail(ENOSYS);
        }
        if (seccomp_notify_respond(fd, resp) < 0) {
            if (errno == ENOENT) {
                continue;
            }
            throw Exception("failed to send seccomp notif");
        }
    }
}

void exec_with_unotify(const char *file, char **argv,
                       const std::vector<int> &intercepted_syscalls,
                       SocketPair *socket_pair) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        throw Exception("failed to init Seccomp");
    }
    for (int sysno : intercepted_syscalls) {
        if (seccomp_rule_add_exact(ctx, SCMP_ACT_NOTIFY, sysno, 0) < 0) {
            throw Exception("failed to add Seccomp rule");
        }
    }
    seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ALLOW);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_SSB, 1);
    if (seccomp_load(ctx) < 0) {
        throw Exception("failed to apply Seccomp");
    }
    int ufd = seccomp_notify_fd(ctx);
    if (ufd < 0) {
        throw Exception("failed to get Seccomp unotify fd");
    }
    socket_pair->send_fd(ufd);
    close(ufd);

    if (execvp(file, argv) == -1) {
        throw Exception("failed to exec");
    }
}