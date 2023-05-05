#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <functional>
#include <csignal>
#include <climits>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <seccomp.h>

struct Addr {
    struct in_addr v4;
    struct in6_addr v6;
    bool only_v6;
};

Addr bind_addr;
std::vector<Addr> bypass_addr;

static int get_process_fd(pid_t pid, int fd) {
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    if (pid == -1) {
        return -1;
    }
    int new_fd = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
    if (!new_fd) {
        close(pidfd);
        return -1;
    }
    return new_fd;
}

static ssize_t read_process_mem(pid_t pid, void *local_addr, void *remote_addr, size_t len) {
    struct iovec local_iov, remote_iov;
    local_iov.iov_base = local_addr;
    local_iov.iov_len = len;
    remote_iov.iov_base = remote_addr;
    remote_iov.iov_len = len;
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

inline static void continue_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    resp->id = req->id;
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
}

inline static void fail_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int err) {
    resp->id = req->id;
    resp->error = err;
    resp->val = 0;
    resp->flags = 0;
}

static void handle_bind(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    pid_t pid = req->pid;
    int fd = req->data.args[0];
    struct sockaddr *paddr = (struct sockaddr *)req->data.args[1];
    struct sockaddr_storage addr;
    socklen_t len = req->data.args[2], optlen;
    int domain, type, res;
    if (len > sizeof(struct sockaddr_storage)) {
        goto cont;
    }
    if (read_process_mem(pid, &addr, paddr, len) == -1) {
        goto cont;
    }
    fd = get_process_fd(pid, fd);
    if (fd == -1) {
        goto cont;
    }
    domain = addr.ss_family;
    if (domain != AF_INET && domain != AF_INET6) {
        goto cont_close;
    }
    optlen = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen) == -1) {
        goto cont_close;
    }
    if (type != SOCK_STREAM) {
        goto cont_close;
    }
    if (domain == AF_INET) {
        if (len != sizeof(struct sockaddr_in)) {
            goto cont_close;
        }
        struct sockaddr_in *inaddr = (struct sockaddr_in *)&addr;
        int port = inaddr->sin_port;
        if (bind_addr.only_v6) {
            goto fail;
        }
        memcpy(&inaddr->sin_addr, &bind_addr.v4, sizeof(struct in_addr));
        res = bind(fd, (struct sockaddr *)inaddr, sizeof(struct sockaddr_in));
    } else {
        if (len != sizeof(struct sockaddr_in6)) {
            goto cont_close;
        }
        struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *)&addr;
        memcpy(&in6addr->sin6_addr, &bind_addr.v6, sizeof(struct in6_addr));
        res = bind(fd, (struct sockaddr *)in6addr, sizeof(struct sockaddr_in6));
    }
    if (res == -1) {
        fail_syscall(req, resp, errno);
    } else {
        resp->id = req->id;
        resp->error = 0;
        resp->val = res;
        resp->flags = 0;
    }
    close(fd);
    return;
cont_close:
    close(fd);
cont:
    continue_syscall(req, resp);
    return;
fail:
    close(fd);
    fail_syscall(req, resp, ECONNREFUSED);
}

static bool should_bypass(const struct in_addr &addr) {
    for (Addr &a : bypass_addr) {
        if (a.only_v6) {
            continue;
        }
        if (memcmp(&a.v4, &addr, sizeof(struct in_addr)) == 0) {
            return true;
        }
    }
    return false;
}

static bool should_bypass(const struct in6_addr &addr) {
    for (Addr &a : bypass_addr) {
        if (memcmp(&a.v6, &addr, sizeof(struct in6_addr)) == 0) {
            return true;
        }
    }
    return false;
}

static void handle_connect(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    pid_t pid = req->pid;
    int fd = req->data.args[0];
    struct sockaddr *paddr = (struct sockaddr *)req->data.args[1];
    struct sockaddr_storage addr;
    socklen_t len = req->data.args[2];
    int domain, type, res;
    if (len > sizeof(struct sockaddr_storage)) {
        goto cont;
    }
    if (read_process_mem(pid, &addr, paddr, len) == -1) {
        goto cont;
    }
    fd = get_process_fd(pid, fd);
    if (fd == -1) {
        goto cont;
    }
    domain = addr.ss_family;
    if (domain != AF_INET && domain != AF_INET6) {
        goto cont_close;
    }
    if (domain == AF_INET) {
        if (len != sizeof(struct sockaddr_in)) {
            goto cont_close;
        }
        struct sockaddr_in *inaddr = (struct sockaddr_in *)&addr;
        if (should_bypass(inaddr->sin_addr)) {
            goto cont_close;
        }
        if (bind_addr.only_v6) {
            goto fail;
        }
        memcpy(&inaddr->sin_addr, &bind_addr.v4, sizeof(struct in_addr));
        inaddr->sin_port = 0; // bind any port
        bind(fd, (struct sockaddr *)inaddr, sizeof(struct sockaddr_in));
    } else {
        if (len != sizeof(struct sockaddr_in6)) {
            goto cont_close;
        }
        if (should_bypass(((struct sockaddr_in6 *)&addr)->sin6_addr)) {
            goto cont_close;
        }
        struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *)&addr;
        memcpy(&in6addr->sin6_addr, &bind_addr.v6, sizeof(struct in6_addr));
        in6addr->sin6_port = 0; // bind any port
        bind(fd, (struct sockaddr *)in6addr, sizeof(struct sockaddr_in6));
    }
cont_close:
    close(fd);
cont:
    continue_syscall(req, resp);
    return;
fail:
    close(fd);
    fail_syscall(req, resp, ECONNREFUSED);
}

static int recvfd(int sockfd) {
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
    nr = recvmsg(sockfd, &msgh, 0);
    if (nr == -1) {
        throw std::runtime_error("failed to recvmsg");
    }
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msgh);
    if (!cmsgp || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
        throw std::runtime_error("corrupted msg");
    }
    memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
    return fd;
}

static void sendfd(int sockfd, int fd) {
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
    if (sendmsg(sockfd, &msgh, 0) == -1) {
        throw std::runtime_error("failed to send fd");
    }
}

static void run_program_with_unotify(const char *file, char **argv, int sockfd[2]) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add_exact(ctx, SCMP_ACT_NOTIFY, SYS_bind, 0);
    seccomp_rule_add_exact(ctx, SCMP_ACT_NOTIFY, SYS_connect, 0);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_SSB, 1);
    seccomp_load(ctx);
    int ufd = seccomp_notify_fd(ctx);
    sendfd(sockfd[0], ufd);
    close(ufd);
    close(sockfd[0]);
    close(sockfd[1]);

    if (execvp(file, argv) == -1) {
        throw std::runtime_error("failed to exec");
    }
}

static void handle_unotify(int ufd) {
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
        throw std::runtime_error("failed to get seccomp notif sizes");
    }
    if (seccomp_notify_alloc(&req, &resp) < 0) {
        throw std::runtime_error("failed to alloc seccomp notif");
    }
    while (true) {
        memset(req, 0, sizes.seccomp_notif);
        if (seccomp_notify_receive(ufd, req) < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("failed to recv seccomp notif");
        }
        int sysno = req->data.nr;
        switch (sysno) {
        case SYS_bind:
            handle_bind(req, resp);
            break;
        case SYS_connect:
            handle_connect(req, resp);
            break;
        default:
            resp->id = req->id;
            resp->error = -ENOSYS;
            resp->val = 0;
            resp->flags = 0;
        }
        if (seccomp_notify_respond(ufd, resp) < 0) {
            if (errno == ENOENT) {
                continue;
            }
            throw std::runtime_error("failed to send seccomp notif");
        }
    }
}

static void supervisor(int sockfd[2]) {
    int ufd = recvfd(sockfd[1]);
    close(sockfd[0]);
    close(sockfd[1]);
    handle_unotify(ufd);
}

static void run_program(int argc, char **argv) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
        throw std::runtime_error("failed to create socketpair");
    }

    struct sigaction sa;
    sa.sa_handler = [] (int sig) {
        _exit(0);
    };
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw std::runtime_error("failed to set handler for SIGCHLD");
    }

    pid_t pid = fork();
    if (pid == -1) {
        throw std::runtime_error("failed to fork");
    }
    if (pid == 0) {
        run_program_with_unotify(argv[0], argv, fds);
        return;
    }
    sigset_t set;
    sigfillset(&set);
    sigdelset(&set, SIGCHLD);
    sigprocmask(SIG_BLOCK, &set, nullptr);
    supervisor(fds);
    exit(0);
}

static bool load_addr(const char *str, Addr &addr) {
    if (strchr(str, ':')) {
        addr.only_v6 = true;
        if (inet_pton(AF_INET6, str, &addr.v6) != 1) {
            return false;
        }
    } else {
        addr.only_v6 = false;
        if (inet_aton(str, &addr.v4) != 1) {
            return false;
        }
        // IPv4-mapped IPv6 adderss
        memset(addr.v6.s6_addr + 10, 0xff, 2);
        memset(addr.v6.s6_addr, 0, 10);
        memcpy(addr.v6.s6_addr + 12, &addr.v4.s_addr, 4);
    }
    return true;
}

static void load_bind_addr() {
    char *addr_str = getenv("BIND_ADDRESS");
    if (!addr_str) {
        throw std::runtime_error("failed to load bind address");
    }
    if (!load_addr(addr_str, bind_addr)) {
        throw std::runtime_error("invalid bind address");
    }
    std::ifstream ifs("/etc/resolv.conf");
    if (!ifs){
        return;
    }
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.size() >= 1 && (line[0] == '#' || line[0] == ';')) {
            continue;
        }
        std::string pattern = "nameserver ";
        size_t len_pattern = pattern.length();
        if (line.substr(0, len_pattern) != pattern) {
            continue;
        }
        const std::string &str = line.substr(len_pattern);
        Addr addr;
        if (!load_addr(str.c_str(), addr)) {
            continue;
        }
        bypass_addr.push_back(addr);
    }
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        std::cerr << "Usage: ./binder <COMMAND> [ARG]...";
        return 1;
    }
    load_bind_addr();
    run_program(argc - 1, argv + 1);
    return 0;
}
