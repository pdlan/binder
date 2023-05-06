#pragma once
#include <memory>
#include <exception>
#include <stdexcept>
#include <vector>
#include <unordered_map>
#include <functional>
#include <cstddef>
#include <sys/types.h>
#include <seccomp.h>

class Exception : public std::runtime_error {
public:
    Exception(const std::string &msg) : std::runtime_error(msg) {}
    Exception(const char *msg) : std::runtime_error(msg) {}
};

class RemoteFile {
public:
    RemoteFile(int fd_);
    ~RemoteFile();
    inline int get() {
        return fd;
    }
private:
    int fd;
};

class RemoteProcess {
public:
    RemoteProcess(pid_t pid_);
    ~RemoteProcess();
    static bool detect_feature();
    std::shared_ptr<RemoteFile> get_file(int remote_fd);
    ssize_t read_memory(void *dst, const void *src, size_t len);
private:
    pid_t pid;
    int fd;
};

class SocketPair {
public:
    SocketPair();
    ~SocketPair();
    void send_fd(int fd);
    int recv_fd();
private:
    int fds[2];
};

class UNotifyEvent {
public:
    UNotifyEvent(struct seccomp_notif *req_, struct seccomp_notif_resp *resp_) : req(req_), resp(resp_) {}
    inline void cont() {
        resp->id = req->id;
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }

    inline void fail(int err) {
        resp->id = req->id;
        resp->error = err;
        resp->val = 0;
        resp->flags = 0;
    }

    template <typename T>
    inline void ret(T val) {
        resp->id = req->id;
        resp->error = 0;
        resp->val = (intptr_t)val;
        resp->flags = 0;
    }

    inline const struct seccomp_notif &get_req() {
        return *req;
    }
private:
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
};

struct UNotifyActions {
    inline static void cont(UNotifyEvent &event) {
        event.cont();
    }

    template <int Err>
    inline static void fail(UNotifyEvent &event) {
        event.fail(Err);
    }
};

class UNotifySupervisor {
public:
    using SyscallHandler = std::function<void (UNotifyEvent &)>;
    UNotifySupervisor(int notify_fd);
    ~UNotifySupervisor();
    void add_syscall(int sysno, const SyscallHandler &handler);
    void run();
private:
    std::unordered_map<int, SyscallHandler> handlers;
    int fd;
};

void exec_with_unotify(const char *file, char **argv,
                       const std::vector<int> &intercepted_syscalls,
                       SocketPair *socket_pair);