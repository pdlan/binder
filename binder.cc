#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "unotify.h"
#include "binder.h"

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

Binder::Binder(const char *addr, const char *resolv_conf_path) {
    if (!load_addr(addr, bind_addr)) {
        throw Exception("invalid bind address");
    }
    if (!resolv_conf_path) {
        return;
    }
    std::ifstream ifs(resolv_conf_path);
    if (!ifs) {
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

void Binder::bind(UNotifyEvent &event) {
    try {
        const struct seccomp_notif &req = event.get_req();
        RemoteProcess proc(req.pid);
        int remotefd = req.data.args[0];
        struct sockaddr *paddr = (struct sockaddr *)req.data.args[1];
        socklen_t len = req.data.args[2];
        std::shared_ptr<RemoteFile> sock = proc.get_file(remotefd);
        if (!sock) {
            return event.cont();
        }
        int fd = sock->get();
        struct sockaddr_storage addr;
        if (len > sizeof(struct sockaddr_storage) || proc.read_memory(&addr, paddr, len) == -1) {
            return event.cont();
        }
        int domain = addr.ss_family;
        if (domain != AF_INET && domain != AF_INET6) {
            return event.cont();
        }
        socklen_t optlen = sizeof(int);
        int type;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen) == -1 || type != SOCK_STREAM) {
            return event.cont();
        }
        int res;
        if (domain == AF_INET) {
            if (len != sizeof(struct sockaddr_in)) {
                return event.cont();
            }
            struct sockaddr_in *inaddr = (struct sockaddr_in *)&addr;
            if (bind_addr.only_v6) {
                return event.fail(EACCES);
            }
            memcpy(&inaddr->sin_addr, &bind_addr.v4, sizeof(struct in_addr));
            res = ::bind(fd, (struct sockaddr *)inaddr, sizeof(struct sockaddr_in));
        } else {
            if (len != sizeof(struct sockaddr_in6)) {
                return event.cont();
            }
            struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *)&addr;
            memcpy(&in6addr->sin6_addr, &bind_addr.v6, sizeof(struct in6_addr));
            res = ::bind(fd, (struct sockaddr *)in6addr, sizeof(struct sockaddr_in6));
        }
        if (res == -1) {
            event.fail(errno);
        } else {
            event.ret(res);
        }
    } catch (Exception &e) {
        event.cont();
    }
}

void Binder::connect(UNotifyEvent &event) {
    try {
        const struct seccomp_notif &req = event.get_req();
        RemoteProcess proc(req.pid);
        int remotefd = req.data.args[0];
        struct sockaddr *paddr = (struct sockaddr *)req.data.args[1];
        socklen_t len = req.data.args[2];
        std::shared_ptr<RemoteFile> sock = proc.get_file(remotefd);
        if (!sock) {
            return event.cont();
        }
        int fd = sock->get();
        struct sockaddr_storage addr;
        if (len > sizeof(struct sockaddr_storage) || proc.read_memory(&addr, paddr, len) == -1) {
            return event.cont();
        }
        int domain = addr.ss_family;
        if (domain != AF_INET && domain != AF_INET6) {
            return event.cont();
        }
        if (domain == AF_INET) {
            if (len != sizeof(struct sockaddr_in)) {
                return event.cont();
            }
            struct sockaddr_in *inaddr = (struct sockaddr_in *)&addr;
            if (should_bypass(inaddr->sin_addr)) {
                return event.cont();
            }
            if (bind_addr.only_v6) {
                return event.fail(ECONNREFUSED);
            }
            memcpy(&inaddr->sin_addr, &bind_addr.v4, sizeof(struct in_addr));
            inaddr->sin_port = 0; // bind any port;
            ::bind(fd, (struct sockaddr *)inaddr, sizeof(struct sockaddr_in));
        } else {
            if (len != sizeof(struct sockaddr_in6)) {
                return event.cont();
            }
            struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *)&addr;
            if (should_bypass(in6addr->sin6_addr)) {
                return event.cont();
            }
            memcpy(&in6addr->sin6_addr, &bind_addr.v6, sizeof(struct in6_addr));
            in6addr->sin6_port = 0; // bind any port;
            ::bind(fd, (struct sockaddr *)in6addr, sizeof(struct sockaddr_in6));
        }
    } catch (Exception &e) {
    }
    event.cont();
}

bool Binder::should_bypass(const struct in_addr &addr) {
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

bool Binder::should_bypass(const struct in6_addr &addr) {
    for (Addr &a : bypass_addr) {
        if (memcmp(&a.v6, &addr, sizeof(struct in6_addr)) == 0) {
            return true;
        }
    }
    return false;
}
