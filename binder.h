#pragma once
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "unotify.h"

struct Addr {
    struct in_addr v4;
    struct in6_addr v6;
    bool only_v6;
};

class Binder {
public:
    Binder(const char *addr, const char *resolv_conf_path = nullptr);
    void bind(UNotifyEvent &event);
    void connect(UNotifyEvent &event);
private:
    bool should_bypass(const struct in_addr &addr);
    bool should_bypass(const struct in6_addr &addr);
    Addr bind_addr;
    std::vector<Addr> bypass_addr;
};