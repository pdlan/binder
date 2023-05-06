# binder
This tool forces a program to bind on a specific address. Also, it adds a `bind()` before every `connect()`.
It only affects the `AF_INET` and `AF_INET6` domains with the `SOCK_STREAM` type.

# Usage
```shell
BIND_ADDRESS=<ip> ./binder <cmd> [args]...
```
It will load `/etc/resolv.conf` if possible and will not bind on `BIND_ADDRESS`
if the IP requested by `bind()` or `connect()` is in the DNS server list.

# License
The code written by me is published in the public domain and you may arbitrarily use it.
However, it needs to be linked with a LGPL library libseccomp. So, the license
of the whole program may be different.