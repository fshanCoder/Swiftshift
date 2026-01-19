#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <pthread.h>
#include <net/if.h>
 #include <stdio.h>
#include <string.h>

/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#define _GNU_SOURCE
#include <event2/event.h>
#include <memory.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>
#include "platform.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>
#else
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#include "getopt.h"
#endif

static struct event *ev_nl = NULL;
static int nl_sock = -1;

// 回调函数指针
static int (*g_on_ip_change_cb)(void *) = NULL;
static void *g_on_ip_change_arg = NULL;

static void netlink_event_cb(evutil_socket_t fd, short events, void *arg) {
    const char *target_ifname = (const char *)arg; 
    char buf[4096];
    int len = recv(fd, buf, sizeof(buf), 0);
    if (len > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr*)buf;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == RTM_NEWADDR) {
                struct ifaddrmsg *ifa = NLMSG_DATA(nh);
                char ifname[IFNAMSIZ];
                if_indextoname(ifa->ifa_index, ifname);
                if (strcmp(ifname, target_ifname) == 0 && g_on_ip_change_cb) {
                    g_on_ip_change_cb(g_on_ip_change_arg);
                }
            }
        }
    }
    event_add(ev_nl, NULL);
}

// 注册netlink事件，base为event_base，cb为IP变化时的回调，arg为回调参数
void register_netlink_event(struct event_base *base, int (*on_ip_change_cb)(void *), void *cb_arg, const char *ifname) {
    struct sockaddr_nl sa = {0};
    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_IPV4_IFADDR;
    bind(nl_sock, (struct sockaddr*)&sa, sizeof(sa));
    g_on_ip_change_cb = on_ip_change_cb;
    g_on_ip_change_arg = cb_arg;
    ev_nl = event_new(base, nl_sock, EV_READ|EV_PERSIST, netlink_event_cb, (void *)ifname);
    event_add(ev_nl, NULL);
}
