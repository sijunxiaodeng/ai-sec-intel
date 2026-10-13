"""Explicit demo network boundary; never enabled by production defaults."""
import ipaddress
import os
import sys

_INSTALLED = False


def enabled():
    return os.environ.get("OFFLINE_DEMO") == "1"


def install_guard():
    global _INSTALLED
    if _INSTALLED:
        return

    def check(event, args):
        if event == "socket.getaddrinfo":
            host = args[0]
        elif event == "socket.connect":
            address = args[1]
            if not isinstance(address, tuple):
                return  # Local Unix socket.
            host = address[0]
        else:
            return
        if host in {None, "localhost", b"localhost"}:
            return
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback or (event == "socket.getaddrinfo" and address.is_unspecified):
                return
        except ValueError:
            pass
        raise OSError("离线演示禁止外部网络；真实采集请使用正式运行入口")

    sys.addaudithook(check)
    _INSTALLED = True
