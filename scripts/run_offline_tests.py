"""Run unittest without public-network calls; loopback HTTP fixtures remain usable."""
import argparse
from contextlib import ExitStack
import ipaddress
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-directory", required=True)
    parser.add_argument("--pattern", default="test_*.py")
    args = parser.parse_args()
    # B intentionally has its own top-level collectors/storage packages.
    sys.path.insert(0, str(Path.cwd()))
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def guard(address):
        if not isinstance(address, tuple):  # Unix-domain sockets are local.
            return
        host = str(address[0])
        if host == "localhost":
            return
        try:
            if ipaddress.ip_address(host).is_loopback:
                return
        except ValueError:
            pass
        raise OSError("Offline tests prohibit public-network socket connections")

    def connect(sock, address):
        guard(address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        guard(address)
        return original_connect_ex(sock, address)

    with ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket, "connect", connect))
        stack.enter_context(patch.object(socket.socket, "connect_ex", connect_ex))
        suite = unittest.defaultTestLoader.discover(args.start_directory, pattern=args.pattern)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
