"""Start the standalone B module API on localhost only; does not affect the scheduler."""
from __future__ import annotations

import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="B 模块 V6 SQLite 只读查询接口")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    uvicorn.run("api_v6.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
