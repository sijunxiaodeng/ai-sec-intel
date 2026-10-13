# 运行方法（在本文件夹打开终端后输入）：
#   python collect_nvd.py
# 兼容旧命令：同步 B 已采集的数据。真实多源采集统一使用
# python intelligence/run_monitor.py --once；网页使用 python main.py。

from orchestrator import KEYWORD, collect_and_save, search


def main():
    cards = collect_and_save(KEYWORD)
    print("已同步 B 情报库；运行 python main.py 查看。真实采集入口为 intelligence/run_monitor.py。")
    for card in cards[:5]:
        print("- %s  分数 %s" % (card["id"], card["cvss"]))
    demo = search("CVE-2025-0312")
    if demo:
        print("按编号能搜到 %s" % demo[0]["id"])


if __name__ == "__main__":
    main()
