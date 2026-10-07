# 运行方法（在本文件夹打开终端后输入）：
#   python collect_nvd.py
# 成功后双击 page.html，用浏览器查看。

from orchestrator import KEYWORD, collect_and_save, search


def main():
    cards = collect_and_save(KEYWORD)
    print("请双击 page.html 查看。")
    for card in cards[:5]:
        print("- %s  分数 %s" % (card["id"], card["cvss"]))
    demo = search("CVE-2025-0312")
    if demo:
        print("按编号能搜到 %s" % demo[0]["id"])


if __name__ == "__main__":
    main()
