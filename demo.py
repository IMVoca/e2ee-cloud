"""一鍵展示正常操作與三種攻擊，所有資料都存於暫存目錄。"""

from pathlib import Path
from tempfile import TemporaryDirectory
from unicodedata import east_asian_width

from common.errors import IntegrityError
from server.malicious import MaliciousServer
from server.storage import HonestServer
from v1.client import Client as V1Client
from v2.client import Client as V2Client

PASSWORD = "demo password"
TRANSFER = b"Transfer $0100 to Alice. Approved by Bob."


def _table(headers: tuple, rows: list[tuple]) -> None:
    def width(text):
        return sum(2 if east_asian_width(ch) in "WF" else 1 for ch in text)

    widths = [max(width(str(row[i])) for row in [headers, *rows])
              for i in range(len(headers))]

    def line(row):
        return "| " + " | ".join(
            str(value) + " " * (size - width(str(value)))
            for value, size in zip(row, widths)
        ) + " |"

    print(line(headers))
    print("|" + "|".join("-" * (size + 2) for size in widths) + "|")
    for row in rows:
        print(line(row))


def _attacks(client_cls, root: Path) -> list[tuple]:
    rows = []
    for attack in ("竄改內容", "植入檔案", "對調檔名"):
        server = MaliciousServer(root / attack)
        client = client_cls(server, PASSWORD)
        if attack == "竄改內容":
            fid = client.upload("transfer.txt", TRANSFER)
            server.tamper_content(fid, TRANSFER.index(b"0100"), b"0100", b"9100")

            def observe():
                return client.download(fid).decode()

            expected = TRANSFER.replace(b"0100", b"9100").decode()
        elif attack == "植入檔案":
            source = client.upload("report.pdf", b"real report")
            fake = server.inject_file("confession.txt", source)

            def observe():
                name = dict(client.list_files())[fake]
                return f"{name}: {client.download(fake).decode()}"

            expected = "confession.txt: real report"
        else:
            a = client.upload("a.txt", b"content of A")
            b = client.upload("b.txt", b"content of B")
            server.swap_names(a, b)

            def observe():
                by_name = {name: fid for fid, name in client.list_files()}
                return f"a.txt: {client.download(by_name['a.txt']).decode()}"

            expected = "a.txt: content of B"
        try:
            evidence = observe()
        except IntegrityError:
            if client_cls is not V2Client:
                raise
            rows.append((attack, "偵測並拒絕（IntegrityError）"))
        else:
            if client_cls is V2Client or evidence != expected:
                raise RuntimeError(f"{attack} 展示結果不符預期")
            rows.append((attack, f"攻擊成功；{evidence}"))
    return rows


def main() -> None:
    with TemporaryDirectory(prefix="e2ee-demo-") as tmp:
        root = Path(tmp)
        client = V1Client(HonestServer(root / "normal"), PASSWORD)
        fid = client.upload("hello.txt", b"Hello, E2EE cloud!")
        content = client.download(fid)
        listing = client.list_files()
        if content != b"Hello, E2EE cloud!" or listing != [(fid, "hello.txt")]:
            raise RuntimeError("正常操作展示失敗")
        print("V1 正常")
        _table(("操作", "結果"), [
            ("上傳／下載", f"成功；{content.decode()}"),
            ("列出檔案", f"成功；{listing[0][1]}"),
        ])
        for label, client_cls in (("V1", V1Client), ("V2", V2Client)):
            print(f"\n{label} 受攻擊")
            _table(("攻擊", "結果與證據"), _attacks(client_cls, root / label))


if __name__ == "__main__":
    main()
