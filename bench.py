"""比較 V1 與 V2 的上傳、下載時間（包含 JSON 儲存，不含 KDF）。"""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from server.storage import HonestServer
from v1.client import Client as V1Client
from v2.client import Client as V2Client


def benchmark(client_cls, root, size=10 * 1024**2, rounds=20) -> dict:
    """在 root 上傳及下載隨機資料 rounds 次，回傳平均秒數。"""
    if size < 0 or rounds <= 0:
        raise ValueError("size 必須非負，rounds 必須為正")
    client = client_cls(HonestServer(root), "benchmark password")
    data = os.urandom(size)
    upload_s = download_s = 0.0
    for i in range(rounds):
        start = perf_counter()
        file_id = client.upload(f"bench-{i}.bin", data)
        upload_s += perf_counter() - start
        start = perf_counter()
        downloaded = client.download(file_id)
        download_s += perf_counter() - start
        if downloaded != data:
            raise RuntimeError("benchmark 下載內容不符")
    return {"upload_avg_s": upload_s / rounds, "download_avg_s": download_s / rounds}


def main() -> None:
    print("10 MiB per file, 20 rounds (KDF excluded)")
    print("| Client | Upload avg (s) | Download avg (s) |")
    print("|--------|----------------|------------------|")
    with TemporaryDirectory(prefix="e2ee-bench-") as tmp:
        for label, client_cls in (("V1", V1Client), ("V2", V2Client)):
            result = benchmark(client_cls, Path(tmp) / label)
            print(f"| {label:<6} | {result['upload_avg_s']:>14.6f} | "
                  f"{result['download_avg_s']:>16.6f} |")


if __name__ == "__main__":
    main()
