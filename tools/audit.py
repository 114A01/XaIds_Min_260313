#!/usr/bin/env python3
"""
前端稽核：用無頭瀏覽器把每一頁以亮、暗兩種主題各開一次，檢查
  * 有沒有 console 錯誤、JavaScript 例外、失敗或 4xx / 5xx 的請求
  * 圖表的 canvas 是否畫出來
  * 幾個主要互動（切換 k、篩選、展示頁的即時警報時間）
並把每一頁截圖存到 --shots 指定的資料夾。

    python -m venv pwenv && pwenv/bin/pip install playwright && pwenv/bin/playwright install chromium
    uvicorn api.main:app --port 8099      # 驗證用的伺服器
    python tools/smoke_test.py --base http://localhost:8099 --keep      # 先產生一些資料
    pwenv/bin/python tools/audit.py --base http://localhost:8099 --shots /tmp/xaids_shots

資料庫裡至少要有一次有 flow 的測試。這支程式只讀取，不會建立或修改測試
（--live 例外：它會啟動一次 30 筆的 pcap 重播來檢查展示頁的即時更新，結束後刪除）。
"""

import argparse
import json
import pathlib
import re
import time
import urllib.request

from playwright.sync_api import sync_playwright


def get(base, path):
    return json.load(urllib.request.urlopen(base + path, timeout=60))


def call(base, path, method, body=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=(json.dumps(body).encode() if body is not None else None),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://localhost:8099")
    ap.add_argument("--shots", default="audit_shots", help="截圖輸出資料夾")
    ap.add_argument("--live", action="store_true", help="另外啟動一次短的 pcap 重播，檢查展示頁的即時更新")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    shots = pathlib.Path(args.shots)
    shots.mkdir(parents=True, exist_ok=True)
    problems = []

    runs = [r for r in get(base, "/api/runs") if r["flow_count"]]
    if not runs:
        raise SystemExit("資料庫裡沒有任何有 flow 的測試，請先跑 tools/smoke_test.py --keep")
    run = runs[0]
    flow_id = get(base, f"/api/runs/{run['run_id']}/flows?limit=1")["items"][0]["id"]
    pages = {
        "index": "/", "test": "/test", "history": "/history", "run_detail": f"/history/{run['run_id']}",
        "demo": "/demo", "explain": f"/explain/{flow_id}", "packets": "/packetRecord",
    }

    def note(page, msg):
        problems.append(f"{page}: {msg}")
        print(f"   !! {msg}")

    with sync_playwright() as p:
        browser = p.chromium.launch()

        def open_page(path, theme="dark"):
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            ctx.add_init_script(f"localStorage.setItem('xaids-theme','{theme}')")
            pg = ctx.new_page()
            errors = []
            pg.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type in ("error", "warning") else None)
            pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            pg.on("requestfailed", lambda r: errors.append(f"requestfailed: {r.url}") if "/stream" not in r.url else None)
            pg.on("response", lambda r: errors.append(f"{r.status} {r.url}") if r.status >= 400 else None)
            # 展示頁與測試頁有輪詢與 SSE，永遠不會 networkidle，所以等 load 再固定等一下
            pg.goto(base + path, wait_until="load")
            pg.wait_for_timeout(2500)
            return ctx, pg, errors

        for name, path in pages.items():
            for theme in ("dark", "light"):
                ctx, pg, errors = open_page(path, theme)
                canvases = pg.evaluate("Array.from(document.querySelectorAll('canvas')).map(c => c.width > 0 && c.height > 0)")
                pg.screenshot(path=str(shots / f"{name}_{theme}.png"), full_page=True)
                print(f"== {name} [{theme}] canvases={len(canvases)} errors={len(errors)}")
                for e in errors:
                    note(name, e)
                if not all(canvases):
                    note(name, "有 canvas 沒有畫出來")
                if theme == "light":
                    ctx.close()
                    continue

                if name == "index":
                    if pg.inner_text("#modelName") in ("", "—"):
                        note(name, "模型名稱沒有載入")
                if name == "test":
                    n_csv, n_lab = pg.locator("#csvSelect option").count(), pg.locator("#labelSelect option").count()
                    print(f"   CSV 選項 {n_csv}，標籤選項 {n_lab}，最多處理筆數預設 {pg.input_value('#maxRows')}")
                    if n_lab < 2:
                        note(name, "標籤下拉選單是空的")
                if name in ("history", "run_detail"):
                    if len(canvases) != 5:
                        note(name, f"應該有 5 張圖，實際 {len(canvases)}")
                    tiles = pg.locator(".sum-tile").count()
                    if tiles != 6:
                        note(name, f"摘要列應該有 6 格，實際 {tiles}")
                    pg.click(".k-btn[data-k='3']")
                    pg.wait_for_timeout(1200)
                    if "/ 3" not in pg.locator(".sum-tile").nth(2).inner_text():
                        note(name, "切到 k=3 後摘要列沒有更新")
                    pg.click(".k-btn[data-k='5']")
                    pg.wait_for_timeout(600)
                if name == "history":
                    rows, checked = pg.locator("#runBody tr").count(), pg.locator("#runFilter input:checked").count()
                    print(f"   測試列表 {rows} 列，RUN FILTER 預設勾選 {checked} 個")
                if name == "run_detail":
                    before = pg.locator("#flowBody tr").count()
                    pg.select_option("#fCorrect", "true")
                    pg.wait_for_timeout(800)
                    print(f"   flow 列 {before}，只看正確：{pg.inner_text('#flowMeta')}")
                if name == "explain":
                    n_shap, n_lime = pg.locator("#shap-features .bar-track").count(), pg.locator("#lime-features .bar-track").count()
                    cards = pg.locator("#consistency .card").count()
                    print(f"   SHAP {n_shap} 條、LIME {n_lime} 條、一致性卡片 {cards} 張")
                    if not (n_shap and n_shap == n_lime and cards == 3):
                        note(name, "解釋或一致性卡片數量不對")
                if name == "demo":
                    print(f"   警報列 {pg.locator('#alertBody tr').count()}，狀態 {pg.inner_text('#statusBadge')}")
                if name == "packets":
                    print(f"   {pg.inner_text('#meta')}")
                ctx.close()

        if args.live:
            print("== demo [live]：頁面開著時啟動一次 pcap 重播")
            ctx, pg, errors = open_page("/demo")
            started = call(base, "/run/start", "POST", {"source_type": "pcap", "source": "syn-flood_1110.pcap",
                                                        "name": "audit live", "expected_label": "DoS", "max_rows": 30})
            time.sleep(1)
            while get(base, "/run/status")["running"]:
                time.sleep(0.5)
            pg.wait_for_timeout(3000)
            feed = pg.locator("#feedBody tr").count()
            first_time = pg.locator("#alertBody tr td").first.inner_text()
            print(f"   LIVE FEED {feed} 列，這次警報 {pg.inner_text('#sAlerts')}，最上面一筆警報的時間 {first_time}")
            if feed < 30:
                note("demo live", f"LIVE FEED 只有 {feed} 列，應該有 30 列")
            m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", first_time)
            if not m or abs(time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")) - time.time()) > 300:
                note("demo live", f"即時插入的警報時間和現在差太多：{first_time}")
            pg.screenshot(path=str(shots / "demo_live.png"), full_page=True)
            for e in errors:
                note("demo live", e)
            ctx.close()
            call(base, f"/api/runs/{started['run_id']}", "DELETE")
        browser.close()

    print("\n結果：" + ("沒有發現問題" if not problems else f"{len(problems)} 個問題"))
    for pr in problems:
        print("  -", pr)
    print(f"截圖在 {shots.resolve()}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
