"""
XaIDS FastAPI 服務。

頁面：/（首頁）、/test（測試）、/history（歷史）、/history/{run_id}（單次測試）、
      /demo（展示：警報 + 一致性燈號）、/explain/{id}（單筆解釋）、/packetRecord（流量紀錄）
API 一覽見 README.md。
"""

import asyncio
import csv
import io
import json
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config import (DATA_DIR, PCAP_DIR, CAPTURE_IFACE, CAPTURE_FILTER, class_names, feature_names,
                    CONSISTENCY_KS, CONSISTENCY_K_DEFAULT, CONSISTENCY_PRIMARY, CONSISTENCY_HIGH,
                    CONSISTENCY_LOW, CONFIDENCE_LOW, CONFIDENCE_HIGH, DEFAULT_MAX_ROWS,
                    DEFAULT_LIME_NUM_SAMPLES, DEFAULT_LIME_REPEATS, MODEL_NAME, MAX_ROWS_LIMIT, SHAP_REFERENCE)
from core import pipeline
from core.consistency import consistency_level, LEVEL_HINT, random_baseline
from core.run_stats import compute_stats, chart_data
from db import repository as repo


@asynccontextmanager
async def lifespan(app: FastAPI):
    await repo.init_pool()
    await repo.finish_stale_runs()
    yield
    await repo.close_pool()


app = FastAPI(title="XaIDS", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="api/static"), name="static")
templates = Jinja2Templates(directory="api/templates_reference")


def _static_version(name: str) -> int:
    """靜態檔的 mtime，當 ?v= 用：改了 JS 之後瀏覽器不會再拿快取的舊版。"""
    try:
        return int((Path("api/static") / name).stat().st_mtime)
    except OSError:
        return 0


templates.env.globals["static_v"] = _static_version


def _k(k: Optional[int]) -> int:
    if k is None:
        return CONSISTENCY_K_DEFAULT
    if k not in CONSISTENCY_KS:
        raise HTTPException(status_code=400, detail=f"k 必須是 {list(CONSISTENCY_KS)} 之一")
    return k


# --- 頁面 ---------------------------------------------------------------

@app.get("/")
async def index_page(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/test")
async def test_page(request: Request):
    return templates.TemplateResponse(request, "test.html")


@app.get("/analysis")
async def analysis_redirect():
    return RedirectResponse("/test", status_code=302)


@app.get("/history")
async def history_page(request: Request):
    return templates.TemplateResponse(request, "history.html")


@app.get("/history/{run_id}")
async def run_detail_page(request: Request, run_id: str):
    return templates.TemplateResponse(request, "run_detail.html", {"run_id": run_id})


@app.get("/demo")
async def demo_page(request: Request):
    return templates.TemplateResponse(request, "demo.html")


@app.get("/alertRecord")
async def alert_redirect():
    return RedirectResponse("/demo", status_code=302)


@app.get("/packetRecord")
async def packets_page(request: Request):
    return templates.TemplateResponse(request, "packets.html")


@app.get("/explain/{id}")
async def explain_page(request: Request, id: str):
    return templates.TemplateResponse(request, "explain.html", {"id": id})


# --- 設定與檔案 -----------------------------------------------------------

@app.get("/api/config")
async def api_config():
    return {
        "model_name": MODEL_NAME,
        "class_names": class_names,
        "feature_names": feature_names,
        "ks": list(CONSISTENCY_KS),
        "k_default": CONSISTENCY_K_DEFAULT,
        "primary": CONSISTENCY_PRIMARY,
        "consistency_high": CONSISTENCY_HIGH,
        "consistency_low": CONSISTENCY_LOW,
        "confidence_low": CONFIDENCE_LOW,
        "confidence_high": CONFIDENCE_HIGH,
        "default_max_rows": DEFAULT_MAX_ROWS,
        "max_rows_limit": MAX_ROWS_LIMIT,
        "shap_reference": SHAP_REFERENCE,
        "default_lime_num_samples": DEFAULT_LIME_NUM_SAMPLES,
        "default_lime_repeats": DEFAULT_LIME_REPEATS,
        "baselines": {k: random_baseline(k, len(feature_names)) for k in CONSISTENCY_KS},
        "level_hint": LEVEL_HINT,
    }


@app.get("/api/classes")
async def api_classes():
    return {"classes": class_names}


@app.get("/files")
async def list_files():
    return {
        "csv": sorted(f.name for f in DATA_DIR.glob("*.csv")),
        "pcap": sorted(f.name for f in PCAP_DIR.glob("*.pcap")) if PCAP_DIR.exists() else [],
    }


def _list_interfaces():
    return sorted(name for _, name in socket.if_nameindex())


@app.get("/capture/interfaces")
async def capture_interfaces():
    return {
        "interfaces": _list_interfaces(),
        "default_interface": CAPTURE_IFACE,
        "default_bpf_filter": CAPTURE_FILTER,
    }


# --- 測試（run）---------------------------------------------------------

class RunStartRequest(BaseModel):
    source_type: str                        # csv | pcap | live
    source: Optional[str] = None            # 檔名或網卡；live 不填用 config.CAPTURE_IFACE
    name: Optional[str] = None
    note: Optional[str] = None
    expected_label: Optional[str] = None    # live / pcap 的真實標籤；CSV 沒有 label 欄時也用它
    bpf_filter: Optional[str] = None        # live 用；不填用 config.CAPTURE_FILTER
    max_rows: Optional[int] = None          # csv / pcap：None 表示全部（上限 config.MAX_ROWS_LIMIT）
    lime_num_samples: Optional[int] = None
    lime_repeats: Optional[int] = None


@app.post("/run/start")
async def run_start(body: RunStartRequest):
    if pipeline.run_state["running"]:
        raise HTTPException(status_code=409, detail="已有測試正在執行中，請先停止。")

    if body.source_type == "csv":
        path = DATA_DIR / Path(body.source or "").name
        if not body.source or not path.is_file():
            raise HTTPException(status_code=404, detail="指定的 CSV 不存在")
        with open(path, encoding="utf-8") as fh:
            columns = [c.strip().strip('"') for c in fh.readline().strip().split(",")]
        missing = [c for c in feature_names if c not in columns]
        if missing:
            raise HTTPException(status_code=400, detail=(
                f"CSV 缺少模型需要的 {len(missing)} 個特徵欄位（這個檔案可能是舊的 12 特徵版本，"
                f"請用 stream/pcap_feature_extractor.py export 重新產生）：{missing[:5]}…"))
        source = str(path)
    elif body.source_type == "pcap":
        path = PCAP_DIR / Path(body.source or "").name
        if not body.source or not path.is_file():
            raise HTTPException(status_code=404, detail="指定的 pcap 不存在")
        source = str(path)
    elif body.source_type == "live":
        source = body.source or CAPTURE_IFACE
        if source not in _list_interfaces():
            raise HTTPException(status_code=400, detail=f"網卡不存在：{source}")
    else:
        raise HTTPException(status_code=422, detail="source_type 必須是 csv、pcap 或 live")

    if body.expected_label and body.expected_label not in class_names:
        raise HTTPException(status_code=422, detail=f"expected_label 必須是模型類別之一：{class_names}")
    if body.max_rows is not None and not (1 <= body.max_rows <= MAX_ROWS_LIMIT):
        raise HTTPException(status_code=422, detail=f"max_rows 需在 1 到 {MAX_ROWS_LIMIT} 之間（不填表示全部，上限相同）")
    if body.lime_repeats is not None and not (1 <= body.lime_repeats <= 50):
        raise HTTPException(status_code=422, detail="lime_repeats 需在 1 到 50 之間")
    if body.lime_num_samples is not None and not (100 <= body.lime_num_samples <= 20000):
        raise HTTPException(status_code=422, detail="lime_num_samples 需在 100 到 20000 之間")

    bpf = body.bpf_filter if body.bpf_filter is not None else CAPTURE_FILTER
    ok, msg = await pipeline.start_run(
        body.source_type, source, name=body.name, note=body.note, expected_label=body.expected_label,
        bpf_filter=bpf if body.source_type == "live" else None,
        max_rows=body.max_rows, lime_num_samples=body.lime_num_samples, lime_repeats=body.lime_repeats)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "started", "run_id": msg, **pipeline.get_status()}


@app.post("/run/stop")
async def run_stop():
    stopped = await pipeline.stop_run()
    if not stopped:
        return {"status": "no run running"}
    return {"status": "stopping", **pipeline.get_status()}


@app.get("/run/status")
async def run_status():
    return pipeline.get_status()


@app.get("/run/results")
async def run_results():
    return pipeline.run_state["results"]


@app.get("/stream")
async def stream(request: Request, offset: int = 0):
    async def event_generator():
        yield 'data: {"zone": "CONNECTED"}\n\n'
        current = offset
        while True:
            if await request.is_disconnected():
                break
            results = pipeline.run_state["results"]
            while current < len(results):
                event = results[current]
                yield f"data: {json.dumps(event, default=str)}\n\n"
                current += 1
                if event.get("zone") == "DONE":
                    return
            await asyncio.sleep(0.2)
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# --- 歷史 ---------------------------------------------------------------

@app.get("/api/runs")
async def api_runs(k: Optional[int] = None):
    return await repo.list_runs(_k(k))


@app.get("/api/runs/{run_id}")
async def api_run(run_id: str, k: Optional[int] = None):
    """單次測試的摘要（同 /api/runs 的一列）。圖表資料用 /api/stats/charts?run_ids=…，完整統計用 /api/stats/overall?run_id=…。"""
    summary = await repo.get_run_summary(run_id, _k(k))
    if not summary:
        raise HTTPException(status_code=404, detail="找不到這次測試")
    return summary


class RunMetaRequest(BaseModel):
    name: Optional[str] = None
    note: Optional[str] = None


@app.patch("/api/runs/{run_id}")
async def api_run_update(run_id: str, body: RunMetaRequest):
    if not await repo.get_run(run_id):
        raise HTTPException(status_code=404, detail="找不到這次測試")
    name = body.name.strip() if body.name is not None else None
    if name == "":
        raise HTTPException(status_code=422, detail="名稱不能是空的")
    await repo.update_run_meta(run_id, name, body.note)
    if pipeline.run_state["run_id"] == run_id and name:
        pipeline.run_state["name"] = name
    return await repo.get_run(run_id)


@app.delete("/api/runs/{run_id}")
async def api_run_delete(run_id: str):
    if pipeline.run_state["running"] and pipeline.run_state["run_id"] == run_id:
        raise HTTPException(status_code=409, detail="這次測試正在執行中，請先停止")
    deleted = await repo.delete_run(run_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="找不到這次測試")
    return {"status": "deleted", "run_id": run_id}


@app.get("/api/runs/{run_id}/flows")
async def api_run_flows(run_id: str, zone: Optional[str] = None, correct: Optional[bool] = None,
                        limit: int = 200, offset: int = 0):
    if not await repo.get_run(run_id):
        raise HTTPException(status_code=404, detail="找不到這次測試")
    return await repo.get_run_flows(run_id, zone, correct, min(limit, 2000), max(offset, 0))


@app.get("/api/runs/{run_id}/export.csv")
async def api_run_export(run_id: str):
    run = await repo.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="找不到這次測試")
    rows = (await repo.get_run_flows(run_id, limit=10**9))["items"]
    metrics = ("feature_agreement", "sign_agreement", "rank_agreement",
               "lime_stability", "shap_ablation_drop", "lime_ablation_drop")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["run_id", "seq", "flow_id", "source_ip", "destination_ip", "protocol", "true_label",
                     "predicted_label", "correct", "confidence", "conf_zone"]
                    + [f"k{k}_{m}" for k in CONSISTENCY_KS for m in metrics])
    for f in rows:
        writer.writerow([run_id, f["seq"], f["id"], f["source_ip"], f["destination_ip"], f["protocol"],
                         f["true_label"], f["predicted_label"], f["correct"], f["confidence"], f["conf_zone"]]
                        + [f["consistency"].get(k, {}).get(m) for k in CONSISTENCY_KS for m in metrics])
    # HTTP 標頭只能放 latin-1：測試名稱有中文時，直接放進 filename 會讓回應編碼失敗（500）。
    # filename 給純 ASCII 的後備檔名，filename*（RFC 5987）給完整名稱，瀏覽器會優先用後者。
    filename = "".join(c if c not in '\\/:*?"<>|\r\n\t' else "_" for c in f"run_{run['name']}_{run_id[:8]}.csv").replace(" ", "_")
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename=\"run_{run_id[:8]}.csv\"; filename*=UTF-8''{quote(filename)}"})


@app.get("/api/stats/overall")
async def api_stats_overall(k: Optional[int] = None, threshold: Optional[float] = None, model: str = "current",
                            run_id: Optional[str] = None):
    """完整統計（core/run_stats.compute_stats，給 notebook / 交接文件的分析用）。
    run_id 有值時只算那一次測試；否則 model=current（預設）只統計目前模型、且 SHAP 參考分布
    與目前設定相同的 run，model=all 全部。"""
    if run_id:
        rows = await repo.get_flows_for_stats(run_id)
    elif model == "all":
        rows = await repo.get_flows_for_stats()
    else:
        rows = await repo.get_flows_for_stats(model_name=MODEL_NAME, shap_reference=SHAP_REFERENCE)
    stats = compute_stats(rows, _k(k), threshold)
    stats["model"] = "all" if model == "all" else MODEL_NAME
    stats["run_id"] = run_id
    return stats


@app.get("/api/stats/charts")
async def api_stats_charts(k: Optional[int] = None, run_ids: Optional[str] = None, bins: int = 20,
                           threshold: Optional[float] = None):
    """歷史頁與單次測試頁的圖：run_ids 以逗號分隔，不給表示全部 run；給空字串表示一個都不選。
    bins = 信心值區間數；threshold = 一致組的門檻（預設 CONSISTENCY_HIGH）。"""
    if not (2 <= bins <= 100):
        raise HTTPException(status_code=400, detail="bins 需在 2 到 100 之間")
    ids = None if run_ids is None else [r for r in run_ids.split(",") if r.strip()]
    rows = await repo.get_flows_for_stats(run_ids=ids)
    return chart_data(rows, _k(k), threshold, conf_bins=bins)


# --- 解釋 ---------------------------------------------------------------

async def _resolve_flow_id(id: str) -> str:
    """id 先當 flow_id，查不到再當 alert_id。"""
    if await repo.get_flow(id):
        return id
    flow_id = await repo.get_flow_id_by_alert(id)
    if not flow_id:
        raise HTTPException(status_code=404, detail="找不到這筆 flow 或警報")
    return flow_id


@app.get("/explain/{id}/info")
async def explain_info(id: str):
    flow = await repo.get_flow(await _resolve_flow_id(id))
    flow["correct"] = (flow["true_label"] == flow["predicted_label"]) if flow["true_label"] is not None else None
    return flow


@app.get("/explain/{id}/shap")
async def explain_shap(id: str):
    exp = await repo.get_explanation(await _resolve_flow_id(id))
    if not exp:
        return {"explanations": []}
    return {"flow_id": exp["flow_id"], "shap_value": exp["shap_value"], "base_value": exp["base_value"],
            "scale": exp["scale"]}


@app.get("/explain/{id}/lime")
async def explain_lime(id: str):
    exp = await repo.get_explanation(await _resolve_flow_id(id))
    if not exp:
        return {"explanations": []}
    return {"flow_id": exp["flow_id"], "lime_value": exp["lime_value"], "lime_repeats": exp["lime_repeats"],
            "scale": exp["scale"]}


@app.get("/explain/{id}/consistent")
async def explain_consistent(id: str):
    flow_id = await _resolve_flow_id(id)
    per_k = await repo.get_consistency(flow_id)
    return {
        "flow_id": flow_id,
        "primary": CONSISTENCY_PRIMARY,
        "per_k": {k: {**m, "level": consistency_level(m.get(CONSISTENCY_PRIMARY)),
                      "baseline": random_baseline(k, len(feature_names))}
                  for k, m in per_k.items()},
    }


# --- 紀錄 ---------------------------------------------------------------

@app.get("/api/alertRecord")
async def api_alert_record(k: Optional[int] = None, limit: int = 500):
    alerts = await repo.get_alerts_with_consistency(_k(k), min(limit, 5000))
    for a in alerts:
        score = a.get(CONSISTENCY_PRIMARY)
        a["consistency"] = score
        a["level"] = consistency_level(score)
        a["hint"] = LEVEL_HINT[a["level"]]
    return alerts


@app.get("/api/packetRecord")
async def api_packet_record(limit: int = 500):
    return await repo.get_flows(min(limit, 5000))


@app.get("/flow/number")
async def flow_number():
    return {"flow_count": await repo.get_flow_count()}


@app.get("/alert/number")
async def alert_number():
    return {"alert_count": await repo.get_alert_count()}
