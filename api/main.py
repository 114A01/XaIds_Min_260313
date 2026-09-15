from pathlib import Path
from typing import Optional
import asyncio
import json
import socket

from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from db.repository import init_pool, close_pool, get_packets, get_explanation_lime, get_explanation_shap, get_flows, get_alerts, get_flow_count, get_alert_count, get_comparison_result
from contextlib import asynccontextmanager
from core import pipeline
from config import DATA_DIR, CAPTURE_IFACE, CAPTURE_FILTER
from stream.catcher import DEFAULT_IDLE_TIMEOUT, DEFAULT_ACTIVE_TIMEOUT

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_pool()  # 啟動事件，初始化資料庫連接池
    yield
    await close_pool()  # 關閉事件，關閉資料庫連接池


app = FastAPI(title="XaIDS", lifespan=lifespan)  # 使用 lifespan 管理資料庫連接池的啟動和關閉
app.mount("/static", StaticFiles(directory="api/static"), name="static")
templates = Jinja2Templates(directory="api/templates_reference")





# --- routes -------------------------------------------------

@app.get("/")
async def root(request: Request):                                           # 首頁，展示系統運作資訊
    # print("Hello World")
    return templates.TemplateResponse(request, "index.html")

@app.get("/packetRecord")                                   # IDS紀錄頁面，展示紀錄到的封包以及相關資訊
async def warning(request: Request):
    # print("Hello World")
    packets = await get_flows()
    return templates.TemplateResponse(request, "packets.html", {
        "packets": packets,
    })

@app.get("/api/packetRecord")
async def api_packet_record():
    return await get_flows()

@app.get("/alertRecord")                                    # 警報紀錄頁面，展示觸發警報的封包以及相關資訊
async def alert(request: Request):
    # print("Hello World")
    alerts = await get_alerts()
    return templates.TemplateResponse(request, "alerts.html", {
        "alerts": alerts,
    })

@app.get("/api/alertRecord")
async def api_alert_record():
    return await get_alerts()

# @app.get("/packetRecord/packetList")                        # 回傳擷取到的封包列表，供IDS紀錄頁面顯示
# async def packetList():
#     return {"message" : "This is a packet list message"}

@app.post("/packetRecord/{id}/statusNote")                   # 接收IDS紀錄頁面對指定封包的狀態更新和備註，更新資料庫中該封包的相關資訊
async def statusNote(id: str):
    return {"message" : "This is a status note message"}

@app.get("/explain/{id}")                                   # 解釋頁面，經過IDS頁面選擇指定封包，展示xai 對該封包的解釋結果
async def explain(request:Request, id: str):
    return templates.TemplateResponse(request, "explain.html", {
        "id": id
    })

@app.get("/explain/{id}/lime")                              # 回傳指定封包的lime解釋，供解釋頁面顯示
async def explain_lime(id: str):
    return await get_explanation_lime(id)

@app.get("/explain/{id}/shap")                              # 回傳指定封包的shap解釋，供解釋頁面顯示
async def explain_shap(id: str):
    return await get_explanation_shap(id)

@app.get("/explain/{id}/consistent")                        # 回傳指定封包的一致性解釋，供解釋頁面顯示
async def explain_consistent(id: str):
    return await get_comparison_result(id)

@app.get("/analysis")
async def analysis_page(request: Request):                                   # 分析頁面，展示可供分析的檔案列表，並提供選擇後開始分析的功能
    return templates.TemplateResponse(request, "analysis.html")

@app.get("/files")
async def list_files():
    files = [f.name for f in DATA_DIR.glob("*.csv")]

    return {"files": files}

class StartRequest(BaseModel):
    filename: str

@app.post("/analysis/start") # 選定檔案，並開始分析
async def start_analysis(body: StartRequest):
    state = pipeline.analysis_state

    if state["running"]:
        raise HTTPException(status_code=409, detail="分析任務已在執行中，請先呼叫 /analysis/stop")
    
    filepath = DATA_DIR / body.filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="指定的檔案不存在")
    
    stop_event = asyncio.Event()
    state["running"] = True
    state["filename"] = body.filename
    state["stop_event"] = stop_event
    state["processed"] = 0
    state["total"] = 0

    asyncio.create_task(pipeline.run_csv_analysis(filepath, stop_event))

    return {"status": "started", "filename": body.filename}

@app.post("/analysis/stop") # 停止分析
async def analysis_stop():
    state = pipeline.analysis_state

    if not state["running"]:
        return {"status": "no task running"}
    if state["stop_event"]:
        state["stop_event"].set()
    return {"status": "stopping"}

@app.get("/analysis/status")
async def analysis_status():
    state = pipeline.analysis_state
    return {
        "running":  state["running"],
        "filename": state["filename"],
        "total":    state["total"],
        "processed":state["processed"]
    }

class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None                                      # 不填使用 config.CAPTURE_IFACE
    bpf_filter: Optional[str] = None                                     # 不填使用 config.CAPTURE_FILTER，空字串表示不過濾
    idle_timeout: int = Field(DEFAULT_IDLE_TIMEOUT, ge=1, le=3600)       # 秒，flow 閒置多久視為結束
    active_timeout: int = Field(DEFAULT_ACTIVE_TIMEOUT, ge=1, le=86400)  # 秒，長連線每隔多久切出一條 flow

def _list_interfaces():
    return sorted(name for _, name in socket.if_nameindex())

@app.get("/capture/interfaces")                             # 列出可擷取的網卡，以及 config 的預設網卡與 BPF
async def capture_interfaces():
    return {
        "interfaces": _list_interfaces(),
        "default_interface": CAPTURE_IFACE,
        "default_bpf_filter": CAPTURE_FILTER,
    }

@app.post("/capture/start")                                 # 開始即時擷取，不帶 body 時使用 config 的預設值
async def capture_start(body: Optional[CaptureStartRequest] = None):
    body = body or CaptureStartRequest()
    if pipeline.analysis_state["running"]:
        raise HTTPException(status_code=409, detail="檔案分析正在進行中，請先停止。")
    if pipeline.live_capture_state["running"]:
        raise HTTPException(status_code=409, detail="即時流量分析已在執行中。")

    interface = body.interface or CAPTURE_IFACE
    if interface not in _list_interfaces():
        raise HTTPException(status_code=400, detail=f"網卡不存在：{interface}")

    ok, msg = await pipeline.start_live_capture(interface, body.bpf_filter, body.idle_timeout, body.active_timeout)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)    # 例如 BPF 語法錯誤、沒有擷取權限
    return {"status": "started", **pipeline.get_live_capture_status()}

@app.post("/capture/stop")
async def capture_stop():
    stopped = await pipeline.stop_live_capture()
    if not stopped:
        return {"status": "no capture running"}
    return {"status": "stopped", **pipeline.get_live_capture_status()}

@app.get("/capture/status")
async def capture_status():
    return pipeline.get_live_capture_status()

@app.get("/analysis/results")
async def get_analysis_results():
    return pipeline.analysis_state["results"]

@app.get("/stream")
async def stream(request: Request, offset: int = 0):
    async def event_generator():
        yield 'data: {"zone" : "CONNECTED"}\n\n' 
        current_offset = offset
        while True:
            if await request.is_disconnected():
                break
            results = pipeline.analysis_state["results"]
            while current_offset < len(results):
                event = results[current_offset]
                yield f'data: {json.dumps(event)}\n\n'
                current_offset += 1
                if event.get("zone") == "DONE":
                    return
            await asyncio.sleep(0.2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/flow/number")
async def get_flow_number():
    count = await get_flow_count()
    return {"flow_count": count}

@app.get("/alert/number")
async def get_alert_number():
    count = await get_alert_count()
    return {"alert_count": count}