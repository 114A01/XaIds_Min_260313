from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from db.repository import init_pool, close_pool, get_packets, get_explanation_lime, get_explanation_shap, get_flows, get_alerts
from contextlib import asynccontextmanager

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

@app.get("/alertRecord")                                    # 警報紀錄頁面，展示觸發警報的封包以及相關資訊
async def alert(request: Request):
    # print("Hello World")
    alerts = await get_alerts()
    return templates.TemplateResponse(request, "alerts.html", {
        "alerts": alerts,
    })

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
    return {"message" : "This is a consistent explanation message"}
