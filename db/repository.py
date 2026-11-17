"""
資料庫存取（aiomysql）。所有函數都是 async，回傳的 Decimal 已轉成 float、datetime 保持原樣。

表格關係：analysis_run (1) ── (n) flow (1) ── (0..1) alert
                                   flow (1) ── (1) explanation
                                   flow (1) ── (n) consistency（k = 3, 5, 7）
"""

import aiomysql
import datetime
import decimal
import json
import uuid

from config import CONSISTENCY_KS

pool = None


async def init_pool():
    global pool
    pool = await aiomysql.create_pool(
        host="localhost",
        user="allen",
        password="allen",
        db="xaids",
        cursorclass=aiomysql.DictCursor,
        autocommit=True,
    )


async def close_pool():
    global pool
    pool.close()
    await pool.wait_closed()


def _clean(row):
    """Decimal → float，讓結果可以直接 JSON 化與進 numpy。"""
    if row is None:
        return None
    return {k: (float(v) if isinstance(v, decimal.Decimal) else v) for k, v in row.items()}


async def _fetchall(sql, args=()):
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            return [_clean(r) for r in await cur.fetchall()]


async def _fetchone(sql, args=()):
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            return _clean(await cur.fetchone())


async def _execute(sql, args=()):
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            return cur.rowcount


# --- analysis_run ------------------------------------------------------

async def create_run(name, note, source_type, source, bpf_filter, expected_label, model_name, params):
    run_id = str(uuid.uuid4())
    await _execute(
        "INSERT INTO analysis_run (run_id, name, note, source_type, source, bpf_filter, expected_label, "
        "model_name, params, status, started_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'running',%s)",
        (run_id, name, note, source_type, source, bpf_filter, expected_label, model_name,
         json.dumps(params), datetime.datetime.now()))
    return run_id


async def update_run_progress(run_id, processed, total):
    await _execute("UPDATE analysis_run SET processed=%s, total=%s WHERE run_id=%s", (processed, total, run_id))


async def finish_run(run_id, status, processed, total, error=None):
    await _execute(
        "UPDATE analysis_run SET status=%s, processed=%s, total=%s, error=%s, finished_at=%s WHERE run_id=%s",
        (status, processed, total, error, datetime.datetime.now(), run_id))


async def finish_stale_runs():
    """伺服器啟動時呼叫：上次行程結束時還在 running 的 run 永遠不會收尾，標成 stopped。"""
    return await _execute(
        "UPDATE analysis_run SET status='stopped', error=COALESCE(error, '伺服器重啟時中斷'), "
        "finished_at=COALESCE(finished_at, %s) WHERE status='running'", (datetime.datetime.now(),))


async def update_run_meta(run_id, name=None, note=None):
    sets, args = [], []
    if name is not None:
        sets.append("name=%s"); args.append(name)
    if note is not None:
        sets.append("note=%s"); args.append(note)
    if not sets:
        return 0
    args.append(run_id)
    return await _execute(f"UPDATE analysis_run SET {', '.join(sets)} WHERE run_id=%s", tuple(args))


async def get_run(run_id):
    row = await _fetchone("SELECT * FROM analysis_run WHERE run_id=%s", (run_id,))
    if row and row.get("params"):
        row["params"] = json.loads(row["params"])
    return row


async def delete_run(run_id):
    return await _execute("DELETE FROM analysis_run WHERE run_id=%s", (run_id,))


_RUN_SUMMARY_SQL = """
SELECT r.*,
       COUNT(f.id)                                   AS flow_count,
       SUM(f.conf_zone='BENIGN')                     AS n_benign,
       SUM(f.conf_zone='UNCERTAIN')                  AS n_uncertain,
       SUM(f.conf_zone='SUSPICIOUS')                 AS n_suspicious,
       SUM(f.conf_zone='HIGH_CONF')                  AS n_high_conf,
       SUM(f.true_label IS NOT NULL)                 AS n_labeled,
       SUM(f.true_label IS NOT NULL AND f.true_label = f.predicted_label) AS n_correct,
       AVG(c.feature_agreement)                      AS mean_feature_agreement,
       AVG(c.sign_agreement)                         AS mean_sign_agreement,
       AVG(c.rank_agreement)                         AS mean_rank_agreement,
       AVG(c.lime_stability)                         AS mean_lime_stability
FROM analysis_run r
LEFT JOIN flow f        ON f.run_id = r.run_id
LEFT JOIN consistency c ON c.flow_id = f.id AND c.k = %s
{where}
GROUP BY r.run_id
ORDER BY r.started_at DESC
"""


def _finish_summary(row):
    row["params"] = json.loads(row["params"]) if row.get("params") else {}
    for key in ("flow_count", "n_benign", "n_uncertain", "n_suspicious", "n_high_conf", "n_labeled", "n_correct"):
        row[key] = int(row[key] or 0)
    row["accuracy"] = (row["n_correct"] / row["n_labeled"]) if row["n_labeled"] else None
    return row


async def list_runs(k):
    rows = await _fetchall(_RUN_SUMMARY_SQL.format(where=""), (k,))
    return [_finish_summary(r) for r in rows]


async def get_run_summary(run_id, k):
    rows = await _fetchall(_RUN_SUMMARY_SQL.format(where="WHERE r.run_id = %s"), (k, run_id))
    return _finish_summary(rows[0]) if rows else None


# --- flow --------------------------------------------------------------

async def insert_flow(record, feature, run_id, seq, true_label, predicted_label, confidence, conf_zone):
    flow_id = str(uuid.uuid4())
    if hasattr(feature, "to_dict"):
        computed_features = feature.iloc[0].to_dict()
    else:
        computed_features = {str(i): v for i, v in enumerate(feature)}
    computed_features = {k: (float(v) if v is not None else None) for k, v in computed_features.items()}

    start_time = record.get("start_time") or datetime.datetime.now()
    # 即時擷取的 record 中，protocol 是特徵（協定號碼），協定名稱在 protocol_name
    protocol = record.get("protocol_name", record.get("protocol"))
    protocol = str(protocol) if protocol is not None else None

    await _execute(
        "INSERT INTO flow (id, run_id, seq, source_ip, destination_ip, source_port, destination_port, protocol, "
        "start_time, end_time, duration_ms, packet_count, byte_count, true_label, predicted_label, confidence, "
        "conf_zone, computed_features) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (flow_id, run_id, seq, record.get("source_ip"), record.get("destination_ip"),
         record.get("source_port"), record.get("destination_port"), protocol,
         start_time, record.get("end_time"), record.get("duration_ms"), record.get("packet_count"),
         record.get("byte_count"), true_label, predicted_label, confidence, conf_zone,
         json.dumps(computed_features)))
    return flow_id


async def get_flows(limit=500):
    return await _fetchall(
        # 依「分析的先後」排序。start_time 是 flow 本身的開始時間，pcap 重播時是錄製當時的時間，
        # 用它排序會讓剛重播的 pcap 沉到後面。
        "SELECT f.*, r.name AS run_name FROM flow f JOIN analysis_run r ON r.run_id = f.run_id "
        "ORDER BY r.started_at DESC, f.seq DESC LIMIT %s", (limit,))


async def get_flow(flow_id):
    return await _fetchone(
        "SELECT f.*, r.name AS run_name FROM flow f JOIN analysis_run r ON r.run_id = f.run_id WHERE f.id=%s",
        (flow_id,))


async def get_flow_count():
    row = await _fetchone("SELECT COUNT(*) AS total FROM flow")
    return row["total"]


def _nest_consistency(flows, crows):
    by_flow = {}
    for c in crows:
        entry = by_flow.setdefault(c["flow_id"], {})
        entry[int(c["k"])] = {key: c[key] for key in
                              ("feature_agreement", "sign_agreement", "rank_agreement",
                               "lime_stability", "shap_ablation_drop", "lime_ablation_drop")}
    for f in flows:
        f["consistency"] = by_flow.get(f["id"], {})
        f["correct"] = (f["true_label"] == f["predicted_label"]) if f.get("true_label") is not None else None
    return flows


async def _attach_consistency(flows):
    if not flows:
        return flows
    ids = [f["id"] for f in flows]
    crows = []
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        placeholders = ",".join(["%s"] * len(chunk))
        crows += await _fetchall(f"SELECT * FROM consistency WHERE flow_id IN ({placeholders})", tuple(chunk))
    return _nest_consistency(flows, crows)


def _flow_filters(run_id=None, zone=None, correct=None, model_name=None, run_ids=None, shap_reference=None):
    where, args = [], []
    if run_id:
        where.append("f.run_id = %s"); args.append(run_id)
    if run_ids is not None:
        if not run_ids:
            where.append("1 = 0")
        else:
            where.append(f"f.run_id IN ({','.join(['%s'] * len(run_ids))})"); args += list(run_ids)
    if model_name:
        where.append("f.run_id IN (SELECT run_id FROM analysis_run WHERE model_name = %s)"); args.append(model_name)
    if shap_reference:
        # 2026-11-17 以前的 run 沒有記錄 shap_reference，當時是 tree_path
        where.append("f.run_id IN (SELECT run_id FROM analysis_run WHERE "
                     "COALESCE(JSON_VALUE(params, '$.shap_reference'), 'tree_path') = %s)")
        args.append(shap_reference)
    if zone:
        where.append("f.conf_zone = %s"); args.append(zone)
    if correct is True:
        where.append("f.true_label IS NOT NULL AND f.true_label = f.predicted_label")
    elif correct is False:
        where.append("f.true_label IS NOT NULL AND f.true_label <> f.predicted_label")
    return ("WHERE " + " AND ".join(where)) if where else "", args


async def get_run_flows(run_id, zone=None, correct=None, limit=200, offset=0):
    where, args = _flow_filters(run_id, zone, correct)
    total = (await _fetchone(f"SELECT COUNT(*) AS n FROM flow f {where}", tuple(args)))["n"]
    flows = await _fetchall(
        f"SELECT f.id, f.run_id, f.seq, f.source_ip, f.destination_ip, f.source_port, f.destination_port, "
        f"f.protocol, f.start_time, f.true_label, f.predicted_label, f.confidence, f.conf_zone "
        f"FROM flow f {where} ORDER BY f.seq LIMIT %s OFFSET %s", tuple(args + [limit, offset]))
    return {"total": total, "items": await _attach_consistency(flows)}


async def get_flows_for_stats(run_id=None, model_name=None, run_ids=None, shap_reference=None):
    """給 core/run_stats.py 用：不分頁，只取統計需要的欄位。
    model_name / shap_reference 有值時只取該模型、該 SHAP 參考分布的 run；
    run_ids 有值（含空列表）時只取這些 run。"""
    where, args = _flow_filters(run_id, model_name=model_name, run_ids=run_ids, shap_reference=shap_reference)
    flows = await _fetchall(
        f"SELECT f.id, f.run_id, f.seq, f.true_label, f.predicted_label, f.confidence, f.conf_zone "
        f"FROM flow f {where} ORDER BY f.seq", tuple(args))
    return await _attach_consistency(flows)


# --- alert -------------------------------------------------------------

async def insert_alert(flow_id, attack_type, confidence, conf_zone):
    alert_id = str(uuid.uuid4())
    await _execute(
        "INSERT INTO alert (alert_id, flow_id, attack_type, confidence, conf_zone, status, alert_time) "
        "VALUES (%s,%s,%s,%s,%s,'unhandled',%s)",
        (alert_id, flow_id, attack_type, confidence, conf_zone, datetime.datetime.now()))
    return alert_id


async def get_alerts_with_consistency(k, limit=500):
    return await _fetchall(
        "SELECT a.*, f.run_id, f.true_label, f.source_ip, f.destination_ip, r.name AS run_name, "
        "c.feature_agreement, c.sign_agreement, c.rank_agreement, c.lime_stability "
        "FROM alert a JOIN flow f ON f.id = a.flow_id JOIN analysis_run r ON r.run_id = f.run_id "
        "LEFT JOIN consistency c ON c.flow_id = f.id AND c.k = %s "
        "ORDER BY a.alert_time DESC LIMIT %s", (k, limit))


async def get_alert_count():
    row = await _fetchone("SELECT COUNT(*) AS total FROM alert")
    return row["total"]


async def get_flow_id_by_alert(alert_id):
    row = await _fetchone("SELECT flow_id FROM alert WHERE alert_id=%s", (alert_id,))
    return row["flow_id"] if row else None


# --- explanation / consistency -------------------------------------------

def _pairs_to_json(pairs):
    return json.dumps([{"feature": name, "weight": round(float(w), 6)} for name, w in pairs])


async def insert_explanation(flow_id, shap_pairs, base_value, lime_pairs, lime_repeats, scale="log_odds"):
    await _execute(
        "INSERT INTO explanation (flow_id, shap_value, base_value, lime_value, lime_repeats, scale) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (flow_id, _pairs_to_json(shap_pairs), f"{base_value:.6f}", _pairs_to_json(lime_pairs), lime_repeats, scale))


async def insert_consistency_rows(flow_id, per_k):
    """per_k: {k: {feature_agreement, sign_agreement, rank_agreement, lime_stability, shap_ablation_drop, lime_ablation_drop}}"""
    rows = [(flow_id, k, m["feature_agreement"], m["sign_agreement"], m["rank_agreement"],
             m.get("lime_stability"), m.get("shap_ablation_drop"), m.get("lime_ablation_drop"))
            for k, m in per_k.items()]
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.executemany(
                "INSERT INTO consistency (flow_id, k, feature_agreement, sign_agreement, rank_agreement, "
                "lime_stability, shap_ablation_drop, lime_ablation_drop) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", rows)


async def get_explanation(flow_id):
    row = await _fetchone("SELECT * FROM explanation WHERE flow_id=%s", (flow_id,))
    if row:
        row["shap_value"] = json.loads(row["shap_value"])
        row["lime_value"] = json.loads(row["lime_value"])
    return row


async def get_consistency(flow_id):
    rows = await _fetchall("SELECT * FROM consistency WHERE flow_id=%s ORDER BY k", (flow_id,))
    return {int(r["k"]): r for r in rows}
