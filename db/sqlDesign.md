
form 1 
packet ------------ 儲存接收到的封包
    id              主鍵
    time            時間
    source IP       來源 IP
    destination IP   目的地 IP
    protocol        協定
    size            封包大小

form 2
alert ------------- 高於閥值的封包
    packet_id       外來鍵（連結到packet
    alert_id        主鍵
    attack_type     攻擊類型
    confidence      信心值
    conf_zone       信心值對應的區間
    status          該筆風包的狀態（未處理/處理中/已處理/誤報
    alert_time      發出警告的時間

form 3
explanationForShap - 紀錄shap的解釋
    alert_id        外來鍵（連結到alert
    shap_value      shap計算的特徵重要性
    top-n feature
    feature_name
    重要性排序

form 4
explanationForLime - 紀錄Lime的解釋
    alert_id        外來鍵（連結到alert
    Lime            Lime計算的特徵重要性
    top-n feature
    feature_name

form 5
honeypotRecord ---- 蜜罐紀錄
    alert_id        外來鍵（連結到alert
    ...             蜜罐紀錄的風包細節，確認後補上

form 6
Validation -------- 比對xai解釋以及蜜罐紀錄的一致性
    alert_id        外來鍵（連結到alert
    shap_vs_lime_correlation                xai關聯性
    shap_vs_honeypot_match                  對蜜罐的關聯性
    lime_vs_honeypot_match
    trust_score
    status                                  驗證狀態
 
    ...             如何比對差異的細節，後續補上

packet(1) ────────── (0..1) alert               紀錄的封包不一定發出警告
alert (1) ────────── (1) explanationForShap     發出警報一定要解釋
alert (1) ────────── (1) explanationForLime     發出警報一定要解釋
alert (1) ────────── (0..1) honeypot_record     高信心值得警報才送蜜罐觀察
alert (1) ────────── (1) validation          對每筆警報驗證解釋的一致性

packet 與 alert 間透過id連結
其餘的表皆夠過alert_id 與 alert之間連結

---
form 7
user    使用者
    user_name       名稱
    user_password   密碼
    permissions     權限
