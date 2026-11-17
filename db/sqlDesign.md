# 資料表設計

> 以 `db/xaids_schema.sql` 為準，這份文件只說明各表的用途與關係。
> 早期「封包 + 蜜罐驗證」的設計已經作廢，舊內容可以從 git 歷史查到。

資料以「一次測試（run）」為單位。一次測試是一次 CSV 重播、pcap 重播或一段即時擷取。

```
analysis_run (1) ── (n) flow (1) ── (0..1) alert
                        flow (1) ── (1)    explanation
                        flow (1) ── (n)    consistency      k = 3、5、7 各一列
```

刪除一次測試時，底下的 flow、alert、explanation、consistency 會一併刪除（外鍵 `ON DELETE CASCADE`）。

| 表 | 一列代表 | 主要欄位 |
|---|---|---|
| `analysis_run` | 一次測試 | 名稱、備註、來源類型與來源、BPF、預期標籤、模型檔名、`params`（JSON）、狀態、起訖時間、進度 |
| `flow` | 一條 flow | 所屬測試與序號、位址與埠（CSV 重播沒有）、真實標籤、預測類別、信心值、ZONE、`computed_features`（22 個特徵值的 JSON） |
| `alert` | 一筆警報 | 對應的 flow、攻擊類型、信心值、ZONE。只有判為攻擊且信心值 ≥ `CONFIDENCE_LOW` 的 flow 才有 |
| `explanation` | 一條 flow 的解釋 | SHAP 與 LIME 對全部特徵的權重（JSON，依絕對值排序）、SHAP 的 base value、LIME 重複次數、尺度（`log_odds`） |
| `consistency` | 一條 flow 在某個 k 的指標 | `feature_agreement`、`sign_agreement`（主指標）、`rank_agreement`、`lime_stability`、`shap_ablation_drop`、`lime_ablation_drop` |

## 設計上的幾個決定

- **每條 flow 都存解釋，不只警報。** 研究需要判對與判錯的樣本都有一致性分數，所以解釋掛在 flow 上，不掛在 alert 上。
- **存原始分數，不存燈號。** 燈號由 `config.py` 的門檻即時算出，改門檻不必重跑測試。
- **存全部特徵的權重。** 任何 k 的指標都可以事後重算。
- **`analysis_run.params` 記錄會影響結果的設定**：`max_rows`、`lime_num_samples`、`lime_repeats`、`ks`、`shap_reference`。`shap_reference` 是 SHAP 的參考分布（`background` 或 `tree_path`），2026-11-17 以前的測試沒有這個欄位，當時是 `tree_path`。設定不同的測試不應該合併分析。
- **`flow.protocol`**：pcap 與即時擷取存協定名稱（`TCP`），CSV 重播沒有名稱，存的是協定號碼（`6`）。
- **`flow.start_time`**：pcap 重播時是封包錄製當時的時間，CSV 重播時是分析的時間。

`core/run_stats.py` 與匯出 CSV 都依賴 `consistency` 表的欄位名稱，改欄位時要一起改。
