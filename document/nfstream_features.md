# nfstream flow 特徵計算方式

## 1. 基本定義

### flow 的切法

| 項目 | 規則 |
|---|---|
| 聚合單位 | 雙向 5-tuple：(src_ip, dst_ip, src_port, dst_port, protocol)，再加上 VLAN ID 與 tunnel ID |
| 方向 | 這條 flow 的**第一個封包的發送端**是 src，另一端是 dst |
| 閒置逾時 `idle_timeout=30` | 超過 30 秒沒有新封包，flow 就結束 |
| 活動逾時 `active_timeout=60` | flow 持續達 60 秒就強制結束，後續封包組成新的 flow，所以 duration 最大是 59,999 ms |
| 只處理 IP 封包 | ARP、STP 等非 IP 封包會被略過 |

長連線被逾時切開後，下一段 flow 的方向由**那一段**的第一個封包決定，可能和前一段相反。

### 符號

- n：flow 內的封包數
- tᵢ：第 i 個封包的時間戳，單位是毫秒，**小數部分會被捨去**
- ℓᵢ：第 i 個封包的大小
- piatᵢ = tᵢ − tᵢ₋₁：相鄰兩個封包的時間間隔，共 n − 1 個

### 封包方向


| 前綴 | 取用的封包 |
|---|---|
| `bidirectional_` | flow 內全部封包 |
| `src2dst_` | 只取 src → dst 的封包 |
| `dst2src_` | 只取 dst → src 的封包 |





---

## 2. 特徵算法




| # | 特徵 | 公式 | 單位／型別 | 說明 |
|---|---|---|---|---|
| 1 | `protocol` | IP 標頭的 protocol 欄位 | 整數 | 6 = TCP、17 = UDP、1 = ICMP、58 = ICMPv6、2 = IGMP。|
| 2 | `bidirectional_duration_ms` | tₙ − t₁ | ms，整數 | 最大 59,999（受 `active_timeout` 限制） |
| 3 | `bidirectional_mean_piat_ms` | Σ piatᵢ ÷ (n − 1) = duration ÷ (n − 1) | ms，小數 | 用捨去後的毫秒時間戳計算，高速流量很容易得到 0 |
| 4 | `bidirectional_packets` | n | 個，整數 | 等於 #6 + #7 |
| 5 | `bidirectional_bytes` | Σ ℓᵢ | bytes，整數 | 等於 src2dst_bytes + dst2src_bytes |
| 6 | `src2dst_packets` | src → dst 的封包數 | 個，整數 | 至少是 1（第一個封包一定是 src 發出的） |
| 7 | `dst2src_packets` | dst → src 的封包數 | 個，整數 | 0 表示對方沒有回應 |
| 8 | `bidirectional_mean_ps` | Σ ℓᵢ ÷ n = bytes ÷ packets | bytes，小數 | |
| 9 | `bidirectional_stddev_ps` | √( Σ (ℓᵢ − mean)² ÷ (n − 1) ) | bytes，小數 | **樣本**標準差（除以 n − 1）；n = 1 時為 0 |
| 10 | `bidirectional_syn_packets` | SYN 位元為 1 的封包數 | 個，整數 | 只有 TCP 會大於 0 |
| 11 | `bidirectional_ack_packets` | ACK 位元為 1 的封包數 | 個，整數 | 同上 |
| 12 | `bidirectional_rst_packets` | RST 位元為 1 的封包數 | 個，整數 | 同上 |
| 13 | `src2dst_stddev_ps` | src → dst 封包大小的樣本標準差 | bytes，小數 | 算法同 #9，只取 src → dst 的封包；該方向只有 1 個封包時為 0 |
| 14 | `bidirectional_min_ps` | min ℓᵢ | bytes，整數 | 等於兩個方向各自最小值中較小的那個 |
| 15 | `dst2src_stddev_ps` | dst → src 封包大小的樣本標準差 | bytes，小數 | 對方沒有回應或只回 1 個封包時為 0 |
| 16 | `src2dst_min_ps` | src → dst 封包大小的最小值 | bytes，整數 | |
| 17 | `bidirectional_min_piat_ms` | min piatᵢ | ms，整數 | 用捨去後的毫秒時間戳計算；n = 1 時為 0。一定不大於 #3 |
| 18 | `src2dst_ack_packets` | src → dst 且 ACK 位元為 1 的封包數 | 個，整數 | 只有 TCP 會大於 0；不大於 #11 |
| 19 | `src2dst_psh_packets` | src → dst 且 PSH 位元為 1 的封包數 | 個，整數 | 只有 TCP 會大於 0 |
| 20 | `bidirectional_max_ps` | max ℓᵢ | bytes，整數 | 等於兩個方向各自最大值中較大的那個 |
| 21 | `src2dst_max_ps` | src → dst 封包大小的最大值 | bytes，整數 | |
| 22 | `src2dst_mean_ps` | src2dst_bytes ÷ src2dst_packets | bytes，小數 | |

#1 到 #12 是原本的 12 個特徵，#13 到 #22 是 7 類模型新增的 10 個。順序與 `stream/flow_features.py` 的 `FEATURES`、模型的 `feature_names` 相同。

封包大小 ℓᵢ 是 **IP 層**的長度（`accounting_mode=1`），不含乙太網路標頭，所以不受鏈路層差異影響。

上表的關係式（#8、#14、#17、#20、#22 的等式，以及只有 1 個封包時標準差與最小間隔為 0）已用 `output/flows/SqlInjection.parquet` 的 6,995 條 flow 逐條核對。


---
