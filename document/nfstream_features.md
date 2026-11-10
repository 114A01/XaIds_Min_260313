# nfstream flow 特徵計算方式

> 對應程式：`stream/pcap_feature_extractor.py`（nfstream 6.6.0）
> 內容依 nfstream 文件，並用 CICIoT2023 的 SqlInjection、DictionaryBruteForce pcap 搭配 tshark 逐欄驗證。

## 1. 基本定義

### flow 的切法

| 項目 | 規則 |
|---|---|
| 聚合單位 | 雙向 5-tuple：(src_ip, dst_ip, src_port, dst_port, protocol)，再加上 VLAN ID 與 tunnel ID |
| 方向 | 這條 flow 的**第一個封包的發送端**是 src，另一端是 dst |
| 閒置逾時 `idle_timeout=30` | 超過 30 秒沒有新封包，flow 就結束 |
| 活動逾時 `active_timeout=60` | flow 持續達 60 秒就強制結束，後續封包組成新的 flow，所以 duration 最大是 59,999 ms |
| 只處理 IP 封包 | ARP、STP 等非 IP 封包會被略過 |

注意：長連線被逾時切開後，下一段 flow 的方向由**那一段**的第一個封包決定，可能和前一段相反。

### 符號

- n：flow 內的封包數
- tᵢ：第 i 個封包的時間戳，單位是毫秒，**小數部分會被捨去**
- ℓᵢ：第 i 個封包的大小，`accounting_mode=1` 時取 IP 層長度，包含 IP 標頭，但不含 Ethernet 標頭
  - IPv4：標頭中的 total length
  - IPv6：payload length + 40（IPv6 固定標頭）
- piatᵢ = tᵢ − tᵢ₋₁：相鄰兩個封包的時間間隔，共 n − 1 個

### 三種方向

大部分統計都有三個版本，計算方式相同，只是取用的封包不同：

| 前綴 | 取用的封包 |
|---|---|
| `bidirectional_` | flow 內全部封包 |
| `src2dst_` | 只取 src → dst 的封包 |
| `dst2src_` | 只取 dst → src 的封包 |

方向版的 piat 是**同方向**相鄰封包的間隔，不是和另一方向的封包相比。

### 邊界情況（已實測）

| 情況 | 結果 |
|---|---|
| 只有 1 個封包 | duration、所有 piat、stddev 都是 0 |
| 只有 2 個封包 | `stddev_piat_ms` 是 0（只有 1 個間隔，無法算樣本標準差） |
| 單向 flow（dst 沒有回應） | 所有 `dst2src_*` 欄位都是 0，**包含 `dst2src_first_seen_ms`**，所以 0 不能當成時間戳 |
| UDP、ICMP | 所有 TCP flag 欄位都是 0 |
| ICMP | `src_port`、`dst_port` 都是 0 |

---

## 2. 訓練用的 12 個特徵

輸出的 CSV 共有 13 欄，也就是下面 12 個特徵再加上 `label`。

| # | 特徵 | 公式 | 單位／型別 | 說明 |
|---|---|---|---|---|
| 1 | `protocol` | IP 標頭的 protocol 欄位 | 整數 | 6 = TCP、17 = UDP、1 = ICMP、58 = ICMPv6、2 = IGMP。這是類別值，數字大小沒有意義 |
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


---
