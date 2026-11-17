-- XaIDS 資料庫 schema（MariaDB）
-- 以「一次測試（analysis_run）」為單位分組，每筆 flow 都有預測、解釋與一致性。
-- 重建方式：mariadb -u allen -pallen xaids < db/xaids_schema.sql
-- 注意：會清空所有資料。

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `consistency`;
DROP TABLE IF EXISTS `explanation`;
DROP TABLE IF EXISTS `explanationForLime`;
DROP TABLE IF EXISTS `explanationForShap`;
DROP TABLE IF EXISTS `validation`;
DROP TABLE IF EXISTS `honeypotRecord`;
DROP TABLE IF EXISTS `packet`;
DROP TABLE IF EXISTS `alert`;
DROP TABLE IF EXISTS `flow`;
DROP TABLE IF EXISTS `analysis_run`;
SET FOREIGN_KEY_CHECKS = 1;

-- 一次測試：CSV 重播、pcap 重播或即時擷取
CREATE TABLE `analysis_run` (
  `run_id`         char(36)     NOT NULL,
  `name`           varchar(100) NOT NULL,
  `note`           text         DEFAULT NULL,
  `source_type`    enum('csv','pcap','live') NOT NULL,
  `source`         varchar(255) NOT NULL,                 -- 檔名或網卡名稱
  `bpf_filter`     varchar(255) DEFAULT NULL,
  `expected_label` varchar(50)  DEFAULT NULL,             -- live / pcap 的真實標籤；CSV 有 label 欄時以該欄為準
  `model_name`     varchar(100) NOT NULL,                 -- config.MODEL_PATH 的檔名
  `params`         longtext     DEFAULT NULL CHECK (json_valid(`params`)),  -- max_rows、lime_num_samples、lime_repeats、ks、shap_reference
  `status`         enum('running','stopped','done','error') NOT NULL DEFAULT 'running',
  `started_at`     datetime     NOT NULL,
  `finished_at`    datetime     DEFAULT NULL,
  `total`          int unsigned NOT NULL DEFAULT 0,
  `processed`      int unsigned NOT NULL DEFAULT 0,
  `error`          text         DEFAULT NULL,
  PRIMARY KEY (`run_id`),
  KEY `idx_run_started` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 每一條 flow 都記錄預測結果，不論是否發出警報
CREATE TABLE `flow` (
  `id`                char(36)     NOT NULL,
  `run_id`            char(36)     NOT NULL,
  `seq`               int unsigned NOT NULL,              -- run 內的序號
  `source_ip`         varchar(45)  DEFAULT NULL,
  `destination_ip`    varchar(45)  DEFAULT NULL,
  `source_port`       smallint unsigned DEFAULT NULL,
  `destination_port`  smallint unsigned DEFAULT NULL,
  `protocol`          varchar(10)  DEFAULT NULL,
  `start_time`        datetime(3)  DEFAULT NULL,
  `end_time`          datetime     DEFAULT NULL,
  `duration_ms`       int unsigned DEFAULT NULL,
  `packet_count`      int unsigned DEFAULT NULL,
  `byte_count`        int unsigned DEFAULT NULL,
  `true_label`        varchar(50)  DEFAULT NULL,
  `predicted_label`   varchar(50)  NOT NULL,
  `confidence`        decimal(5,4) NOT NULL,
  `conf_zone`         enum('BENIGN','UNCERTAIN','SUSPICIOUS','HIGH_CONF') NOT NULL,
  `computed_features` longtext     DEFAULT NULL CHECK (json_valid(`computed_features`)),
  PRIMARY KEY (`id`),
  KEY `idx_flow_run_seq` (`run_id`, `seq`),
  CONSTRAINT `fk_flow_run` FOREIGN KEY (`run_id`) REFERENCES `analysis_run` (`run_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 警報：非 Benign 且 confidence >= CONFIDENCE_LOW 的 flow
CREATE TABLE `alert` (
  `alert_id`    char(36)     NOT NULL,
  `flow_id`     char(36)     NOT NULL,
  `attack_type` varchar(50)  NOT NULL,
  `confidence`  decimal(5,4) NOT NULL,
  `conf_zone`   enum('SUSPICIOUS','HIGH_CONF') NOT NULL,
  `status`      enum('unhandled','processing','resolved','false_positive') NOT NULL DEFAULT 'unhandled',
  `alert_time`  datetime     NOT NULL,
  PRIMARY KEY (`alert_id`),
  KEY `idx_alert_flow` (`flow_id`),
  CONSTRAINT `fk_alert_flow` FOREIGN KEY (`flow_id`) REFERENCES `flow` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- SHAP 與 LIME 解釋，兩者都解釋「預測類別」的 log-odds（margin），存全部特徵
CREATE TABLE `explanation` (
  `flow_id`      char(36)      NOT NULL,
  `shap_value`   longtext      NOT NULL CHECK (json_valid(`shap_value`)),  -- [{feature, weight}, ...] 依 |weight| 排序
  `base_value`   decimal(10,6) NOT NULL,
  `lime_value`   longtext      NOT NULL CHECK (json_valid(`lime_value`)),  -- 重複多次時為平均權重
  `lime_repeats` tinyint unsigned NOT NULL DEFAULT 1,
  `scale`        varchar(20)   NOT NULL DEFAULT 'log_odds',
  PRIMARY KEY (`flow_id`),
  CONSTRAINT `fk_explanation_flow` FOREIGN KEY (`flow_id`) REFERENCES `flow` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 每筆 flow 在 k = 3, 5, 7 各一列
CREATE TABLE `consistency` (
  `flow_id`            char(36)     NOT NULL,
  `k`                  tinyint unsigned NOT NULL,
  `feature_agreement`  decimal(5,4) NOT NULL,              -- top-k 特徵交集 / k
  `sign_agreement`     decimal(5,4) NOT NULL,              -- 交集中方向相同 / k（主指標）
  `rank_agreement`     decimal(5,4) NOT NULL,              -- 同名次 / k
  `lime_stability`     decimal(5,4) DEFAULT NULL,          -- LIME 重複 n 次兩兩 sign_agreement 平均，n = 1 時 NULL
  `shap_ablation_drop` decimal(5,4) DEFAULT NULL,          -- 移除 SHAP top-k 後預測類別機率下降量
  `lime_ablation_drop` decimal(5,4) DEFAULT NULL,          -- 移除 LIME top-k 後預測類別機率下降量
  PRIMARY KEY (`flow_id`, `k`),
  CONSTRAINT `fk_consistency_flow` FOREIGN KEY (`flow_id`) REFERENCES `flow` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
