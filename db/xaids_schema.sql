-- MySQL dump 10.13  Distrib 9.3.0, for macos13.7 (arm64)
--
-- Host: localhost    Database: xaids
-- ------------------------------------------------------
-- Server version	12.2.2-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `alert`
--

DROP TABLE IF EXISTS `alert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `alert` (
  `alert_id` char(36) NOT NULL,
  `flow_id` char(36) NOT NULL,
  `attack_type` varchar(50) NOT NULL,
  `confidence` decimal(5,4) NOT NULL,
  `conf_zone` enum('SUSPICIOUS','HIGH_CONF') NOT NULL,
  `status` enum('unhandled','processing','resolved','false_positive') NOT NULL DEFAULT 'unhandled',
  `alert_time` datetime NOT NULL,
  PRIMARY KEY (`alert_id`),
  KEY `packet_id` (`flow_id`),
  CONSTRAINT `fk_alert_flow` FOREIGN KEY (`flow_id`) REFERENCES `flow` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alert`
--

LOCK TABLES `alert` WRITE;
/*!40000 ALTER TABLE `alert` DISABLE KEYS */;
INSERT INTO `alert` VALUES ('0dee2035-41bb-42db-8b15-2e58575c708c','3c7d432d-29d5-48e7-bc51-65bb55298222','BENIGN',1.0000,'HIGH_CONF','unhandled','2026-05-05 12:26:23'),('521acd29-5931-4105-83f9-9d4d36696c46','9a181601-5840-42ae-90c8-8ccc07ae1ff5','BENIGN',1.0000,'HIGH_CONF','unhandled','2026-05-05 13:52:27'),('66428638-36bb-461f-b5ee-6b4399afe55d','e005c10e-7268-4723-b95a-19c7959f0f2b','BENIGN',1.0000,'HIGH_CONF','unhandled','2026-05-05 13:49:36'),('eff6dc53-efcf-470c-960d-2e6b798d6089','604e1555-b320-4c63-a067-0cd999e9af26','BENIGN',1.0000,'HIGH_CONF','unhandled','2026-05-05 13:56:38');
/*!40000 ALTER TABLE `alert` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `explanationForLime`
--

DROP TABLE IF EXISTS `explanationForLime`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `explanationForLime` (
  `alert_id` char(36) NOT NULL,
  `lime_value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`lime_value`)),
  PRIMARY KEY (`alert_id`),
  CONSTRAINT `explanationForLime_ibfk_1` FOREIGN KEY (`alert_id`) REFERENCES `alert` (`alert_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `explanationForLime`
--

LOCK TABLES `explanationForLime` WRITE;
/*!40000 ALTER TABLE `explanationForLime` DISABLE KEYS */;
INSERT INTO `explanationForLime` VALUES ('66428638-36bb-461f-b5ee-6b4399afe55d','[{\"feature\": \" Destination Port\", \"weight\": 0.31680337076077913}, {\"feature\": \"FIN Flag Count\", \"weight\": -0.2659754646033368}, {\"feature\": \" Fwd Packet Length Max\", \"weight\": -0.18103888929700424}, {\"feature\": \"Total Length of Fwd Packets\", \"weight\": 0.16543257524902064}, {\"feature\": \" ECE Flag Count\", \"weight\": -0.1436557817027661}, {\"feature\": \"Bwd IAT Total\", \"weight\": -0.09595601523712904}, {\"feature\": \"Fwd Packets/s\", \"weight\": 0.08249665669452307}, {\"feature\": \" Bwd Packet Length Std\", \"weight\": 0.056838209853999844}, {\"feature\": \" Fwd IAT Std\", \"weight\": 0.04911390174726499}, {\"feature\": \" Subflow Bwd Bytes\", \"weight\": 0.045259480780063296}]'),('eff6dc53-efcf-470c-960d-2e6b798d6089','[{\"feature\": \" Destination Port\", \"weight\": 0.2978643406923222}, {\"feature\": \"FIN Flag Count\", \"weight\": 0.24703899951092617}, {\"feature\": \" Fwd Packet Length Max\", \"weight\": -0.19307831186894975}, {\"feature\": \"Fwd PSH Flags\", \"weight\": 0.1767105850054888}, {\"feature\": \"Total Length of Fwd Packets\", \"weight\": 0.17547580436316162}, {\"feature\": \" Flow IAT Max\", \"weight\": 0.08570361610226088}, {\"feature\": \"Bwd IAT Total\", \"weight\": -0.07568698778843377}, {\"feature\": \" Bwd Header Length\", \"weight\": -0.07183904914306133}, {\"feature\": \" Flow Duration\", \"weight\": -0.054736322598071666}, {\"feature\": \" Fwd Packet Length Mean\", \"weight\": -0.05304970289620485}]');
/*!40000 ALTER TABLE `explanationForLime` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `explanationForShap`
--

DROP TABLE IF EXISTS `explanationForShap`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `explanationForShap` (
  `alert_id` char(36) NOT NULL,
  `shap_value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`shap_value`)),
  `base_value` decimal(10,6) NOT NULL,
  PRIMARY KEY (`alert_id`),
  CONSTRAINT `explanationForShap_ibfk_1` FOREIGN KEY (`alert_id`) REFERENCES `alert` (`alert_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `explanationForShap`
--

LOCK TABLES `explanationForShap` WRITE;
/*!40000 ALTER TABLE `explanationForShap` DISABLE KEYS */;
INSERT INTO `explanationForShap` VALUES ('eff6dc53-efcf-470c-960d-2e6b798d6089','[{\"feature\": \"Total Length of Fwd Packets\", \"weight\": -4.7474}, {\"feature\": \" Destination Port\", \"weight\": -3.7987}, {\"feature\": \"Init_Win_bytes_forward\", \"weight\": -1.5802}, {\"feature\": \" Fwd Packet Length Max\", \"weight\": 1.1947}, {\"feature\": \"Fwd Packets/s\", \"weight\": -1.0051}, {\"feature\": \" Init_Win_bytes_backward\", \"weight\": -0.7719}, {\"feature\": \" Flow IAT Max\", \"weight\": -0.5211}, {\"feature\": \" Flow Packets/s\", \"weight\": -0.5204}, {\"feature\": \" Fwd IAT Min\", \"weight\": -0.4671}, {\"feature\": \" Flow IAT Mean\", \"weight\": -0.3378}]',1.049925);
/*!40000 ALTER TABLE `explanationForShap` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `flow`
--

DROP TABLE IF EXISTS `flow`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `flow` (
  `id` char(36) NOT NULL,
  `source_ip` varchar(45) DEFAULT NULL,
  `destination_ip` varchar(45) DEFAULT NULL,
  `source_port` smallint(5) unsigned DEFAULT NULL,
  `destination_port` smallint(5) unsigned DEFAULT NULL,
  `protocol` varchar(10) DEFAULT NULL,
  `start_time` datetime(3) DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `duration_ms` int(10) unsigned DEFAULT NULL,
  `packet_count` int(10) unsigned DEFAULT NULL,
  `byte_count` int(10) unsigned DEFAULT NULL,
  `computed_features` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`computed_features`)),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `flow`
--

LOCK TABLES `flow` WRITE;
/*!40000 ALTER TABLE `flow` DISABLE KEYS */;
INSERT INTO `flow` VALUES ('3c7d432d-29d5-48e7-bc51-65bb55298222',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}'),('604e1555-b320-4c63-a067-0cd999e9af26',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}'),('7aab9795-6c65-4f8a-a6eb-8ff3e42308e0',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}'),('9a181601-5840-42ae-90c8-8ccc07ae1ff5',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}'),('a5e747fc-35da-457c-a33d-f2797f7ccbea',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}'),('e005c10e-7268-4723-b95a-19c7959f0f2b',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'{\" Destination Port\": 54865.0, \" Flow Duration\": 3.0, \" Total Fwd Packets\": 2.0, \" Total Backward Packets\": 0.0, \"Total Length of Fwd Packets\": 12.0, \" Total Length of Bwd Packets\": 0.0, \" Fwd Packet Length Max\": 6.0, \" Fwd Packet Length Min\": 6.0, \" Fwd Packet Length Mean\": 6.0, \" Fwd Packet Length Std\": 0.0, \"Bwd Packet Length Max\": 0.0, \" Bwd Packet Length Min\": 0.0, \" Bwd Packet Length Mean\": 0.0, \" Bwd Packet Length Std\": 0.0, \"Flow Bytes/s\": 4000000.0, \" Flow Packets/s\": 666666.6667, \" Flow IAT Mean\": 3.0, \" Flow IAT Std\": 0.0, \" Flow IAT Max\": 3.0, \" Flow IAT Min\": 3.0, \"Fwd IAT Total\": 3.0, \" Fwd IAT Mean\": 3.0, \" Fwd IAT Std\": 0.0, \" Fwd IAT Max\": 3.0, \" Fwd IAT Min\": 3.0, \"Bwd IAT Total\": 0.0, \" Bwd IAT Mean\": 0.0, \" Bwd IAT Std\": 0.0, \" Bwd IAT Max\": 0.0, \" Bwd IAT Min\": 0.0, \"Fwd PSH Flags\": 0.0, \" Bwd PSH Flags\": 0.0, \" Fwd URG Flags\": 0.0, \" Bwd URG Flags\": 0.0, \" Fwd Header Length\": 40.0, \" Bwd Header Length\": 0.0, \"Fwd Packets/s\": 666666.6667, \" Bwd Packets/s\": 0.0, \" Min Packet Length\": 6.0, \" Max Packet Length\": 6.0, \" Packet Length Mean\": 6.0, \" Packet Length Std\": 0.0, \" Packet Length Variance\": 0.0, \"FIN Flag Count\": 0.0, \" SYN Flag Count\": 0.0, \" RST Flag Count\": 0.0, \" PSH Flag Count\": 0.0, \" ACK Flag Count\": 1.0, \" URG Flag Count\": 0.0, \" CWE Flag Count\": 0.0, \" ECE Flag Count\": 0.0, \" Down/Up Ratio\": 0.0, \" Average Packet Size\": 9.0, \" Avg Fwd Segment Size\": 6.0, \" Avg Bwd Segment Size\": 0.0, \" Fwd Header Length.1\": 40.0, \"Fwd Avg Bytes/Bulk\": 0.0, \" Fwd Avg Packets/Bulk\": 0.0, \" Fwd Avg Bulk Rate\": 0.0, \" Bwd Avg Bytes/Bulk\": 0.0, \" Bwd Avg Packets/Bulk\": 0.0, \"Bwd Avg Bulk Rate\": 0.0, \"Subflow Fwd Packets\": 2.0, \" Subflow Fwd Bytes\": 12.0, \" Subflow Bwd Packets\": 0.0, \" Subflow Bwd Bytes\": 0.0, \"Init_Win_bytes_forward\": 33.0, \" Init_Win_bytes_backward\": -1.0, \" act_data_pkt_fwd\": 1.0, \" min_seg_size_forward\": 20.0, \"Active Mean\": 0.0, \" Active Std\": 0.0, \" Active Max\": 0.0, \" Active Min\": 0.0, \"Idle Mean\": 0.0, \" Idle Std\": 0.0, \" Idle Max\": 0.0, \" Idle Min\": 0.0}');
/*!40000 ALTER TABLE `flow` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `honeypotRecord`
--

DROP TABLE IF EXISTS `honeypotRecord`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `honeypotRecord` (
  `alert_id` char(36) NOT NULL,
  `src_ip` varchar(50) NOT NULL,
  `raw_log` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`raw_log`)),
  `recorded_at` datetime NOT NULL,
  PRIMARY KEY (`alert_id`),
  CONSTRAINT `honeypotRecord_ibfk_1` FOREIGN KEY (`alert_id`) REFERENCES `alert` (`alert_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `honeypotRecord`
--

LOCK TABLES `honeypotRecord` WRITE;
/*!40000 ALTER TABLE `honeypotRecord` DISABLE KEYS */;
/*!40000 ALTER TABLE `honeypotRecord` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `packet`
--

DROP TABLE IF EXISTS `packet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `packet` (
  `id` char(36) NOT NULL,
  `time` datetime NOT NULL,
  `source_ip` varchar(45) NOT NULL,
  `destination_ip` varchar(45) NOT NULL,
  `protocol` varchar(10) NOT NULL,
  `size` int(10) unsigned NOT NULL,
  `raw_features` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`raw_features`)),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `packet`
--

LOCK TABLES `packet` WRITE;
/*!40000 ALTER TABLE `packet` DISABLE KEYS */;
/*!40000 ALTER TABLE `packet` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `validation`
--

DROP TABLE IF EXISTS `validation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `validation` (
  `alert_id` char(36) NOT NULL,
  `shap_vs_lime_correlation` decimal(5,4) DEFAULT NULL,
  `shap_vs_honeypot_match` decimal(5,4) DEFAULT NULL,
  `lime_vs_honeypot_match` decimal(5,4) DEFAULT NULL,
  `trust_score` decimal(5,4) DEFAULT NULL,
  `status` enum('match','high_similarity','partial_match','mismatch') DEFAULT NULL,
  PRIMARY KEY (`alert_id`),
  CONSTRAINT `validation_ibfk_1` FOREIGN KEY (`alert_id`) REFERENCES `alert` (`alert_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `validation`
--

LOCK TABLES `validation` WRITE;
/*!40000 ALTER TABLE `validation` DISABLE KEYS */;
/*!40000 ALTER TABLE `validation` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-05-05 16:22:52
