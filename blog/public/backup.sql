-- MySQL dump 10.13  Distrib 8.0.36
-- Server version: 8.0.36-0ubuntu0.22.04.1
-- Host: db.honeypot.internal    Database: production_db
-- Generated: 2026-05-01 04:00:01 (automated daily backup)
-- --------------------------------------------------------

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Table structure for `users`
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('superadmin','admin','analyst','viewer') DEFAULT 'viewer',
  `api_key` varchar(64) DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`),
  UNIQUE KEY `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES
  (1,'admin','admin@honeypot.internal','$2y$10$XkL9mN2pQ7rS4tU6vW8xYz.fakehash123456789','superadmin','sk-adm-a1b2c3d4e5f6','2026-05-01 03:45:12','2026-01-15 10:00:00'),
  (2,'operator','operator@honeypot.internal','$2y$10$Ab3Cd5Ef7Gh9Ij1Kl3Mn5O.fakehash987654321','admin','sk-usr-g7h8i9j0k1l2','2026-04-30 22:18:45','2026-01-15 10:05:00'),
  (3,'analyst1','analyst@honeypot.internal','$2y$10$Pq3Rs5Tu7Vw9Xy1Za3Bc5D.fakehashanalyst0001','analyst','sk-anl-m3n4o5p6q7r8','2026-04-28 14:30:00','2026-02-20 08:00:00'),
  (4,'viewer_bot','bot@honeypot.internal','$2y$10$Ef3Gh5Ij7Kl9Mn1Op3Qr5S.fakehashbotuser0001','viewer',NULL,NULL,'2026-03-01 12:00:00');

-- Table structure for `api_keys`
DROP TABLE IF EXISTS `api_keys`;
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `key_value` varchar(128) NOT NULL,
  `service` varchar(64) NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `api_keys` VALUES
  (1,1,'AKIA3J3UHE32MVZOUVYX','aws_prod','2026-01-20 09:00:00'),
  (2,1,'sk_live_51abc123def456ghi789','stripe_prod','2026-01-20 09:05:00'),
  (3,1,'SG.fake1234567890.abcdefghijklmnop','sendgrid','2026-02-10 14:00:00'),
  (4,2,'c971960fakefakefake','abuseipdb','2026-03-01 08:00:00');

-- Table structure for `sessions`
DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
  `id` varchar(128) NOT NULL,
  `user_id` int NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` text,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `expires_at` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dump completed: 2026-05-01 04:00:03
