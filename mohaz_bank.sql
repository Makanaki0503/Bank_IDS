-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 19, 2026 at 07:35 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `mohaz_bank`
--

-- --------------------------------------------------------

--
-- Table structure for table `blocked_ips`
--

CREATE TABLE `blocked_ips` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `customers`
--

CREATE TABLE `customers` (
  `id` int(11) NOT NULL,
  `customer_id` varchar(50) NOT NULL,
  `encrypted_name` text NOT NULL,
  `encrypted_email` text NOT NULL,
  `encrypted_phone` text NOT NULL,
  `encrypted_account_number` text NOT NULL,
  `encrypted_balance` text NOT NULL,
  `iv` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_by` varchar(50) DEFAULT 'admin',
  `owner_key` varchar(255) DEFAULT NULL,
  `user_key` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `customers`
--

INSERT INTO `customers` (`id`, `customer_id`, `encrypted_name`, `encrypted_email`, `encrypted_phone`, `encrypted_account_number`, `encrypted_balance`, `iv`, `created_at`, `created_by`, `owner_key`, `user_key`) VALUES
(4, 'CUST1773896542504', 'c0huL2YyS2VoT0t0czEzcU5pV1pIUT09', 'R2E3MlBKT0J2Umh2OXBraTR0UVMyR3ExWmE2ZFJGRDZPc09RSTRMUm92Yz0=', 'OXcrblR5WllLeGFLWmxrVnhkZmpWUT09', 'bDJsNXp0Tnp5QVdZTFFlWVVVbEFFZz09', 'Tk9NdDFsRUI1VWZ4em1nTklmdnBqZz09', 'W6Ak0Zbh+CwrAN9jPBoTXg==', '2026-03-19 05:02:22', 'hillbrixlimited@gmail.com', 'af3e1fe2a6034856686cb14843536cdbda040fb2ad7e7d075fa6ef3e2db26020', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `failed_logins`
--

CREATE TABLE `failed_logins` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `failed_logins`
--

INSERT INTO `failed_logins` (`id`, `ip_address`, `username`, `user_agent`, `created_at`) VALUES
(1, '::1', 'admin@gufax.com', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36', '2026-03-19 04:15:21'),
(2, '::1', 'admin@gufax.com', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36', '2026-03-19 04:15:31'),
(3, '::1', 'admin@gufax.com', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36', '2026-03-19 04:15:34');

-- --------------------------------------------------------

--
-- Table structure for table `intrusion_logs`
--

CREATE TABLE `intrusion_logs` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `activity` text DEFAULT NULL,
  `threat_level` varchar(20) DEFAULT NULL,
  `status` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `intrusion_logs`
--

INSERT INTO `intrusion_logs` (`id`, `ip_address`, `activity`, `threat_level`, `status`, `created_at`) VALUES
(1, '::1', 'Successful login: admin@gufax.com', 'Low', 'Success', '2026-03-19 04:14:01'),
(2, '::1', 'Failed login attempt for user: admin@gufax.com (Attempt #1)', 'Low', 'Failed', '2026-03-19 04:15:21'),
(3, '::1', 'Failed login attempt for user: admin@gufax.com (Attempt #2)', 'Low', 'Failed', '2026-03-19 04:15:31'),
(4, '::1', 'Failed login attempt for user: admin@gufax.com (Attempt #3)', 'Medium', 'Failed', '2026-03-19 04:15:35'),
(5, '::1', 'Successful login: admin@gufax.com', 'Low', 'Success', '2026-03-19 04:15:41'),
(6, '::1', 'Successful login: hillbrixlimited@gmail.com', 'Low', 'Success', '2026-03-19 04:27:51'),
(7, '::1', 'Successful login: admin@gufax.com', 'Low', 'Success', '2026-03-19 04:35:08'),
(8, '::1', 'User admin@gufax.com viewed customers (3 records)', 'Low', 'Success', '2026-03-19 04:43:44'),
(9, '::1', 'Admin admin@gufax.com viewed all customers', 'Low', 'Success', '2026-03-19 04:48:26'),
(10, '::1', 'Successful login: hillbrixlimited@gmail.com', 'Low', 'Success', '2026-03-19 04:54:39'),
(11, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:50'),
(12, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:52'),
(13, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:52'),
(14, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:52'),
(15, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:53'),
(16, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:53'),
(17, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:53'),
(18, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:53'),
(19, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:56'),
(20, '::1', 'Unauthorized admin access attempt by user: hillbrixlimited@gmail.com', 'High', 'Blocked', '2026-03-19 04:54:58'),
(21, '::1', 'User hillbrixlimited@gmail.com added customer: CUST1773896542504', 'Low', 'Success', '2026-03-19 05:02:22'),
(22, '::1', 'User hillbrixlimited@gmail.com viewed 1 customers', 'Low', 'Success', '2026-03-19 05:02:30'),
(23, '::1', 'Successful login: admin@gufax.com', 'Low', 'Success', '2026-03-19 05:02:48'),
(24, '::1', 'User admin@gufax.com viewed 1 customers', 'Low', 'Success', '2026-03-19 05:03:30'),
(25, '::1', 'User admin@gufax.com viewed 1 customers', 'Low', 'Success', '2026-03-19 06:05:04'),
(26, '::1', 'User admin@gufax.com viewed 1 customers', 'Low', 'Success', '2026-03-19 06:17:06'),
(27, '::1', 'Successful login: admin@gufax.com', 'Low', 'Success', '2026-03-19 06:17:13');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `encryption_key` varchar(255) DEFAULT NULL,
  `role` varchar(50) DEFAULT 'user',
  `is_locked` tinyint(1) DEFAULT 0,
  `lockout_until` timestamp NULL DEFAULT NULL,
  `failed_attempts` int(11) DEFAULT 0,
  `last_failed_login` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `encryption_key`, `role`, `is_locked`, `lockout_until`, `failed_attempts`, `last_failed_login`, `created_at`) VALUES
(1, 'admin@gufax.com', '$2y$10$G43glMFY7wB6xpX0o/RsAeXJHSUGRYKLfrDAmxJ1LrNxvQLFzGBDy', '739b62cfc65c4d8fcd97a00e238eef608e925800ed6046377184c1f9b834e699', 'admin', 0, NULL, 0, NULL, '2026-03-19 02:08:40'),
(2, 'hillbrixlimited@gmail.com', '$2y$10$yDWj37waI.3tY.mKSt894OOyhOHXQemYKR.mHYU0C7GHhFyGOcnRC', 'af3e1fe2a6034856686cb14843536cdbda040fb2ad7e7d075fa6ef3e2db26020', 'user', 0, NULL, 0, NULL, '2026-03-19 02:14:56');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `blocked_ips`
--
ALTER TABLE `blocked_ips`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `ip_address` (`ip_address`);

--
-- Indexes for table `customers`
--
ALTER TABLE `customers`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `customer_id` (`customer_id`);

--
-- Indexes for table `failed_logins`
--
ALTER TABLE `failed_logins`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `intrusion_logs`
--
ALTER TABLE `intrusion_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `blocked_ips`
--
ALTER TABLE `blocked_ips`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `customers`
--
ALTER TABLE `customers`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `failed_logins`
--
ALTER TABLE `failed_logins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `intrusion_logs`
--
ALTER TABLE `intrusion_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
