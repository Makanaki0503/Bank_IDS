-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Feb 15, 2026 at 08:44 AM
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
-- Database: `archilink`
--

-- --------------------------------------------------------

--
-- Table structure for table `activity_logs`
--

CREATE TABLE `activity_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(100) NOT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `applications`
--

CREATE TABLE `applications` (
  `id` int(11) NOT NULL,
  `student_id` int(11) NOT NULL,
  `firm_id` int(11) NOT NULL,
  `status` enum('pending','accepted','rejected') DEFAULT 'pending',
  `applied_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT NULL,
  `reviewed_by` int(11) DEFAULT NULL,
  `review_notes` text DEFAULT NULL,
  `cover_letter` text DEFAULT NULL,
  `expected_start_date` date DEFAULT NULL,
  `expected_end_date` date DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `is_starred` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `applications`
--

INSERT INTO `applications` (`id`, `student_id`, `firm_id`, `status`, `applied_at`, `updated_at`, `reviewed_by`, `review_notes`, `cover_letter`, `expected_start_date`, `expected_end_date`, `is_read`, `is_starred`) VALUES
(21, 8, 3, 'accepted', '2026-02-13 05:41:40', '2026-02-12 22:31:14', 3, NULL, NULL, NULL, NULL, 1, 0);

-- --------------------------------------------------------

--
-- Table structure for table `firms`
--

CREATE TABLE `firms` (
  `id` int(11) NOT NULL,
  `firm_name` varchar(150) NOT NULL,
  `location` varchar(100) NOT NULL,
  `specialization` varchar(100) DEFAULT NULL,
  `accepts_interns` tinyint(1) DEFAULT 1,
  `license_verified` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `status` enum('pending','approved','rejected') DEFAULT 'pending'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `firms`
--

INSERT INTO `firms` (`id`, `firm_name`, `location`, `specialization`, `accepts_interns`, `license_verified`, `created_at`, `status`) VALUES
(1, 'ArchDesign Ltd', 'Lagos', 'Urban Design', 1, 0, '2026-02-10 19:00:44', 'pending'),
(2, 'BuildIt Architects', 'Abuja', 'Residential', 1, 0, '2026-02-10 19:00:44', 'pending'),
(3, 'Skyline Studio', 'Port Harcourt', 'Commercial', 1, 0, '2026-02-10 19:00:44', 'pending'),
(4, 'Vision Arch', 'Kaduna', 'Interior Design', 1, 0, '2026-02-10 19:00:44', 'pending');

-- --------------------------------------------------------

--
-- Table structure for table `firm_profiles`
--

CREATE TABLE `firm_profiles` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `profile_photo` varchar(255) DEFAULT NULL,
  `profile_photo_updated_at` datetime DEFAULT NULL,
  `firm_name` varchar(255) DEFAULT NULL,
  `registration_no` varchar(100) DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `website` varchar(255) DEFAULT NULL,
  `specialization` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `established_year` varchar(10) DEFAULT NULL,
  `employee_count` varchar(50) DEFAULT NULL,
  `license_verified` tinyint(1) DEFAULT 0,
  `accepts_interns` tinyint(1) DEFAULT 1,
  `internship_duration` varchar(50) DEFAULT NULL,
  `internship_topics` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `firm_profiles`
--

INSERT INTO `firm_profiles` (`id`, `user_id`, `profile_photo`, `profile_photo_updated_at`, `firm_name`, `registration_no`, `location`, `address`, `phone`, `email`, `website`, `specialization`, `description`, `established_year`, `employee_count`, `license_verified`, `accepts_interns`, `internship_duration`, `internship_topics`, `created_at`, `updated_at`) VALUES
(2, 3, 'assets/uploads/profiles/firms/user_3_1770976813_4030ee030702d55f.jpg', '2026-02-13 02:00:13', 'HillBrix Limited', 'RC234654', 'Gombe', 'Gombe', '09038424288', 'hillbrixlimited@gmail.com', 'https://www.hillbrixlimited.netlify.app', 'General Practice', 'Being Unique', '2010', '11-50', 0, 1, '6 months', 'Everything', '2026-02-12 13:04:07', '2026-02-13 02:07:59');

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `type` enum('student','firm') NOT NULL,
  `message` varchar(255) NOT NULL,
  `is_read` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `student_profiles`
--

CREATE TABLE `student_profiles` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `profile_photo` varchar(255) DEFAULT NULL,
  `profile_photo_updated_at` datetime DEFAULT NULL,
  `full_name` varchar(255) DEFAULT NULL,
  `matric_no` varchar(100) DEFAULT NULL,
  `institution` varchar(255) DEFAULT NULL,
  `department` varchar(100) DEFAULT NULL,
  `level` varchar(50) DEFAULT NULL,
  `siwes_start` date DEFAULT NULL,
  `siwes_end` date DEFAULT NULL,
  `skills` text DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `bio` text DEFAULT NULL,
  `portfolio_url` varchar(255) DEFAULT NULL,
  `linkedin_url` varchar(255) DEFAULT NULL,
  `available_for_internship` tinyint(1) DEFAULT 1,
  `preferred_location` varchar(100) DEFAULT NULL,
  `expected_stipend` varchar(50) DEFAULT NULL,
  `resume` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `student_profiles`
--

INSERT INTO `student_profiles` (`id`, `user_id`, `profile_photo`, `profile_photo_updated_at`, `full_name`, `matric_no`, `institution`, `department`, `level`, `siwes_start`, `siwes_end`, `skills`, `phone`, `address`, `bio`, `portfolio_url`, `linkedin_url`, `available_for_internship`, `preferred_location`, `expected_stipend`, `resume`, `created_at`, `updated_at`) VALUES
(1, 2, 'assets/uploads/profiles/students/user_2_1770931566_df15e9dea0baf403.jpg', '2026-02-12 13:26:06', NULL, NULL, NULL, 'Architechure', '500', NULL, NULL, 'Everything in Architecture', NULL, NULL, NULL, NULL, NULL, 1, NULL, NULL, NULL, '2026-02-12 13:01:29', '2026-02-12 13:26:06'),
(2, 8, 'assets/uploads/profiles/students/user_8_1770965041_eba33b4d5636579c.jpg', '2026-02-12 22:44:01', 'zayyad Ishiaku', '2019/2234', 'Mautech yola', 'Architechure', '400', '2026-02-01', '2026-04-25', 'AutoCARD, REVIT', '09022334455', 'Gombe', 'i am good in everything', '', '', 1, 'Gombe', '50000', NULL, '2026-02-12 13:01:44', '2026-02-12 22:44:01');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `role` enum('student','firm','admin') NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `role`, `name`, `email`, `password`, `created_at`, `updated_at`, `status`) VALUES
(2, 'student', 'Makanaki', 'mohazgloballink@gmail.com', '$2y$10$9yQMJoixAMzn9C2cyOop3esIyvTggZ4SjPIw7HbVtXL49YrZH6rHS', '2026-02-10 17:51:50', NULL, 'approved'),
(3, 'firm', 'HillBrix Limited', 'hillbrixlimited@gmail.com', '$2y$10$OgeKRJXPILA1DIAg3IjNGeYtTze2vaFWeZko2R18g3DQopRwGkXkG', '2026-02-10 19:07:35', NULL, 'approved'),
(4, 'admin', 'System Admin', 'admin@archilink.com', '$2y$10$iESd45ZzwacCPVv5DkbQ7.eNvpvzSxB5LU9s7WB0WwzDR9cAB3sEy', '2026-02-11 11:07:14', NULL, 'pending'),
(8, 'student', 'zayyad Ishiaku', 'musa@gmail.com', '$2y$10$/75twevE2mQ8jPh9JcAaD.0NayWg45v7rvDO72a.ca1YqR9RbVPMe', '2026-02-12 20:37:59', NULL, 'approved'),
(9, 'admin', 'Ishiaku', 'ishiaku@gmail.com', '$2y$10$cfRjrmq/IvRyWTwdBI8JEOuHtthJHZKXzSKBZMy1nn0GzndOQBNdO', '2026-02-13 07:15:38', '2026-02-12 23:30:24', 'approved');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `activity_logs`
--
ALTER TABLE `activity_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `created_at` (`created_at`);

--
-- Indexes for table `applications`
--
ALTER TABLE `applications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `firm_id` (`firm_id`),
  ADD KEY `idx_updated_at` (`updated_at`),
  ADD KEY `idx_is_read` (`is_read`),
  ADD KEY `idx_student_firm` (`student_id`,`firm_id`),
  ADD KEY `idx_reviewed_by` (`reviewed_by`);

--
-- Indexes for table `firms`
--
ALTER TABLE `firms`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `firm_profiles`
--
ALTER TABLE `firm_profiles`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `idx_location` (`location`),
  ADD KEY `idx_specialization` (`specialization`),
  ADD KEY `idx_accepts_interns` (`accepts_interns`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `student_profiles`
--
ALTER TABLE `student_profiles`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `activity_logs`
--
ALTER TABLE `activity_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `applications`
--
ALTER TABLE `applications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- AUTO_INCREMENT for table `firms`
--
ALTER TABLE `firms`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `firm_profiles`
--
ALTER TABLE `firm_profiles`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `student_profiles`
--
ALTER TABLE `student_profiles`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `applications`
--
ALTER TABLE `applications`
  ADD CONSTRAINT `applications_ibfk_1` FOREIGN KEY (`student_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `applications_ibfk_2` FOREIGN KEY (`firm_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `firm_profiles`
--
ALTER TABLE `firm_profiles`
  ADD CONSTRAINT `firm_profiles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `student_profiles`
--
ALTER TABLE `student_profiles`
  ADD CONSTRAINT `student_profiles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
