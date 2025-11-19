CREATE TABLE
  IF NOT EXISTS `#__jbrasso_oauth_tokens` (
    `id` INT (11) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `access_token` TEXT NOT NULL,
    `refresh_token` TEXT NULL,
    `expires_in` INT NULL,
    `created_at` TEXT NULL,
    `updated_at` TEXT NULL,
    PRIMARY KEY (`id`)
  );