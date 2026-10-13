#!/bin/bash
set -eu
# Generated credentials are hex; never interpolate arbitrary shell-provided values.
for value in "$VULN002_APP_PASSWORD" "$VULN002_MANAGER_PASSWORD" "$VULN002_READER_PASSWORD"; do
  [[ "$value" =~ ^[a-f0-9]{48}$ ]] || exit 1
done
export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
for suffix in vulnerable secure vulnerable_test secure_test; do
  db="lab_vuln002_$suffix"
  mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS $db;
USE $db;
CREATE TABLE lab_identity (lab_id VARCHAR(16) PRIMARY KEY);
INSERT INTO lab_identity VALUES ('VULN-002');
CREATE TABLE lab_users (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 run_id CHAR(32) NOT NULL,
 username VARCHAR(64) NOT NULL UNIQUE,
 password_hash VARCHAR(60) NOT NULL,
 role VARCHAR(16) NOT NULL CHECK(role = 'USER'),
 UNIQUE KEY uq_run_user(run_id, username)
);
CREATE TABLE lab_articles (
 id BIGINT AUTO_INCREMENT PRIMARY KEY,
 run_id CHAR(32) NOT NULL,
 user_id BIGINT NOT NULL,
 title VARCHAR(200) NOT NULL,
 content TEXT NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 FOREIGN KEY(user_id) REFERENCES lab_users(id),
 KEY ix_run(run_id)
);
CREATE USER 'v002_${suffix}_app'@'%' IDENTIFIED BY '$VULN002_APP_PASSWORD';
CREATE USER 'v002_${suffix}_manager'@'%' IDENTIFIED BY '$VULN002_MANAGER_PASSWORD';
CREATE USER 'v002_${suffix}_reader'@'%' IDENTIFIED BY '$VULN002_READER_PASSWORD';
GRANT SELECT ON $db.lab_identity TO 'v002_${suffix}_app'@'%';
GRANT SELECT ON $db.lab_users TO 'v002_${suffix}_app'@'%';
GRANT SELECT ON $db.lab_articles TO 'v002_${suffix}_app'@'%';
GRANT UPDATE(title, content, updated_at) ON $db.lab_articles TO 'v002_${suffix}_app'@'%';
GRANT SELECT ON $db.lab_identity TO 'v002_${suffix}_manager'@'%';
GRANT SELECT, INSERT, DELETE ON $db.lab_users TO 'v002_${suffix}_manager'@'%';
GRANT SELECT, INSERT, DELETE ON $db.lab_articles TO 'v002_${suffix}_manager'@'%';
GRANT SELECT ON $db.lab_articles TO 'v002_${suffix}_reader'@'%';
SQL
done
