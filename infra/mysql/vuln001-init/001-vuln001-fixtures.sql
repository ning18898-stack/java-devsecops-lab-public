CREATE TABLE IF NOT EXISTS lab_articles (
    id BIGINT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    visibility VARCHAR(16) NOT NULL
);
INSERT INTO lab_articles (id, title, visibility)
SELECT 1, 'Alpha public article', 'public' WHERE NOT EXISTS (SELECT 1 FROM lab_articles WHERE id = 1);
INSERT INTO lab_articles (id, title, visibility)
SELECT 2, 'Beta public article', 'public' WHERE NOT EXISTS (SELECT 1 FROM lab_articles WHERE id = 2);
INSERT INTO lab_articles (id, title, visibility)
SELECT 3, 'Synthetic draft article', 'draft' WHERE NOT EXISTS (SELECT 1 FROM lab_articles WHERE id = 3);
