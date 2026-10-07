-- Database: finalfinal   (create once with:  createdb finalfinal)
-- Apply manually (optional — the app also creates this table on first submit):
--   psql "$DATABASE_URL" -f db/schema.sql
CREATE TABLE IF NOT EXISTS clients (
  id                 BIGSERIAL PRIMARY KEY,
  "fullName"         TEXT           NOT NULL,
  "dateOfBirth"      DATE           NOT NULL,
  "mobile"           VARCHAR(10)    NOT NULL,
  "email"            TEXT           NOT NULL,
  "address"          TEXT           NOT NULL,
  "occupation"       TEXT           NOT NULL,
  "category"         TEXT           NOT NULL CHECK ("category" IN ('Savings', 'Current', 'Salary')),
  "initialAmount"    NUMERIC(15, 2) NOT NULL CHECK ("initialAmount" >= 0),
  "verification"     TEXT           NOT NULL CHECK ("verification" IN ('Verified', 'Pending', 'Unverified')),
  "registrationDate" DATE           NOT NULL,
  "createdAt"        TIMESTAMPTZ    NOT NULL DEFAULT now()
);
