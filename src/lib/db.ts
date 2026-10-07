// SERVER-ONLY. Never import this file from client/UI code: it reads DATABASE_URL
// and opens a PostgreSQL connection. It is only reached through the server
// function in src/lib/onboarding-actions.ts (loaded with a dynamic import inside the handler).
import pg from "pg";
import type { Pool } from "pg";

declare global {
  // Keeps one pool across dev-server hot reloads.
  // eslint-disable-next-line no-var
  var __finalfinalPgPool: Pool | undefined;
  // eslint-disable-next-line no-var
  var __finalfinalSchemaReady: Promise<void> | undefined;
}

export class DatabaseConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DatabaseConfigError";
  }
}

function readDatabaseUrl(): string {
  if (!process.env["DATABASE_URL"]) {
    // `vite dev` does not copy non-VITE_ variables from .env into process.env.
    try {
      process.loadEnvFile?.(".env");
    } catch {
      // No .env file — fall through to the error below.
    }
  }
  const url = process.env["DATABASE_URL"];
  if (!url) throw new DatabaseConfigError("DATABASE_URL is not set on the server");
  return url;
}

export function getPool(): Pool {
  if (!globalThis.__finalfinalPgPool) {
    const pool = new pg.Pool({
      connectionString: readDatabaseUrl(),
      max: 5,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
    });
    // An error on an idle client must not crash the server process.
    pool.on("error", (error) => console.error("[db] idle client error:", error.message));
    globalThis.__finalfinalPgPool = pool;
  }
  return globalThis.__finalfinalPgPool;
}

// Same DDL as db/schema.sql. IF NOT EXISTS means an existing `clients` table is left untouched.
const CREATE_CLIENTS_TABLE = `
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
  )
`;

export function ensureClientsTable(): Promise<void> {
  const existing = globalThis.__finalfinalSchemaReady;
  if (existing) return existing;

  const pending = getPool()
    .query(CREATE_CLIENTS_TABLE)
    .then(() => undefined)
    .catch((error: unknown) => {
      globalThis.__finalfinalSchemaReady = undefined; // retry on the next request
      throw error;
    });
  globalThis.__finalfinalSchemaReady = pending;
  return pending;
}
