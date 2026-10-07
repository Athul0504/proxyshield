import { createServerFn } from "@tanstack/react-start";

import { onboardingSchema } from "@/lib/onboarding-schema";

export type SubmitOnboardingResult =
  | { ok: true; id: string }
  | { ok: false; message: string; fieldErrors: Record<string, string> };

// Saves a client onboarding application to PostgreSQL (database: finalfinal).
// The handler body runs on the server only; `@/lib/db` (and DATABASE_URL) are
// loaded with a dynamic import so they can never end up in the browser bundle.
export const submitOnboarding = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => data)
  .handler(async ({ data }): Promise<SubmitOnboardingResult> => {
    const parsed = onboardingSchema.safeParse(data);
    if (!parsed.success) {
      const fieldErrors: Record<string, string> = {};
      for (const issue of parsed.error.issues) {
        const field = String(issue.path[0] ?? "form");
        if (!(field in fieldErrors)) fieldErrors[field] = issue.message;
      }
      return { ok: false, message: "Please correct the highlighted fields.", fieldErrors };
    }

    const c = parsed.data;
    try {
      // Primary Route: Submit to ProxyShield FastAPI Backend REST API
      const backendUrl = process.env["BACKEND_URL"] || "http://127.0.0.1:8000";
      const res = await fetch(`${backendUrl}/api/onboarding/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(c),
      });

      if (res.ok) {
        const body = (await res.json()) as { ok: boolean; id: string };
        if (body.ok) return { ok: true, id: body.id };
      }

      // Legacy Fallback Route (in case backend API service is unreachable)
      const { getPool, ensureClientsTable } = await import("@/lib/db");
      await ensureClientsTable();
      const result = await getPool().query<{ id: string }>(
        `INSERT INTO clients
           ("fullName", "dateOfBirth", "mobile", "email", "address", "occupation",
            "category", "initialAmount", "verification", "registrationDate")
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id`,
        [
          c.fullName,
          c.dateOfBirth,
          c.mobile,
          c.email,
          c.address,
          c.occupation,
          c.category,
          c.initialAmount,
          c.verification,
          c.registrationDate,
        ],
      );
      const row = result.rows[0];
      if (!row) throw new Error("INSERT returned no row");
      return { ok: true, id: String(row.id) };
    } catch (error) {
      console.error("[onboarding] submission error:", error);
      return {
        ok: false,
        message: "We couldn’t save this application. Please try again in a moment.",
        fieldErrors: {},
      };
    }
  });
