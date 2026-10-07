import { z } from "zod";

// Shared by the onboarding form (browser) and the server function, so both
// sides enforce exactly the same rules. The server never trusts the browser.

const isoDate = (message: string) =>
  z
    .string()
    .min(1, message)
    .refine((value) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
      const parsed = new Date(`${value}T00:00:00Z`);
      return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
    }, "Enter a valid date");

export const onboardingSchema = z.object({
  fullName: z.string().trim().min(2, "Enter the client’s full name").max(100),
  dateOfBirth: isoDate("Select the date of birth").refine(
    // Evaluated per call (not at module load) so a long-running server never goes stale.
    (value) => value <= new Date().toISOString().slice(0, 10),
    "Date of birth cannot be in the future",
  ),
  mobile: z.string().trim().regex(/^[6-9]\d{9}$/, "Enter a valid 10-digit mobile number"),
  email: z.string().trim().email("Enter a valid email address").max(255),
  address: z.string().trim().min(5, "Enter the residential address").max(300),
  occupation: z.string().min(1, "Select an occupation").max(100),
  category: z.enum(["Savings", "Current", "Salary"]),
  initialAmount: z
    .union([z.string(), z.number()])
    .refine((value) => String(value).trim() !== "", "Enter the initial amount")
    .pipe(z.coerce.number().min(0, "Amount cannot be negative").max(100000000)),
  verification: z.enum(["Verified", "Pending", "Unverified"], {
    required_error: "Select verification status",
  }),
  registrationDate: isoDate("Select the registration date"),
});

export type OnboardingData = z.infer<typeof onboardingSchema>;
export type OnboardingField = keyof OnboardingData;
