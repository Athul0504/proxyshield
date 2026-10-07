import { createFileRoute } from "@tanstack/react-router";
import {
  BadgeCheck,
  BriefcaseBusiness,
  CalendarDays,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  IndianRupee,
  LoaderCircle,
  LockKeyhole,
  Mail,
  MapPin,
  Network,
  Phone,
  ShieldCheck,
  Smartphone,
  UserRound,
  UsersRound,
  X,
} from "lucide-react";
import { useRef, useState, type FormEvent, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { onboardingSchema, type OnboardingField } from "@/lib/onboarding-schema";
import { submitOnboarding } from "@/lib/onboarding-actions";

const today = new Date().toISOString().slice(0, 10);

type FieldName = OnboardingField;
type FormErrors = Partial<Record<FieldName, string>>;

const initialForm = {
  fullName: "",
  dateOfBirth: "",
  mobile: "",
  email: "",
  address: "",
  occupation: "",
  category: "Savings",
  initialAmount: "",
  verification: "Pending",
  registrationDate: today,
};

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Client Onboarding | SecureApp" },
      {
        name: "description",
        content: "SecureApp client onboarding form for personal, account, and system details.",
      },
      { property: "og:title", content: "Client Onboarding | SecureApp" },
      {
        property: "og:description",
        content: "Secure client onboarding for internal CRM operations.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  const [form, setForm] = useState(initialForm);
  const [errors, setErrors] = useState<FormErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // Synchronous lock: state updates are async, so a fast double-click could otherwise submit twice.
  const submittingRef = useRef(false);

  const updateField = (name: FieldName, value: string) => {
    setForm((current) => ({ ...current, [name]: value }));
    if (errors[name]) {
      setErrors((current) => ({ ...current, [name]: undefined }));
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submittingRef.current) return;
    const formElement = event.currentTarget;
    const result = onboardingSchema.safeParse(form);

    if (!result.success) {
      const nextErrors: FormErrors = {};
      result.error.issues.forEach((issue) => {
        const field = issue.path[0] as FieldName;
        if (!nextErrors[field]) nextErrors[field] = issue.message;
      });
      setErrors(nextErrors);
      const firstInvalid = formElement.querySelector<HTMLElement>("[aria-invalid='true']");
      firstInvalid?.focus();
      return;
    }

    submittingRef.current = true;
    setErrors({});
    setSubmitError(null);
    setIsSubmitting(true);
    try {
      const response = await submitOnboarding({ data: result.data });
      if (response.ok) {
        setForm(initialForm); // saved — clear the form so it cannot be re-submitted as a duplicate
        setShowSuccess(true);
      } else {
        setErrors(response.fieldErrors as FormErrors);
        setSubmitError(response.message);
      }
    } catch (error) {
      console.error(error);
      setSubmitError("Network error — the application was not saved. Please try again.");
    } finally {
      submittingRef.current = false;
      setIsSubmitting(false);
    }
  };

  return (
    <main className="min-h-screen bg-background">
      <header className="border-b border-border bg-surface/95 shadow-header backdrop-blur-sm">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:h-18 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-lg bg-primary text-primary-foreground shadow-brand">
              <LockKeyhole size={19} strokeWidth={2.4} aria-hidden="true" />
            </div>
            <div>
              <div className="text-[17px] font-bold leading-none text-foreground">SecureApp</div>
              <div className="mt-1 text-[11px] font-medium text-muted-foreground">Internal CRM</div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-semibold text-success">
            <ShieldCheck size={17} aria-hidden="true" />
            <span className="hidden sm:inline">Secure session</span>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 sm:py-10 lg:px-8">
        <div className="mb-8 max-w-2xl">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-primary">
            <UsersRound size={17} aria-hidden="true" />
            Client Management
          </div>
          <h1 className="text-2xl font-bold text-foreground sm:text-3xl">Client Onboarding Form</h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground sm:text-base">
            Enter and review the client’s information before submitting the application.
          </p>
        </div>

        <form onSubmit={handleSubmit} noValidate className="space-y-6">
          <FormSection
            number="01"
            title="Personal Information"
            description="Client identity and contact details"
            icon={<UserRound size={20} />}
          >
            <div className="grid gap-5 md:grid-cols-2">
              <Field label="Full Name" htmlFor="fullName" required error={errors.fullName} icon={<UserRound size={17} />}>
                <input id="fullName" name="fullName" value={form.fullName} onChange={(e) => updateField("fullName", e.target.value)} placeholder="Rahul Kumar" autoComplete="name" maxLength={100} aria-invalid={Boolean(errors.fullName)} className="form-control" />
              </Field>
              <Field label="Date of Birth" htmlFor="dateOfBirth" required error={errors.dateOfBirth} icon={<CalendarDays size={17} />}>
                <input id="dateOfBirth" name="dateOfBirth" type="date" max={today} value={form.dateOfBirth} onChange={(e) => updateField("dateOfBirth", e.target.value)} aria-invalid={Boolean(errors.dateOfBirth)} className="form-control" />
              </Field>
              <Field label="Mobile Number" htmlFor="mobile" required error={errors.mobile} icon={<Phone size={17} />}>
                <div className="input-composite">
                  <span className="border-r border-border pr-3 text-sm font-semibold text-muted-foreground">+91</span>
                  <input id="mobile" name="mobile" type="tel" inputMode="numeric" value={form.mobile} onChange={(e) => updateField("mobile", e.target.value.replace(/\D/g, "").slice(0, 10))} placeholder="98XXXXXXXX" autoComplete="tel" aria-invalid={Boolean(errors.mobile)} className="min-w-0 flex-1 bg-transparent outline-none" />
                </div>
              </Field>
              <Field label="Email Address" htmlFor="email" required error={errors.email} icon={<Mail size={17} />}>
                <input id="email" name="email" type="email" value={form.email} onChange={(e) => updateField("email", e.target.value)} placeholder="rahul@example.com" autoComplete="email" maxLength={255} aria-invalid={Boolean(errors.email)} className="form-control" />
              </Field>
              <Field label="Residential Address" htmlFor="address" required error={errors.address} icon={<MapPin size={17} />} className="md:col-span-2">
                <textarea id="address" name="address" value={form.address} onChange={(e) => updateField("address", e.target.value)} placeholder="Kochi, Kerala" autoComplete="street-address" maxLength={300} rows={3} aria-invalid={Boolean(errors.address)} className="form-control min-h-24 resize-y py-3" />
              </Field>
              <Field label="Occupation" htmlFor="occupation" required error={errors.occupation} icon={<BriefcaseBusiness size={17} />}>
                <SelectField id="occupation" value={form.occupation} onChange={(value) => updateField("occupation", value)} invalid={Boolean(errors.occupation)}>
                  <option value="">Select occupation</option>
                  <option>Salaried Professional</option><option>Business Owner</option><option>Self-employed</option><option>Student</option><option>Retired</option><option>Other</option>
                </SelectField>
              </Field>
            </div>
          </FormSection>

          <FormSection number="02" title="Account Details" description="Account setup and verification" icon={<BadgeCheck size={20} />}>
            <div className="grid gap-5 md:grid-cols-2">
              <Field label="Category" htmlFor="category" required error={errors.category}>
                <SelectField id="category" value={form.category} onChange={(value) => updateField("category", value)} invalid={Boolean(errors.category)}>
                  <option>Savings</option><option>Current</option><option>Salary</option>
                </SelectField>
              </Field>
              <Field label="Initial Amount" htmlFor="initialAmount" required error={errors.initialAmount} icon={<IndianRupee size={17} />}>
                <div className="input-composite">
                  <IndianRupee size={16} className="text-muted-foreground" aria-hidden="true" />
                  <input id="initialAmount" name="initialAmount" type="number" min="0" step="1" value={form.initialAmount} onChange={(e) => updateField("initialAmount", e.target.value)} placeholder="25,000" inputMode="numeric" aria-invalid={Boolean(errors.initialAmount)} className="min-w-0 flex-1 bg-transparent outline-none" />
                </div>
              </Field>
              <Field label="Document Verification" htmlFor="verification" required error={errors.verification}>
                <SelectField id="verification" value={form.verification} onChange={(value) => updateField("verification", value)} invalid={Boolean(errors.verification)}>
                  <option>Verified</option><option>Pending</option><option>Unverified</option>
                </SelectField>
              </Field>
              <Field label="Registration Date" htmlFor="registrationDate" required error={errors.registrationDate} icon={<CalendarDays size={17} />}>
                <input id="registrationDate" name="registrationDate" type="date" value={form.registrationDate} onChange={(e) => updateField("registrationDate", e.target.value)} aria-invalid={Boolean(errors.registrationDate)} className="form-control" />
              </Field>
            </div>
          </FormSection>

          <FormSection number="03" title="System Diagnostics" description="Automatically captured for security and audit" icon={<Network size={20} />} system>
            <div className="mb-5 flex items-center gap-2 rounded-lg border border-info-border bg-info px-3 py-2.5 text-xs font-medium text-info-foreground">
              <ShieldCheck size={16} className="shrink-0" aria-hidden="true" />
              These values are securely captured by the system and cannot be edited.
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <Diagnostic label="Client Node ID" value="DEV-126-A" icon={<Network size={17} />} />
              <Diagnostic label="Network Origin" value="192.168.1.142" icon={<ShieldCheck size={17} />} />
              <Diagnostic label="Active Device Count" value="1" icon={<Smartphone size={17} />} />
              <Diagnostic label="Session Count" value="1" icon={<UsersRound size={17} />} />
            </div>
          </FormSection>

          {submitError && (
            <div role="alert" className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-sm font-medium text-destructive">
              <CircleAlert size={16} className="shrink-0" aria-hidden="true" />
              {submitError}
            </div>
          )}

          <div className="flex flex-col-reverse items-stretch justify-between gap-4 border-t border-border pt-6 sm:flex-row sm:items-center">
            <p className="flex items-center gap-2 text-xs text-muted-foreground">
              <LockKeyhole size={14} aria-hidden="true" /> Your submission is encrypted and securely processed.
            </p>
            <Button type="submit" size="lg" disabled={isSubmitting} className="w-full sm:w-auto">
              {isSubmitting ? <><LoaderCircle size={18} className="animate-spin" /> Submitting application…</> : <><Check size={18} /> Submit Application</>}
            </Button>
          </div>
        </form>
      </div>

      {showSuccess && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-overlay px-4 backdrop-blur-sm" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setShowSuccess(false); }}>
          <section role="dialog" aria-modal="true" aria-labelledby="success-title" className="relative w-full max-w-md rounded-xl border border-border bg-surface p-7 text-center shadow-modal sm:p-8">
            <button type="button" onClick={() => setShowSuccess(false)} className="absolute right-4 top-4 grid size-9 place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" aria-label="Close success message"><X size={18} /></button>
            <div className="mx-auto grid size-14 place-items-center rounded-full bg-success-soft text-success"><CheckCircle2 size={30} strokeWidth={2.2} /></div>
            <h2 id="success-title" className="mt-5 text-xl font-bold text-foreground">Application Submitted</h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">Data successfully submitted to the system.</p>
            <Button type="button" onClick={() => { setShowSuccess(false); setForm(initialForm); }} className="mt-6 w-full">Done</Button>
          </section>
        </div>
      )}
    </main>
  );
}

function FormSection({ number, title, description, icon, children, system = false }: { number: string; title: string; description: string; icon: ReactNode; children: ReactNode; system?: boolean }) {
  return (
    <section className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
      <div className="flex items-start gap-4 border-b border-border bg-section px-5 py-4 sm:items-center sm:px-6">
        <div className={`grid size-10 shrink-0 place-items-center rounded-lg ${system ? "bg-system text-system-foreground" : "bg-primary-soft text-primary"}`}>{icon}</div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2"><span className="text-[10px] font-bold text-muted-foreground">{number}</span><h2 className="text-base font-bold text-foreground sm:text-lg">{title}</h2></div>
          <p className="mt-0.5 text-xs text-muted-foreground sm:text-sm">{description}</p>
        </div>
        {system && <span className="hidden items-center gap-1.5 rounded-full bg-system px-2.5 py-1 text-[10px] font-bold text-system-foreground sm:flex"><ShieldCheck size={12} /> SYSTEM CAPTURED</span>}
      </div>
      <div className="p-5 sm:p-6">{children}</div>
    </section>
  );
}

function Field({ label, htmlFor, required, error, icon, className = "", children }: { label: string; htmlFor: string; required?: boolean; error?: string | undefined; icon?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <div className={className}>
      <label htmlFor={htmlFor} className="mb-2 flex items-center gap-2 text-sm font-semibold text-foreground">{icon && <span className="text-muted-foreground">{icon}</span>}{label}{required && <span className="text-primary" aria-hidden="true">*</span>}</label>
      {children}
      {error && <p className="mt-1.5 flex items-center gap-1.5 text-xs font-medium text-destructive"><CircleAlert size={13} />{error}</p>}
    </div>
  );
}

function SelectField({ id, value, onChange, invalid, children }: { id: string; value: string; onChange: (value: string) => void; invalid: boolean; children: ReactNode }) {
  return <div className="relative"><select id={id} value={value} onChange={(e) => onChange(e.target.value)} aria-invalid={invalid} className="form-control appearance-none pr-10">{children}</select><ChevronDown size={17} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" /></div>;
}

function Diagnostic({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-disabled p-3.5">
      <div className="flex items-center justify-between text-muted-foreground"><span className="text-xs font-semibold">{label}</span><span>{icon}</span></div>
      <div className="mt-2.5 flex items-center justify-between gap-2"><span className="font-mono text-sm font-semibold text-foreground">{value}</span><LockKeyhole size={13} className="shrink-0 text-muted-foreground" /></div>
    </div>
  );
}
