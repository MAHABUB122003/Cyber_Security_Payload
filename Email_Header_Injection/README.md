# Email Header Injection (& SMTP tricks)

If an app builds email headers from user input (contact/subscribe/forgot-password forms), you can inject new headers → **spam, phishing, credential leak, or header bcc attackers**.

## When to test
- "Contact us", "newsletter subscribe", "forgot password", "invite teammate" forms
- Any `email`, `subject`, `reply-to`, `name` field passed to `mail()` / smtp libs

## Priority payloads
- CRLF injection → add `Bcc:`, `Cc:`, custom headers
- Overwrite `To:`/`From:`/`Subject:` via `\r\n`
- If the app embeds values in a JSON/SMTP API (sendgrid style) header injection may not apply — instead test *markdown/HTML* injection

## Files
- `email-injection-payloads.txt`

## Why
Email header injection = full-strength email control from a web bug (session-initiated spam / phishing from your domain). Often rated medium–high.