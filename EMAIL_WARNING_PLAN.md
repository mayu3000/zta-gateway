# EMAIL_WARNING_PLAN.md — Email warning when a device's risk goes LOW to MEDIUM

Feature: when a device's risk level rises from LOW to MEDIUM, the gateway emails
the device's owner a warning: the activity looks unusual, here is the main
reason, and if it reaches HIGH the device will be blocked. When a device is
actually banned, the owner gets a short ban notice. The email is the only
channel; a gateway cannot push a notification onto a phone, and a banned device
cannot receive anything over the network.

Branch: `feature/email-warning`, created from `feature/portal-gate`.
`main` and `v1.0-final` stay untouched.

Legend: `[ ]` todo, `[x]` done and tested. Do not tick an item until its
acceptance test passes.

## Decisions (made before starting)

1. **Delivery:** real email via SMTP (details in `.env`); lab-mode console
   fallback kept for tests and when `MAIL_SERVER` is unset.
2. **Cooldown:** 10 minutes (`ZTA_NOTIFY_COOLDOWN_MINUTES=10`).
3. **Sensitivity:** warn on the first MEDIUM window (`ZTA_NOTIFY_MIN_WINDOWS=1`);
   set to `2` to require two consecutive windows.
4. **Admin copy:** yes — `ZTA_NOTIFY_ADMIN_COPY` copies the admin on every
   notice.

## Where this fits in the current code

| Piece | Today | Used for |
|---|---|---|
| `run.py` `run_scoring_window()` | Already compares `prev_level` and `level` | The trigger point |
| `app/policy/scoring.py` `risk_level()` | LOW below 35, MEDIUM 35-69, HIGH 70+ | Level boundaries; HIGH is the ban line |
| `app/mail.py` | `send_verification_email()`, optional Flask-Mail, console fallback | The sender, same fallback |
| `app/models.py` `Device` | Has `status`, `ip`, `mac` | Needs an owner email |
| `app/routes.py` | Dashboard, login, unban | Admin page to set a contact email |

Rules: 1) scoring never fails/slows because of email; 2) no secrets in code or
git — SMTP in `.env`; 3) never put passwords/tokens/full DNS history in an
email; 4) the existing 95 tests keep passing at every step.

---

## Item 1 — Who gets the email `[x]`
Two sources, in order: (1) the signed-in user of that device (`user_id`, from the
portal gate); (2) an admin-set `notify_email` on the device.
**Done:** `Device.notify_email` (and `medium_streak`); `/admin/device/<mac>/contact`
(POST, PRG, admin-only, format-validated, forensic-logged); Contact cell on the
dashboard; `resolve_recipient()`. **Accept met:** tests cover set / 403 /
invalid rejected / clear (see `ContactRouteTests`).

## Item 2 — Settings `[x]`
`ZTA_NOTIFY=1`, `ZTA_NOTIFY_COOLDOWN_MINUTES=10`, `ZTA_NOTIFY_MIN_WINDOWS=1`,
`ZTA_NOTIFY_BAN_NOTICE=1`, `ZTA_NOTIFY_ADMIN_COPY=""`. **Accept met:** with
`ZTA_NOTIFY=0` no notification code runs and all suites pass.

## Item 3 — Notification log table `[x]`
`Notification(id, mac, recipient, kind medium_warning|ban_notice, score, reason,
status sent|failed|skipped, error, created_at)`. Idempotent migration
`add_notifications.py` (`CREATE TABLE IF NOT EXISTS`, PRAGMA-guarded ALTERs).
**Accept met:** migration runs twice cleanly; `create_all()` builds the schema.

## Item 4 — Notifier module `app/notify.py` `[x]`
`notify_medium` / `notify_ban`; recipient lookup with a `skipped` row when none;
cooldown from the audit table; one-sentence reason from the strongest signal
(never raw domains); background daemon thread inside `app.app_context()`; row
written as `sent`/`failed` with the error; all wrapped in try/except with a
`NOTIFY_FAILED` forensic entry.

## Item 5 — Email sender and wording `[x]`
`app/mail.py`: `send_risk_email(app, to, subject, body_text, body_html)` reusing
the lab-mode fallback (console + `EMAIL_NOTICE` forensic entry); hard-coded
sender/user/password were coincidentally also removed as a security improvement.
`get_last_notification()` added. Plain professional wording, no emoji, plain-text
part always present.

## Item 6 — Hook into scoring `[x]`
`run.py` `run_scoring_window`: `medium_streak` tracked; warning fired on rising
into MEDIUM (never HIGH, and not for a device first seen already at MEDIUM/HIGH);
ban notice on the Ban row. Called after the scoring commit so the send never
races the window's writes. The 95 existing tests pass; the send is in the
background.

## Item 7 — Automated tests `tests/test_notify.py` `[x]`
20 tests, all pass: LOW→MEDIUM (one warning, one `sent` row); second inside
cooldown suppressed; MEDIUM→HIGH and LOW→HIGH (ban notice only, no medium);
no recipient → `skipped`; sender raises → `failed` row and scoring unchanged;
`ZTA_NOTIFY=0` → nothing; `ZTA_NOTIFY_MIN_WINDOWS=2` → two windows.

## Item 8 — Dashboard and admin view `[x]`
"Warned" badge, "Recent notifications" table (time, device, recipient, kind,
score, status), 10-second refresh retained. Jinja auto-escaping covers every
data value.

## Item 9 — Live test on the gateway `[ ]`
Needs the Pi/Kali gateway, a spare device and a real contact email. Scenarios:
moderate sweep → one warning; repeat inside 10 min → none; push to HIGH → ban
notice; no contact → `skipped`; wrong SMTP password → `failed` + console
fallback; admin unban → normal, no email.

## Item 10 — Documentation `[x]`
Section 15 added to `docs/BLACKBOOK.md`: triggers, levels, cooldown, wording,
the audit table, test results, and the honest limits.

---

## Notes / bug fixed along the way
- **Infinite recursion in `app/routes.py`:** the Flask view `revoke_access`
  shadowed the imported portal `revoke_access`, so `/admin/unban/<mac>` (and the
  revoke view itself) recursed forever. The integration test crashed with a
  Windows C-stack overflow as a result. Fixed by importing the portal function
  as `portal_revoke_access`. `tests/test_integration.py` now passes 35/35.
