# Public registration and login

Visitors choose Create an account (/sign-up), complete Clerk registration and verification, and enter the dashboard. Returning users use /sign-in. Organization invitations are not required for a personal workspace.

The backend derives personal workspace ownership from the verified JWT subject as personal:<user_id>. New accounts are members, not administrators. They can upload captures, investigate their own sessions, track remediation and download their own reports. Agent provisioning, deletion and lab administration remain restricted. A personal account cannot access existing pilot data. An active shared organization must still match the configured pilot organization.

## Clerk configuration required

In the Clerk Dashboard select the intended application, open Access mode, select Open and save. Configure the desired sign-in methods and verification requirements. Remove any unintended allowlist restrictions. Set the deployed frontend/backend to the same Clerk application and exact HTTPS origin. No provider settings were changed from this workspace.

SECURE_SMTP_PUBLIC_REGISTRATION defaults to true. Set it to false to restore invitation-only application access. SECURE_SMTP_PILOT_ORG_ID is optional for public personal access and required for shared pilot organization access. Existing ownership records are unchanged. Offline Keycloak continues to use administrator-provisioned accounts.

Production acceptance: register two new accounts, verify their credentials, upload different captures and confirm neither account can fetch the other's sessions, jobs or reports. Confirm personal users cannot invoke administrator routes; verify logout, login and password recovery. Test actual Clerk registration and verification in a browser before rollout. Public access also needs ingress rate limits and capacity monitoring.

This document supersedes older invitation-only login descriptions for public Clerk mode. See https://clerk.com/docs/guides/secure/restricting-access for provider access modes.
