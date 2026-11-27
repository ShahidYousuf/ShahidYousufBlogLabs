# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through [GitHub's private vulnerability reporting](https://github.com/ShahidYousuf/ShahidYousufBlogLabs/security/advisories/new) instead. Include the lab folder, what you found and how to reproduce it. I aim to reply within a week.

## Scope

These labs are teaching code. They run locally in Docker with throwaway data and dev-only credentials, so a hardcoded dev token or an unsealed dev server inside a lab is expected and not a vulnerability.

In scope: anything in a lab that would be unsafe if a reader copied the pattern into real code, and vulnerable dependency versions.

Only the latest commit on `main` is supported.
