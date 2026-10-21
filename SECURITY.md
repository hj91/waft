# Security policy

Waft carries private messages, clipboard contents and files, so security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.

Include the affected version or commit, the steps to reproduce, and the impact you observed. You will get an acknowledgement within 5 working days and a fix or mitigation plan as soon as the issue is confirmed.

## Scope

In scope: authentication and session handling, account isolation, the end-to-end encryption format (`pkg/e2ee`, `static/app.js`), file transfer, the WebSocket stream, and the default deployment files.

Out of scope: deployments that disable `WAFT_COOKIE_SECURE` or TLS, run with default passwords, or expose PostgreSQL or Redis publicly.

## Supported versions

Only the latest release receives security fixes while the project is in beta.
