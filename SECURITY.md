# Security Policy

## Supported versions

Nuncio is pre-1.0 and moves fast. Security fixes are made against the latest
release and the `main` branch. Please upgrade to the newest release before
reporting an issue.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. This opens a private advisory visible
only to the maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal payload or configuration is ideal), and
- affected version(s).

You can expect an initial acknowledgement within a few days. Once a fix is
available, a patched release is published and the advisory is disclosed.

## Scope notes

Nuncio is designed to fail safe and to keep alert content private:

- Every outbound LLM and delivery payload is scrubbed of credentials, tokens,
  and keys before it leaves the process.
- The dashboard and settings screen have no built-in authentication for reads;
  the settings write path is admin-token gated. Both are intended to sit behind
  a reverse proxy or IP allowlist. Exposing them directly to an untrusted
  network is a deployment mistake, not a Nuncio vulnerability — but a way to
  bypass the redactor or the admin-token write gate is in scope.
- The repeat cooldown (`NUNCIO_COOLDOWN_S`) is a *suppression* primitive
  reachable from `/ingest/*`: a caller who can post an identity-bearing payload
  (OpenObserve is the only one today) can advance that identity's clock and
  suppress a genuine page for up to the cooldown window. Ingest auth is optional
  (`NUNCIO_INGEST_TOKEN`) and off by default, so **run with a token if the
  cooldown is enabled and the port is reachable by anything you do not trust**.
