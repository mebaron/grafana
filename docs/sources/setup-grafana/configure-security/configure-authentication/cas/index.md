---
aliases:
  - ../../../auth/cas/
description: Grafana CAS (4A) authentication guide
keywords:
  - grafana
  - configuration
  - documentation
  - cas
  - 4a
  - sso
labels:
  products:
    - enterprise
    - oss
menuTitle: CAS (4A)
title: Configure CAS (4A) authentication
weight: 1100
---

# Configure CAS (4A) authentication

This topic describes how to configure CAS authentication against a corporate "4A" unified authentication platform.

CAS authentication is implemented as a standalone login flow: unauthenticated visitors of `/login` are redirected to the 4A login page, and after a successful 4A login the browser is sent back to Grafana with a one-time ticket that Grafana validates server-side before creating a native Grafana session.

## Before you begin

Register Grafana with the 4A platform. The 4A platform matches the `service` parameter **exactly** against the value registered for your `appId`, so the callback address must be registered verbatim:

```
<GRAFANA-BASE-URL>/sso/callback
```

Note down:

- the `appId` assigned to Grafana,
- the full 4A endpoint URLs for login, ticket validation and logout.

The 4A endpoints and their parameters are:

| 4A endpoint | Fixed parameter | Dynamic parameter | Purpose |
| :---------- | :-------------- | :---------------- | :------ |
| `/4a/credentials/cas` | `appId={app_id}` | `service={service}` | Redirect the user to the 4A login page |
| `/4a/cas/serviceValidate` | `appId={app_id}` | `ticket={ticket}` | Server-side ticket validation; returns HTTP 200 with an XML user payload on success, HTTP 401 with a plain-text error on failure |
| `/4a/cas/logout` | `appId={app_id}` | `url={url}` | Log the user out of the 4A platform and send them to `url` |

## Configure CAS authentication

The following settings are supported in the `[auth.cas]` section of the Grafana configuration file. Configuration is read from the configuration file only (including `GF_AUTH_CAS_*` environment variable overrides); it is not available through the Authentication UI.

```ini
[auth.cas]
enabled = true
app_id = <appId assigned by the 4A platform>
login_url = https://4a.example.com/4a/credentials/cas
service_validate_url = https://4a.example.com/4a/cas/serviceValidate
logout_url = https://4a.example.com/4a/cas/logout
service = https://grafana.example.com/sso/callback
url = https://grafana.example.com/login
email_attribute = email
name_attribute = cn
role_attribute = role
allow_sign_up = true
```

### Configuration options

| Setting        | Required | Description                                                                                                                                                                                                                                                                                   |
| :------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`      | Yes      | Enable CAS authentication. When enabled, unauthenticated `GET /login` requests are redirected to `/sso/login`, which starts the 4A login flow.                                                                                                                                                  |
| `app_id`       | Yes      | The `appId` assigned to Grafana by the 4A platform.                                                                                                                                                                                                                                            |
| `login_url`    | Yes      | Full URL of the 4A login endpoint. Grafana appends the `appId` and `service` query parameters.                                                                                                                                                                                                  |
| `service_validate_url` | Yes | Full URL of the 4A ticket validation endpoint. Grafana appends the `appId` and `ticket` query parameters and calls it server-side only.                                                                                                                                                          |
| `logout_url`   | No       | Full URL of the 4A logout endpoint. When set, a user authenticated via CAS is redirected here after a user-initiated Grafana logout (the local Grafana session is revoked first). Grafana appends the `appId` and `url` query parameters.                                                        |
| `service`      | Yes      | The callback URL registered with the 4A platform for your `appId` (``<GRAFANA-BASE-URL>/sso/callback``). The value is sent verbatim and must match the registered value exactly.                                                                                                                 |
| `url`          | No       | The application URL the 4A logout page returns the user to. Falls back to `root_url` + `/login` when empty.                                                                                                                                                                                     |
| `email_attribute` | No   | Name of the XML attribute (local name) inside `<cas:attributes>` that carries the user's email address. Empty disables email mapping.                                                                                                                                                            |
| `name_attribute`  | No   | Name of the XML attribute that carries the user's display name. Empty disables name mapping.                                                                                                                                                                                                    |
| `role_attribute`  | No   | Name of the XML attribute that carries the organization role. Accepted values are `Viewer`, `Editor` and `Admin` (case-insensitive). Any other value, a missing attribute, or an unset `role_attribute` falls back to the Grafana default organization role (see `[users] auto_assign_org_role`). |
| `allow_sign_up`   | No   | Whether to create a Grafana user on first login (default `true`). Existing users are matched by the `user_auth` connection only; CAS accounts never take over a pre-existing local account with the same login or email.                                                                          |
| `timeout`         | No   | Timeout for the `serviceValidate` call (default `10s`).                                                                                                                                                                                                                                         |
| `tls_skip_verify_insecure` | No | Skip TLS certificate verification when calling the 4A endpoints. Insecure, use only in test environments.                                                                                                                                                                            |
| `tls_client_ca`  | No       | Path to a PEM CA bundle used to verify the 4A endpoints' certificates (for private CA environments).                                                                                                                                                                                            |

## Login flow

1. An unauthenticated user opens `GET /login`; Grafana responds with a redirect to `/sso/login`.
1. `/sso/login` stores a signed `cas_state` cookie, remembers the originally requested page (the `redirectTo` parameter) in a validated `redirect_to` cookie, and redirects the browser to the 4A `login_url`.
1. After a successful 4A login the browser is redirected to `service` (`/sso/callback`) with a one-time `ticket` parameter.
1. Grafana validates the ticket **server-side** by calling `service_validate_url`; browser-supplied user information is never trusted.
1. On success Grafana upserts the user (email/name/role are synced from the XML attributes according to the configured attribute names) and creates a native Grafana session (`grafana_session` cookie), then redirects the user back to the originally requested page.

On any failure the user is sent back to `/login` with an error message, and the native login form remains reachable:

- append `?disableAutoLogin` to `/login` to skip the automatic redirect and use the built-in login form (for example for local admin access),
- if multiple providers are configured with auto-login, Grafana skips the automatic redirect and renders the login page instead.

## Logout flow

When a user authenticated via CAS logs out:

1. The local Grafana session is revoked and the session cookies are deleted.
1. Grafana redirects the browser to the 4A `logout_url`, appending `appId` and the `url` to return to (`[auth.cas] url`, or `root_url` + `/login`).

{{< admonition type="note" >}}
The 4A platform forbids calling the logout endpoint before a login has happened; Grafana only calls it on explicit, user-initiated logouts.
{{< /admonition >}}

## Role mapping notes

- `role_attribute` only affects the user's **default organization**; multi-organization mapping is not supported.
- On user creation the mapped role is applied via the same mechanism as the `auto_assign_org_role` setting. If `[users] auto_assign_org_role` handling is disabled (`auto_assign_org = false`), Grafana's stock first-user behavior applies and `role_attribute` has no effect at creation time.
- On subsequent logins a mapped role updates the user's role in their default organization; when no valid role is mapped the role is left unchanged.
