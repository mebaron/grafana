---
description: Grafana CAS (4A) Authentication
labels:
  products:
    - oss
menuTitle: CAS (4A)
title: Configure CAS authentication
weight: 1650
---

# Configure CAS authentication

You can configure Grafana to authenticate users through an external CAS provider, such as a corporate 4A unified authentication platform. When CAS authentication is enabled, unauthenticated users are redirected to the provider's login page. After a successful login, the provider redirects back to Grafana with a ticket that Grafana validates server-side.

If the CAS provider is unreachable (timeouts, network errors, or HTTP 5xx responses), Grafana automatically falls back to its native login form so that local accounts can still sign in. No manual intervention is required, and Grafana returns to CAS redirection once the provider recovers.

## Before you begin, ensure you have the following:

- The `app_id` assigned to Grafana by your CAS provider.
- The base URL of the CAS provider, for example `https://4a.example.com.cn`.
- The callback address (`<grafana-root-url>/login/cas`) registered with the provider. The `server.root_url` setting must match the registered callback exactly, including any sub-path. The provider matches the callback (`service`) value exactly, so differences in scheme, host, port, or trailing slash cause ticket validation to fail.

## Enable CAS authentication

Enable CAS in the [configuration file](../../../configure-grafana/):

```ini
[auth.cas]
enabled = true
app_id = <APP_ID>
server_url = <CAS_BASE_URL>
```

`<APP_ID>` is the application ID assigned by your provider. `<CAS_BASE_URL>` is the provider base URL without a trailing slash, for example `https://4a.example.com.cn`.

## How the login flow works

Grafana uses the following provider endpoints:

- `GET <CAS_BASE_URL>/4a/credentials/cas?appid=<APP_ID>&service=<CALLBACK_URL>`: Grafana redirects unauthenticated users here. After a successful login, the provider redirects the browser back to `<CALLBACK_URL>` with a `ticket` parameter.
- `GET <CAS_BASE_URL>/4a/cas/serviceValidate?appid=<APP_ID>&ticket=<TICKET>`: Grafana validates the ticket server-side and reads the user information (`user`, `cn`, `email` attributes) from the XML response.
- `GET <CAS_BASE_URL>/4a/cas/logout?appid=<APP_ID>&url=<LOGIN_URL>`: When a user signs out of Grafana, the browser is redirected here so the provider session ends as well. This is only triggered by an explicit user sign-out.

The callback URL is `<server.root_url>/login/cas` and must stay static, because the provider matches it exactly.

## Automatic login and fallback

When CAS is enabled and the provider is reachable, Grafana automatically redirects unauthenticated users to the provider login page, skipping the native login screen. This works like other providers' `auto_login` and is skipped if another provider also requests automatic login.

Before each automatic redirect, Grafana probes the provider endpoint. If the probe fails with a timeout, a network error, or an HTTP 5xx response, Grafana doesn't redirect and instead renders the native login form, where any local account can sign in. The probe result is cached for 30 seconds. Users can also always reach the native login screen with `?disableAutoLogin=true`, and the CAS flow remains available at `/login/cas`.

{{< admonition type="note" >}}
While the provider is down, any local Grafana account can sign in through the native login form. This bypasses the centralized authentication audit for the duration of the outage. If your deployment can't accept this, set `disable_login_form = true` in the `[auth]` section — but this also removes the fallback login.
{{< /admonition >}}

## User provisioning

The first time a user signs in through CAS, Grafana creates a user account linked to the CAS identity, unless a user with the same login already exists locally. Set `allow_sign_up = false` to restrict sign-in to users that were linked beforehand.

Organization roles aren't synced from the provider. New users get the role configured in `[users] auto_assign_org_role`.

## Configuration options

```ini
[auth.cas]
enabled = false
app_id =
server_url =
allow_sign_up = true
signout_redirect_url =
timeout = 10s
healthcheck_timeout = 3s
tls_client_ca =
tls_skip_verify_insecure = false
```

- `app_id`: Application ID assigned by the CAS provider.
- `server_url`: Base URL of the CAS provider, without a trailing slash.
- `allow_sign_up`: Automatically create Grafana users on first sign-in. Defaults to `true`.
- `signout_redirect_url`: Overrides the default provider logout URL used on sign-out.
- `timeout`: Timeout for the ticket validation request. Defaults to `10s`.
- `healthcheck_timeout`: Timeout for the provider reachability probe that controls automatic login fallback. Defaults to `3s`.
- `tls_client_ca`: Path to a CA certificate file used to verify the provider when it's served over TLS with a private CA.
- `tls_skip_verify_insecure`: Skip TLS certificate verification of the provider. Insecure, use only in controlled environments.

## Troubleshoot

- **Redirected back to the login page with an error after provider login**: The ticket validation failed. A ticket is single-use and expires quickly; check the Grafana server log for the provider response, and verify that `server.root_url` matches the registered callback exactly.
- **Users stuck on the native login form even though the provider is up**: The reachability probe may be failing (for example, a firewall blocks the Grafana server from reaching the provider, or the probe times out). Check connectivity from the Grafana host, and consider raising `healthcheck_timeout`. The probe result is cached for 30 seconds, so allow for that delay after the provider recovers.
- **Sign-in fails for a user whose login matches an existing local account**: CAS identities never adopt an existing local account. Rename the local account or disable it, then sign in again with the CAS user.
