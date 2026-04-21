# Third-party acknowledgments

lumen-argus is MIT-licensed. It depends on and incorporates material from the
following open-source projects, all under permissive licenses compatible with
both the community tier and commercial distributions.

## Runtime dependencies

| Project | License | Role | License file |
|---|---|---|---|
| [aiohttp](https://github.com/aio-libs/aiohttp) | Apache 2.0 | HTTP proxy + dashboard server | upstream package metadata |
| [pyyaml](https://github.com/yaml/pyyaml) | MIT | Config loading | upstream package metadata |
| [pyahocorasick](https://github.com/WojciechMula/pyahocorasick) | BSD-3-Clause | Multi-pattern rule pre-filter | upstream package metadata |
| [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) | Apache 2.0 | NANPA + E.164 phone validation | `third_party/LICENSES/phonenumbers-APACHE-2.0.txt` |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) (agent only) | MIT | Forward-proxy TLS interception | upstream package metadata |

## Adapted rule content

### Gitleaks — MIT

Several secrets-detection rules in `packages/proxy/lumen_argus/rules/community.json`
are adapted verbatim from the [Gitleaks](https://github.com/gitleaks/gitleaks)
default config. All adapted entries carry the `gitleaks` tag for traceability.
Where the original pattern relied on Go-specific regex features (inline flag
placement), it was rewritten to equivalent behavior in Python `re` — the
matching shape is unchanged.

- Upstream: https://github.com/gitleaks/gitleaks
- Upstream commit referenced: `8863af47d64c3681422523e36837957c74d4af4b` (master as of 2026-04-21)
- License text: `third_party/LICENSES/gitleaks-MIT.txt`
- Rules tagged `gitleaks`: `digitalocean_access_token`, `digitalocean_pat`,
  `digitalocean_refresh_token`, `cloudflare_api_key`, `cloudflare_global_api_key`,
  `cloudflare_origin_ca_key`, `linear_api_key`, `linear_client_secret`,
  `notion_api_token`, `atlassian_api_token`, `kubernetes_secret_yaml`,
  `shopify_access_token`, `shopify_private_app_token`, `hubspot_api_key`,
  `telegram_bot_token`
