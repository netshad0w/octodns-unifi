# UniFi Network provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider for managing
local DNS on [UniFi Network](https://ui.com/) controllers.

## Installation

### Command line

```bash
pip install octodns-unifi
```

### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

#### Versions

```txt
# Start with the latest versions and don't just copy what's here
octodns==1.16.0
octodns-unifi==1.1.3
```

#### SHAs

```txt
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/netshad0w/octodns-unifi.git@9da63f00309d76bfa94001c0cfdc0c594a647b97#egg=octodns_unifi
```

## Configuration

Requires UniFi Network 10.1+, the integration API (v1), and an API key.

```yaml
providers:
  unifi:
    class: octodns_unifi.UnifiProvider
    # Controller hostname or IP (local access)
    host: unifi.example.com
    # API key from UniFi controller settings
    api_key: env/UNIFI_API_KEY
    # Site name (defaults to 'default')
    site: default
    # SSL verification (defaults to true)
    # Set to false for self-signed certificates
    verify_ssl: true
    # Console ID for cloud access via api.ui.com (see below)
    # console_id: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX:123456"
    # TTL in seconds (defaults to 300)
    default_ttl: 300
    # Explicit zone list, useful for multi-label TLDs (co.uk, com.au)
    # When omitted, zones are guessed from the last two labels of each
    # record (e.g. host.example.com -> example.com)
    # zones:
    #   - example.com.
    #   - internal.example.
```

### Cloud access

You can manage DNS through the Ubiquiti cloud API instead of
connecting directly to the controller. Set `console_id` to your
console's ID, which you can grab from the URL at
[unifi.ui.com](https://unifi.ui.com)
(`https://unifi.ui.com/consoles/<console_id>/...`).

`host` is still required but gets ignored when `console_id` is set.

```yaml
providers:
  unifi:
    class: octodns_unifi.UnifiProvider
    host: unused
    api_key: env/UNIFI_API_KEY
    site: default
    console_id: env/UNIFI_CONSOLE_ID
```

## Support Information

### Records

| Record | Support |
|--------|---------|
| A      | ✅      |
| AAAA   | ✅      |
| ALIAS  | ❌      |
| CAA    | ❌      |
| CNAME  | ✅      |
| DNAME  | ❌      |
| DS     | ❌      |
| HTTPS  | ❌      |
| LOC    | ❌      |
| MX     | ✅      |
| NAPTR  | ❌      |
| NS     | ❌      |
| PTR    | ❌      |
| SPF    | ❌      |
| SRV    | ✅      |
| SSHFP  | ❌      |
| SVCB   | ❌      |
| TLSA   | ❌      |
| TXT    | ✅      |
| URI    | ❌      |
| URLFWD | ❌      |

### Limitations

Custom TTL values only work for A, AAAA, and CNAME records.
For MX, TXT, and SRV, the controller manages the TTL and any
octodns value is ignored.

Zone auto-detection infers zones from the last two labels of each
domain (e.g. `example.com`). If you use multi-label TLDs like
`co.uk` or `com.au`, set `zones` explicitly in the provider config.

### Dynamic

UnifiProvider does not support dynamic records.

## Development

See the [/script/](/script/) directory for some tools to help with
the development process. They generally follow the
[Script to rule them all](https://github.com/github/scripts-to-rule-them-all)
pattern. Most useful is `./script/bootstrap` which will create a
venv and install both the runtime and development related
requirements. It will also hook up a pre-commit hook that covers
most of what's run by CI.
