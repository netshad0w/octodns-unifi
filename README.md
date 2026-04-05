## UniFi Network provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [UniFi Network](https://ui.com/) controllers for local DNS management.

### Installation

#### Command line

```
pip install octodns-unifi
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==1.16.0
octodns-unifi==1.0.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/netshad0w/octodns-unifi.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_unifi
```

### Configuration

Requires UniFi Network 10.1+ with the integration API (v1) and an API key.

```yaml
providers:
  unifi:
    class: octodns_unifi.UnifiProvider
    # Controller hostname or IP (for local access)
    host: unifi.example.com
    # API key generated from UniFi controller settings
    api_key: env/UNIFI_API_KEY
    # Site name (optional, defaults to 'default')
    site: default
    # Disable SSL verification for self-signed certs (optional, defaults to true)
    verify_ssl: true
    # For cloud access via api.ui.com, provide your console ID (optional)
    # console_id: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX:123456"
    # Default TTL in seconds (optional, defaults to 300)
    default_ttl: 300
```

#### Cloud access

To manage DNS via the Ubiquiti cloud API instead of connecting directly to the controller, set `console_id` to your console's ID (found in the URL at unifi.ui.com):

```yaml
providers:
  unifi:
    class: octodns_unifi.UnifiProvider
    host: unused
    api_key: env/UNIFI_API_KEY
    console_id: env/UNIFI_CONSOLE_ID
```

### Support Information

#### Records

The following record types are supported:

| Record | Support |
|--------|---------|
| A      | Yes     |
| AAAA   | Yes     |
| CNAME  | Yes     |
| MX     | Yes     |
| TXT    | Yes     |
| SRV    | Yes     |

#### Dynamic

UnifiProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
