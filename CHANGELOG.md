## 1.1.4 - 2026-05-23

Patch:
* Fix sub-zone record leakage in populate() using native zone.owns()
* Harden GitHub Actions workflows with least-privilege permissions and SHA-pinned actions
* Remove unused _OCTODNS_TYPE_MAP map
* Harden UnifiClient response parsing against non-JSON and non-dict API responses
* Fix Changelog workflow Python version and add CodeQL analysis workflow
* Refresh pinned dev/build requirements (octodns 1.17.0, cryptography 48.0.0, idna 3.16) and cap isort/docutils below their pre-release lines

## 1.1.3 - 2026-04-07

Patch:
* Improve README clarity and add full record type support table

## 1.1.2 - 2026-04-06

Patch:
* Clarify README with API limitations, cloud access details, and updated SHA

## 1.1.1 - 2026-04-06

Patch:
* Fix SRV/MX/TXT API compatibility, sanitize exception messages, and improve zone cache behavior

## 1.1.0 - 2026-04-05

Minor:
* Add list_zones for dynamic zone configuration with optional explicit zone list

## 1.0.0 - 2026-04-05

Major:
* Initial release with support for A, AAAA, CNAME, MX, TXT, and SRV records via UniFi Network v1 integration API.
