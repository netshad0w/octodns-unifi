from collections import defaultdict
from logging import getLogger
from re import compile as re_compile

import urllib3
from requests import Session
from requests.exceptions import RequestException

from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = '1.1.4'

# Reject hosts with characters that could break out of the
# https://{host}/proxy/network URL (path, query, fragment, credentials,
# percent-encoding)
_HOST_FORBIDDEN_RE = re_compile(r'[\x00\s/\\?#@%]')
# console_id, site id and record id go into URL paths; require a leading
# alphanumeric so values like '..' or ':' can't traverse or alter the path.
# \A/\Z (not ^/$) so a trailing newline can't slip past the anchor. Length is
# bounded so a hostile or buggy id can't produce an oversized URL.
_SAFE_ID_RE = re_compile(r'\A[A-Za-z0-9][A-Za-z0-9._:-]{0,254}\Z')


class UnifiClientException(Exception):
    pass


class UnifiClientNotFound(UnifiClientException):
    pass


class UnifiClientUnauthorized(UnifiClientException):
    pass


class UnifiClient:
    def __init__(
        self, host, api_key, site='default', verify_ssl=True, console_id=None
    ):
        self.log = getLogger('UnifiClient')

        sess = Session()
        sess.headers.update(
            {'X-API-KEY': api_key, 'Accept': 'application/json'}
        )
        sess.verify = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.log.warning(
                '__init__: SSL certificate verification is disabled'
            )
        self._sess = sess

        if console_id:
            if not _SAFE_ID_RE.match(str(console_id)):
                raise UnifiClientException(
                    f'Invalid console_id: {console_id!r}'
                )
            self._base = (
                f'https://api.ui.com/v1/connector/consoles'
                f'/{console_id}/proxy/network'
            )
        else:
            if not host or _HOST_FORBIDDEN_RE.search(host):
                raise UnifiClientException(f'Invalid host: {host!r}')
            self._base = f'https://{host}/proxy/network'

        self._site_name = site
        self._site_id = None
        self._dns_path = None

    def _resolve_site(self):
        if self._site_id:
            return

        resp = self._request('GET', '/integration/v1/sites')
        for s in resp or []:
            site_id = s.get('id')
            if site_id and s.get('name', '').lower() == self._site_name.lower():
                self._site_id = site_id
                break

        if not self._site_id:
            raise UnifiClientException(
                f'Site {self._site_name!r} not found on controller'
            )
        if not _SAFE_ID_RE.match(str(self._site_id)):
            raise UnifiClientException(f'Invalid site id: {self._site_id!r}')

        self._dns_path = f'/integration/v1/sites/{self._site_id}/dns/policies'
        self.log.debug(
            '_resolve_site: name=%s, id=%s', self._site_name, self._site_id
        )

    def _request(self, method, path, data=None):
        url = f'{self._base}{path}'
        self.log.debug('_request: method=%s, url=%s', method, url)

        try:
            resp = self._sess.request(method, url, json=data, timeout=30)
        except RequestException as e:
            raise UnifiClientException(
                f'Request failed: {method} {url}: {type(e).__name__}'
            ) from e

        if resp.status_code == 401:
            raise UnifiClientUnauthorized('Invalid API key')
        if resp.status_code == 404:
            raise UnifiClientNotFound(f'Not found: {path}')
        resp.raise_for_status()

        if resp.status_code == 204 or not resp.text:
            return None

        try:
            body = resp.json()
        except ValueError as e:
            raise UnifiClientException(
                f'Invalid JSON response: {type(e).__name__}'
            ) from e
        if isinstance(body, dict):
            return body.get('data', body)
        return body

    def records(self):
        self._resolve_site()
        return self._request('GET', self._dns_path)

    def record_create(self, data):
        self._resolve_site()
        return self._request('POST', self._dns_path, data)

    def record_delete(self, record_id):
        if not _SAFE_ID_RE.match(str(record_id)):
            raise UnifiClientException(f'Invalid record id: {record_id!r}')
        self._resolve_site()
        return self._request('DELETE', f'{self._dns_path}/{record_id}')


_UNIFI_TYPE_MAP = {
    'A_RECORD': 'A',
    'AAAA_RECORD': 'AAAA',
    'CNAME_RECORD': 'CNAME',
    'MX_RECORD': 'MX',
    'TXT_RECORD': 'TXT',
    'SRV_RECORD': 'SRV',
}


class UnifiProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV'}

    def __init__(
        self,
        id,
        host,
        api_key,
        site='default',
        verify_ssl=True,
        console_id=None,
        default_ttl=300,
        zones=None,
        *args,
        **kwargs,
    ):
        self.log = getLogger(f'UnifiProvider[{id}]')
        self.log.debug('__init__: id=%s, host=%s, site=%s', id, host, site)
        super().__init__(id, *args, **kwargs)
        self._client = UnifiClient(
            host=host,
            api_key=api_key,
            site=site,
            verify_ssl=verify_ssl,
            console_id=console_id,
        )
        self._default_ttl = default_ttl
        self._zones = zones
        self._all_records = None
        self._zone_records = {}

    def list_zones(self):
        self.log.debug('list_zones:')
        if self._zones is not None:
            return sorted(
                {z if z.endswith('.') else f'{z}.' for z in self._zones}
            )
        self._all_records = self._client.records() or []
        zones = set()
        for record in self._all_records:
            domain = record.get('domain', '')
            domain = domain.removeprefix('*.')
            parts = domain.split('.')
            # Extract the zone as the last two labels; does not support
            # country-code SLDs like co.uk — use explicit zones config
            # for those.
            if len(parts) >= 2:
                zones.add(f'{".".join(parts[-2:])}.')
        return sorted(zones)

    def _zone_name_sans_dot(self, zone):
        return zone.name.removesuffix('.')

    def _record_name(self, domain, zone_name):
        if domain == zone_name:
            return ''
        suffix = f'.{zone_name}'
        if domain.endswith(suffix):
            return domain[: -len(suffix)]
        return None

    def _record_type(self, unifi_type):
        return _UNIFI_TYPE_MAP.get(unifi_type)

    def _ttl(self, records):
        ttls = {r.get('ttlSeconds', 0) for r in records}
        ttls.discard(0)
        if len(ttls) > 1:
            self.log.warning('_ttl: inconsistent TTLs %s, using max', ttls)
        return max(ttls) if ttls else self._default_ttl

    def _data_for_A(self, _type, records):
        return {
            'type': _type,
            'ttl': self._ttl(records),
            'values': [r['ipv4Address'] for r in records],
        }

    def _data_for_AAAA(self, _type, records):
        return {
            'type': _type,
            'ttl': self._ttl(records),
            'values': [r['ipv6Address'] for r in records],
        }

    def _data_for_CNAME(self, _type, records):
        if not records:
            raise ValueError('_data_for_CNAME: no records to map')
        value = records[0]['targetDomain']
        if not value.endswith('.'):
            value = f'{value}.'
        return {'type': _type, 'ttl': self._ttl(records), 'value': value}

    def _data_for_MX(self, _type, records):
        values = []
        for r in records:
            exchange = r['mailServerDomain']
            if not exchange.endswith('.'):
                exchange = f'{exchange}.'
            values.append(
                {'preference': r.get('priority', 10), 'exchange': exchange}
            )
        return {'type': _type, 'ttl': self._ttl(records), 'values': values}

    def _data_for_TXT(self, _type, records):
        return {
            'type': _type,
            'ttl': self._ttl(records),
            'values': [r['text'] for r in records],
        }

    def _data_for_SRV(self, _type, records):
        values = []
        for r in records:
            target = r['serverDomain']
            if not target.endswith('.'):
                target = f'{target}.'
            values.append(
                {
                    'priority': r.get('priority', 0),
                    'weight': r.get('weight', 0),
                    'port': r.get('port', 0),
                    'target': target,
                }
            )
        return {'type': _type, 'ttl': self._ttl(records), 'values': values}

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        zone_name = self._zone_name_sans_dot(zone)
        # Reuse records fetched by list_zones() for all populate() calls
        # in the same sync run; fetch fresh data only when no cache exists
        if self._all_records is not None:
            raw_records = self._all_records
        else:
            raw_records = self._client.records() or []

        grouped = defaultdict(lambda: defaultdict(list))
        # Cache only this zone's records so _apply_Delete can't match (and
        # delete) a record owned by another managed zone
        owned_records = []
        for r in raw_records:
            octodns_type = self._record_type(r.get('type', ''))
            if octodns_type is None or octodns_type not in self.SUPPORTS:
                continue

            domain = r.get('domain', '')
            # SRV records store service/protocol separately in the API
            if octodns_type == 'SRV':
                service = r.get('service', '')
                protocol = r.get('protocol', '')
                if service and protocol:
                    domain = f'{service}.{protocol}.{domain}'

            # Skip empty or sub-zone-owned records
            if not domain or not zone.owns(octodns_type, domain):
                continue

            owned_records.append(r)
            name = self._record_name(domain, zone_name)
            grouped[name][octodns_type].append(r)

        self._zone_records[zone.name] = owned_records

        before = len(zone.records)
        for name, types in grouped.items():
            for _type, records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                data = data_for(_type, records)
                record = Record.new(
                    zone, name, data, source=self, lenient=lenient
                )
                zone.add_record(record, lenient=lenient)

        exists = len(zone.records) - before > 0
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    _TTL_SUPPORTED_TYPES = {'A_RECORD', 'AAAA_RECORD', 'CNAME_RECORD'}

    def _params_for_base(self, record, unifi_type):
        zone_name = self._zone_name_sans_dot(record.zone)
        if record.name:
            domain = f'{record.name}.{zone_name}'
        else:
            domain = zone_name
        params = {'type': unifi_type, 'enabled': True, 'domain': domain}
        if unifi_type in self._TTL_SUPPORTED_TYPES:
            params['ttlSeconds'] = record.ttl
        return params

    def _params_for_A(self, record):
        for value in record.values:
            params = self._params_for_base(record, 'A_RECORD')
            params['ipv4Address'] = value
            yield params

    def _params_for_AAAA(self, record):
        for value in record.values:
            params = self._params_for_base(record, 'AAAA_RECORD')
            params['ipv6Address'] = value
            yield params

    def _params_for_CNAME(self, record):
        params = self._params_for_base(record, 'CNAME_RECORD')
        params['targetDomain'] = record.value.removesuffix('.')
        yield params

    def _params_for_MX(self, record):
        for value in record.values:
            params = self._params_for_base(record, 'MX_RECORD')
            params['mailServerDomain'] = value.exchange.removesuffix('.')
            params['priority'] = value.preference
            yield params

    def _params_for_TXT(self, record):
        for value in record.values:
            params = self._params_for_base(record, 'TXT_RECORD')
            params['text'] = value
            yield params

    def _params_for_SRV(self, record):
        zone_name = self._zone_name_sans_dot(record.zone)
        # SRV names are _service._protocol.name — extract each part
        parts = record.name.split('.', 2)
        if len(parts) < 2:
            raise ValueError(
                f'SRV record name {record.name!r} is not _service._protocol'
            )
        service = parts[0]
        protocol = parts[1]
        host = parts[2] if len(parts) > 2 else ''
        if host:
            domain = f'{host}.{zone_name}'
        else:
            domain = zone_name
        for value in record.values:
            params = {
                'type': 'SRV_RECORD',
                'enabled': True,
                'domain': domain,
                'service': service,
                'protocol': protocol,
                'serverDomain': value.target.removesuffix('.'),
                'priority': value.priority,
                'weight': value.weight,
                'port': value.port,
            }
            yield params

    def _params_for(self, record):
        handler = getattr(self, f'_params_for_{record._type}')
        return handler(record)

    def _record_matches(self, api_record, octodns_record):
        zone_name = self._zone_name_sans_dot(octodns_record.zone)
        octodns_type = self._record_type(api_record.get('type', ''))
        if octodns_type != octodns_record._type:
            return False
        domain = api_record.get('domain', '')
        if octodns_type == 'SRV':
            service = api_record.get('service', '')
            protocol = api_record.get('protocol', '')
            if service and protocol:
                domain = f'{service}.{protocol}.{domain}'
        name = self._record_name(domain, zone_name)
        if name is None:
            return False
        return name == octodns_record.name

    def _apply_Create(self, change):
        new = change.new
        for params in self._params_for(new):
            self._client.record_create(params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        if existing.zone.name not in self._zone_records:
            raise UnifiClientException(
                f'_apply_Delete: no cached records for zone '
                f'{existing.zone.name}, populate() must be called first'
            )
        for record in self._zone_records[existing.zone.name]:
            if self._record_matches(record, existing):
                record_id = record.get('id')
                if record_id is None:
                    self.log.warning(
                        '_apply_Delete: record missing id, skipping'
                    )
                    continue
                self._client.record_delete(record_id)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.info(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )
        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)
        self._zone_records.pop(desired.name, None)
