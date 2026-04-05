from collections import defaultdict
from logging import getLogger

import urllib3
from requests import Session
from requests.exceptions import RequestException

from octodns.provider.base import BaseProvider
from octodns.record import Record

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'


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
        self._sess = sess

        if console_id:
            self._base = (
                f'https://api.ui.com/v1/connector/consoles'
                f'/{console_id}/proxy/network'
            )
        else:
            self._base = f'https://{host}/proxy/network'

        self._site_name = site
        self._site_id = None
        self._dns_path = None

    def _resolve_site(self):
        if self._site_id:
            return

        resp = self._request('GET', '/integration/v1/sites')
        for s in resp:
            site_id = s.get('id')
            if site_id and s.get('name', '').lower() == self._site_name.lower():
                self._site_id = site_id
                break

        if not self._site_id:
            raise UnifiClientException(
                f'Site {self._site_name!r} not found on controller'
            )

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
                f'Request failed: {method} {url}: {e}'
            ) from e

        if resp.status_code == 401:
            raise UnifiClientUnauthorized('Invalid API key')
        if resp.status_code == 404:
            raise UnifiClientNotFound(f'Not found: {path}')
        resp.raise_for_status()

        if resp.status_code == 204 or not resp.text:
            return None

        body = resp.json()
        return body.get('data', body)

    def records(self):
        self._resolve_site()
        return self._request('GET', self._dns_path)

    def record_create(self, data):
        self._resolve_site()
        return self._request('POST', self._dns_path, data)

    def record_delete(self, record_id):
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

_OCTODNS_TYPE_MAP = {v: k for k, v in _UNIFI_TYPE_MAP.items()}


class UnifiProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV'))

    def __init__(
        self,
        id,
        host,
        api_key,
        site='default',
        verify_ssl=True,
        console_id=None,
        default_ttl=300,
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
        self._zone_records = {}

    def _zone_name_sans_dot(self, zone):
        return zone.name.rstrip('.')

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
        raw_records = self._client.records() or []
        self._zone_records[zone.name] = raw_records

        grouped = defaultdict(lambda: defaultdict(list))
        for r in raw_records:
            octodns_type = self._record_type(r.get('type', ''))
            if octodns_type is None or octodns_type not in self.SUPPORTS:
                continue

            name = self._record_name(r.get('domain', ''), zone_name)
            if name is None:
                continue

            grouped[name][octodns_type].append(r)

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
