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
    pass
