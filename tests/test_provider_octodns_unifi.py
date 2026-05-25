from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from requests.exceptions import ConnectionError as RequestsConnectionError

from octodns.record import Record
from octodns.zone import Zone

from octodns_unifi import (
    UnifiClient,
    UnifiClientException,
    UnifiClientNotFound,
    UnifiClientUnauthorized,
    UnifiProvider,
)

SITES_RESPONSE = {
    'data': [
        {'id': 'site-uuid-123', 'name': 'default'},
        {'id': 'site-uuid-456', 'name': 'other'},
    ]
}

RECORDS_RESPONSE = {
    'data': [
        {
            'type': 'A_RECORD',
            'id': 'rec-a-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'www.example.com',
            'ttlSeconds': 300,
            'ipv4Address': '1.2.3.4',
        },
        {
            'type': 'A_RECORD',
            'id': 'rec-a-2',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'www.example.com',
            'ttlSeconds': 300,
            'ipv4Address': '5.6.7.8',
        },
        {
            'type': 'AAAA_RECORD',
            'id': 'rec-aaaa-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'ipv6.example.com',
            'ttlSeconds': 3600,
            'ipv6Address': '2001:db8::1',
        },
        {
            'type': 'CNAME_RECORD',
            'id': 'rec-cname-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'alias.example.com',
            'ttlSeconds': 300,
            'targetDomain': 'www.example.com',
        },
        {
            'type': 'MX_RECORD',
            'id': 'rec-mx-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'example.com',
            'ttlSeconds': 3600,
            'mailServerDomain': 'mail.example.com',
            'priority': 10,
        },
        {
            'type': 'MX_RECORD',
            'id': 'rec-mx-2',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'example.com',
            'ttlSeconds': 3600,
            'mailServerDomain': 'mail2.example.com',
            'priority': 20,
        },
        {
            'type': 'TXT_RECORD',
            'id': 'rec-txt-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'example.com',
            'ttlSeconds': 300,
            'text': 'v=spf1 include:example.com ~all',
        },
        {
            'type': 'SRV_RECORD',
            'id': 'rec-srv-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'example.com',
            'service': '_sip',
            'protocol': '_tcp',
            'serverDomain': 'sip.example.com',
            'priority': 10,
            'weight': 60,
            'port': 5060,
        },
        {
            'type': 'A_RECORD',
            'id': 'rec-other-1',
            'enabled': True,
            'metadata': {'origin': 'USER_DEFINED'},
            'domain': 'host.other.com',
            'ttlSeconds': 300,
            'ipv4Address': '10.0.0.1',
        },
    ]
}


class TestUnifiClient(TestCase):
    @patch('octodns_unifi.Session')
    def test_api_key_auth(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        UnifiClient('unifi.local', 'my-api-key')

        mock_sess.headers.update.assert_called_once_with(
            {'X-API-KEY': 'my-api-key', 'Accept': 'application/json'}
        )
        self.assertTrue(mock_sess.verify)

    @patch('octodns_unifi.Session')
    def test_verify_ssl_false(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        client = UnifiClient('unifi.local', 'key', verify_ssl=False)

        self.assertFalse(client._sess.verify)

    @patch('octodns_unifi.Session')
    def test_local_base_url(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()

        client = UnifiClient('unifi.local', 'key')

        self.assertEqual('https://unifi.local/proxy/network', client._base)

    @patch('octodns_unifi.Session')
    def test_cloud_base_url(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()

        client = UnifiClient('unifi.local', 'key', console_id='UUID-123:456')

        self.assertEqual(
            'https://api.ui.com/v1/connector/consoles'
            '/UUID-123:456/proxy/network',
            client._base,
        )

    @patch('octodns_unifi.Session')
    def test_resolve_site(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SITES_RESPONSE
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key', site='default')
        client._resolve_site()

        self.assertEqual('site-uuid-123', client._site_id)
        self.assertEqual(
            '/integration/v1/sites/site-uuid-123/dns/policies', client._dns_path
        )

    @patch('octodns_unifi.Session')
    def test_resolve_site_not_found(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SITES_RESPONSE
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key', site='nonexistent')

        with self.assertRaises(UnifiClientException):
            client._resolve_site()

    @patch('octodns_unifi.Session')
    def test_resolve_site_null_response(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": null}'
        mock_resp.json.return_value = {'data': None}
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key', site='default')

        with self.assertRaises(UnifiClientException):
            client._resolve_site()

    @patch('octodns_unifi.Session')
    def test_records(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        sites_resp = Mock()
        sites_resp.status_code = 200
        sites_resp.json.return_value = SITES_RESPONSE

        records_resp = Mock()
        records_resp.status_code = 200
        records_resp.json.return_value = RECORDS_RESPONSE

        mock_sess.request.side_effect = [sites_resp, records_resp]

        client = UnifiClient('unifi.local', 'key')
        records = client.records()

        self.assertEqual(len(RECORDS_RESPONSE['data']), len(records))

    @patch('octodns_unifi.Session')
    def test_unauthorized(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 401
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key')

        with self.assertRaises(UnifiClientUnauthorized):
            client._request('GET', '/some/path')

    @patch('octodns_unifi.Session')
    def test_not_found(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key')

        with self.assertRaises(UnifiClientNotFound):
            client._request('GET', '/some/path')

    @patch('octodns_unifi.Session')
    def test_invalid_json(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = 'not json'
        mock_resp.json.side_effect = ValueError('no json')
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key')

        with self.assertRaises(UnifiClientException):
            client._request('GET', '/some/path')

    @patch('octodns_unifi.Session')
    def test_non_dict_json_body(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '[]'
        mock_resp.json.return_value = [{'id': 'x'}]
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key')

        self.assertEqual([{'id': 'x'}], client._request('GET', '/some/path'))

    @patch('octodns_unifi.Session')
    def test_null_data_body(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": null}'
        mock_resp.json.return_value = {'data': None}
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key')

        self.assertIsNone(client._request('GET', '/some/path'))

    @patch('octodns_unifi.Session')
    def test_record_create(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        sites_resp = Mock()
        sites_resp.status_code = 200
        sites_resp.json.return_value = SITES_RESPONSE

        create_resp = Mock()
        create_resp.status_code = 200
        create_resp.json.return_value = {'data': {'id': 'new-id'}}

        mock_sess.request.side_effect = [sites_resp, create_resp]

        client = UnifiClient('unifi.local', 'key')
        result = client.record_create({'type': 'A_RECORD'})

        self.assertEqual({'id': 'new-id'}, result)

    @patch('octodns_unifi.Session')
    def test_record_delete(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        sites_resp = Mock()
        sites_resp.status_code = 200
        sites_resp.json.return_value = SITES_RESPONSE

        delete_resp = Mock()
        delete_resp.status_code = 204

        mock_sess.request.side_effect = [sites_resp, delete_resp]

        client = UnifiClient('unifi.local', 'key')
        result = client.record_delete('rec-123')

        self.assertIsNone(result)

    @patch('octodns_unifi.Session')
    def test_invalid_host(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()

        for bad in (
            'evil.com/proxy',
            'evil.com?x=1',
            'a b',
            'user@host',
            'evil\x00.com',
            'evil.com%2fadmin',
            '',
        ):
            with self.assertRaises(UnifiClientException) as ctx:
                UnifiClient(bad, 'key')
            self.assertIn('Invalid host', str(ctx.exception))

    @patch('octodns_unifi.Session')
    def test_invalid_console_id(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()

        for bad in ('../escape', 'good\n', 'a' + 'b' * 300):
            with self.assertRaises(UnifiClientException) as ctx:
                UnifiClient('unifi.local', 'key', console_id=bad)
            self.assertIn('Invalid console_id', str(ctx.exception))

    @patch('octodns_unifi.Session')
    def test_record_delete_invalid_id(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        client = UnifiClient('unifi.local', 'key')
        with self.assertRaises(UnifiClientException) as ctx:
            client.record_delete('../../other-resource')
        self.assertIn('Invalid record id', str(ctx.exception))
        # fails fast, before any network call
        mock_sess.request.assert_not_called()

    @patch('octodns_unifi.Session')
    def test_resolve_site_invalid_id(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'data': [{'id': '../../../admin', 'name': 'default'}]
        }
        mock_sess.request.return_value = mock_resp

        client = UnifiClient('unifi.local', 'key', site='default')
        with self.assertRaises(UnifiClientException) as ctx:
            client._resolve_site()
        self.assertIn('Invalid site id', str(ctx.exception))


class TestUnifiProvider(TestCase):
    def _get_provider(self):
        provider = UnifiProvider('test', 'unifi.local', 'test-api-key')
        provider._client = MagicMock()
        return provider

    def _get_zone(self):
        return Zone('example.com.', [])

    def test_populate_a_records(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('A', record._type)
        self.assertEqual('www', record.name)
        self.assertEqual(300, record.ttl)
        self.assertEqual(['1.2.3.4', '5.6.7.8'], sorted(record.values))

    def test_populate_aaaa_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'AAAA_RECORD',
                'id': 'rec-1',
                'domain': 'ipv6.example.com',
                'ttlSeconds': 3600,
                'ipv6Address': '2001:db8::1',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('AAAA', record._type)
        self.assertEqual('ipv6', record.name)
        self.assertEqual(['2001:db8::1'], record.values)

    def test_populate_cname_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'CNAME_RECORD',
                'id': 'rec-1',
                'domain': 'alias.example.com',
                'ttlSeconds': 300,
                'targetDomain': 'www.example.com',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('CNAME', record._type)
        self.assertEqual('alias', record.name)
        self.assertEqual('www.example.com.', record.value)

    def test_populate_mx_records(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'MX_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'ttlSeconds': 3600,
                'mailServerDomain': 'mail.example.com',
                'priority': 10,
            },
            {
                'type': 'MX_RECORD',
                'id': 'rec-2',
                'domain': 'example.com',
                'ttlSeconds': 3600,
                'mailServerDomain': 'mail2.example.com',
                'priority': 20,
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('MX', record._type)
        self.assertEqual('', record.name)
        values = sorted(record.values, key=lambda v: v.preference)
        self.assertEqual(10, values[0].preference)
        self.assertEqual('mail.example.com.', values[0].exchange)
        self.assertEqual(20, values[1].preference)
        self.assertEqual('mail2.example.com.', values[1].exchange)

    def test_populate_txt_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'TXT_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'text': 'v=spf1 include:example.com ~all',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('TXT', record._type)
        self.assertEqual('', record.name)
        self.assertEqual(['v=spf1 include:example.com ~all'], record.values)

    def test_populate_srv_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'service': '_sip',
                'protocol': '_tcp',
                'serverDomain': 'sip.example.com',
                'priority': 10,
                'weight': 60,
                'port': 5060,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('SRV', record._type)
        self.assertEqual('_sip._tcp', record.name)
        value = record.values[0]
        self.assertEqual(10, value.priority)
        self.assertEqual(60, value.weight)
        self.assertEqual(5060, value.port)
        self.assertEqual('sip.example.com.', value.target)

    def test_populate_filters_by_zone(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'host.other.com',
                'ttlSeconds': 300,
                'ipv4Address': '10.0.0.1',
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('www', record.name)

    def test_populate_apex_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('', record.name)

    def test_populate_mixed_records(self):
        provider = self._get_provider()
        provider._client.records.return_value = RECORDS_RESPONSE['data']

        zone = self._get_zone()
        provider.populate(zone)

        types = {r._type for r in zone.records}
        self.assertEqual({'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV'}, types)

    def test_populate_skips_unsupported_types(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'UNKNOWN_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(0, len(zone.records))

    def test_apply_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []

        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            'www',
            {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '5.6.7.8']},
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        self.assertEqual(2, provider._client.record_create.call_count)
        calls = provider._client.record_create.call_args_list
        params_0 = calls[0][0][0]
        self.assertEqual('A_RECORD', params_0['type'])
        self.assertEqual('www.example.com', params_0['domain'])
        self.assertTrue(params_0['enabled'])
        self.assertNotIn('metadata', params_0)

    def test_apply_delete(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]

        change = MagicMock()
        change.existing = record

        provider._apply_Delete(change)

        self.assertEqual(2, provider._client.record_delete.call_count)
        provider._client.record_delete.assert_any_call('rec-1')
        provider._client.record_delete.assert_any_call('rec-2')

    def test_apply_update(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        existing = list(zone.records)[0]
        new = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 300, 'values': ['9.9.9.9']}
        )

        change = MagicMock()
        change.existing = existing
        change.new = new

        provider._apply_Update(change)

        provider._client.record_delete.assert_called_once_with('rec-1')
        provider._client.record_create.assert_called_once()
        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('9.9.9.9', params['ipv4Address'])

    def test_apply_cname_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            'alias',
            {'type': 'CNAME', 'ttl': 300, 'value': 'www.example.com.'},
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('CNAME_RECORD', params['type'])
        self.assertEqual('www.example.com', params['targetDomain'])
        self.assertEqual('alias.example.com', params['domain'])

    def test_apply_mx_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            '',
            {
                'type': 'MX',
                'ttl': 3600,
                'values': [{'preference': 10, 'exchange': 'mail.example.com.'}],
            },
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('MX_RECORD', params['type'])
        self.assertEqual('mail.example.com', params['mailServerDomain'])
        self.assertEqual(10, params['priority'])
        self.assertEqual('example.com', params['domain'])

    def test_apply_srv_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            '_sip._tcp',
            {
                'type': 'SRV',
                'ttl': 600,
                'values': [
                    {
                        'priority': 10,
                        'weight': 60,
                        'port': 5060,
                        'target': 'sip.example.com.',
                    }
                ],
            },
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('SRV_RECORD', params['type'])
        self.assertEqual('sip.example.com', params['serverDomain'])
        self.assertEqual(10, params['priority'])
        self.assertEqual(60, params['weight'])
        self.assertEqual(5060, params['port'])
        self.assertEqual('example.com', params['domain'])
        self.assertEqual('_sip', params['service'])
        self.assertEqual('_tcp', params['protocol'])

    def test_apply_full_plan(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'old.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        plan = MagicMock()
        plan.desired = zone

        create_change = MagicMock()
        create_change.__class__ = type('Create', (), {})
        create_change.__class__.__name__ = 'Create'
        create_change.new = Record.new(
            zone, 'new', {'type': 'A', 'ttl': 300, 'values': ['9.9.9.9']}
        )

        delete_change = MagicMock()
        delete_change.__class__ = type('Delete', (), {})
        delete_change.__class__.__name__ = 'Delete'
        delete_change.existing = list(zone.records)[0]

        plan.changes = [delete_change, create_change]

        provider._apply(plan)

        provider._client.record_delete.assert_called_once_with('rec-1')
        provider._client.record_create.assert_called_once()

        self.assertNotIn(zone.name, provider._zone_records)

    def test_apply_aaaa_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            'ipv6',
            {'type': 'AAAA', 'ttl': 300, 'values': ['2001:db8::1']},
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('AAAA_RECORD', params['type'])
        self.assertEqual('2001:db8::1', params['ipv6Address'])
        self.assertEqual('ipv6.example.com', params['domain'])

    def test_apply_txt_create(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            '',
            {
                'type': 'TXT',
                'ttl': 300,
                'values': ['v=spf1 include:example.com ~all'],
            },
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('TXT_RECORD', params['type'])
        self.assertEqual('v=spf1 include:example.com ~all', params['text'])
        self.assertEqual('example.com', params['domain'])

    def test_apply_delete_skips_wrong_type(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-mx-1',
                'domain': 'mail.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.5',
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        # Manually inject a mismatched type record into the cache
        provider._zone_records[zone.name].append(
            {
                'type': 'MX_RECORD',
                'id': 'rec-mx-fake',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'mailServerDomain': 'mail.example.com',
                'priority': 10,
            }
        )

        www_record = None
        for r in zone.records:
            if r.name == 'www':
                www_record = r
                break

        change = MagicMock()
        change.existing = www_record

        provider._apply_Delete(change)

        # Should only delete the A record, not the MX
        provider._client.record_delete.assert_called_once_with('rec-1')

    def test_populate_cname_with_trailing_dot(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'CNAME_RECORD',
                'id': 'rec-1',
                'domain': 'alias.example.com',
                'ttlSeconds': 300,
                'targetDomain': 'www.example.com.',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual('www.example.com.', record.value)

    def test_populate_mx_with_trailing_dot(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'MX_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'mailServerDomain': 'mail.example.com.',
                'priority': 10,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual('mail.example.com.', record.values[0].exchange)

    def test_populate_srv_with_trailing_dot(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-1',
                'domain': 'example.com',
                'service': '_sip',
                'protocol': '_tcp',
                'serverDomain': 'sip.example.com.',
                'priority': 10,
                'weight': 60,
                'port': 5060,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual('sip.example.com.', record.values[0].target)

    def test_populate_srv_without_service_protocol(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-1',
                'domain': '_sip._tcp.example.com',
                'serverDomain': 'sip.example.com',
                'priority': 10,
                'weight': 60,
                'port': 5060,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('SRV', record._type)
        self.assertEqual('_sip._tcp', record.name)

    def test_apply_srv_create_with_host(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            '_sip._tcp.sub',
            {
                'type': 'SRV',
                'ttl': 600,
                'values': [
                    {
                        'priority': 10,
                        'weight': 60,
                        'port': 5060,
                        'target': 'sip.example.com.',
                    }
                ],
            },
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('sub.example.com', params['domain'])
        self.assertEqual('_sip', params['service'])
        self.assertEqual('_tcp', params['protocol'])

    def test_apply_srv_create_apex(self):
        provider = self._get_provider()
        provider._client.records.return_value = []
        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone,
            '_sip._tcp',
            {
                'type': 'SRV',
                'ttl': 600,
                'values': [
                    {
                        'priority': 10,
                        'weight': 60,
                        'port': 5060,
                        'target': 'sip.example.com.',
                    }
                ],
            },
        )

        change = MagicMock()
        change.__class__ = type('Create', (), {})
        change.__class__.__name__ = 'Create'
        change.new = record

        provider._apply_Create(change)

        params = provider._client.record_create.call_args[0][0]
        self.assertEqual('example.com', params['domain'])
        self.assertEqual('_sip', params['service'])
        self.assertEqual('_tcp', params['protocol'])

    def test_apply_delete_srv_matches(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-srv-1',
                'domain': 'example.com',
                'service': '_sip',
                'protocol': '_tcp',
                'serverDomain': 'sip.example.com',
                'priority': 10,
                'weight': 60,
                'port': 5060,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        change = MagicMock()
        change.existing = record

        provider._apply_Delete(change)

        provider._client.record_delete.assert_called_once_with('rec-srv-1')

    def test_apply_delete_srv_without_service_protocol(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-srv-1',
                'domain': '_sip._tcp.example.com',
                'serverDomain': 'sip.example.com',
                'priority': 10,
                'weight': 60,
                'port': 5060,
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        change = MagicMock()
        change.existing = record

        provider._apply_Delete(change)

        provider._client.record_delete.assert_called_once_with('rec-srv-1')

    def test_resolve_site_cached(self):
        provider = self._get_provider()
        provider._client = MagicMock()

        client = UnifiClient.__new__(UnifiClient)
        client.log = MagicMock()
        client._sess = MagicMock()
        client._base = 'https://unifi.local/proxy/network'
        client._site_name = 'default'
        client._site_id = 'already-resolved'
        client._dns_path = '/integration/v1/sites/already-resolved/dns/policies'

        client._resolve_site()

        client._sess.request.assert_not_called()

    def test_populate_returns_false_when_no_records(self):
        provider = self._get_provider()
        provider._client.records.return_value = []

        zone = self._get_zone()
        exists = provider.populate(zone)

        self.assertFalse(exists)
        self.assertEqual(0, len(zone.records))

    def test_populate_returns_true_when_records_exist(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        exists = provider.populate(zone)

        self.assertTrue(exists)

    def test_populate_handles_none_response(self):
        provider = self._get_provider()
        provider._client.records.return_value = None

        zone = self._get_zone()
        exists = provider.populate(zone)

        self.assertFalse(exists)
        self.assertEqual(0, len(zone.records))

    def test_populate_default_ttl_fallback(self):
        provider = UnifiProvider(
            'test', 'unifi.local', 'test-api-key', default_ttl=600
        )
        provider._client = MagicMock()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 0,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual(600, record.ttl)

    def test_populate_inconsistent_ttls(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'www.example.com',
                'ttlSeconds': 600,
                'ipv4Address': '5.6.7.8',
            },
        ]

        zone = self._get_zone()
        with self.assertLogs('UnifiProvider[test]', level='WARNING') as cm:
            provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual(600, record.ttl)
        self.assertTrue(
            any('inconsistent TTLs' in m for m in cm.output), cm.output
        )

    @patch('octodns_unifi.Session')
    def test_connection_error(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess
        mock_sess.request.side_effect = RequestsConnectionError(
            'Connection refused'
        )

        secret = 'my-secret-api-key-value'
        client = UnifiClient('unifi.local', secret)

        with self.assertRaises(UnifiClientException) as ctx:
            client._request('GET', '/some/path')

        msg = str(ctx.exception)
        self.assertIn('ConnectionError', msg)
        self.assertNotIn(secret, msg)

    def test_apply_delete_no_cache(self):
        provider = self._get_provider()
        provider._client.records.return_value = []

        zone = self._get_zone()
        provider.populate(zone)

        record = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
        )

        change = MagicMock()
        change.existing = record

        # Clear cache to simulate missing zone entry
        provider._zone_records.clear()

        with self.assertRaises(UnifiClientException):
            provider._apply_Delete(change)

        provider._client.record_delete.assert_not_called()

    def test_apply_delete_skips_missing_id(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]

        change = MagicMock()
        change.existing = record

        provider._apply_Delete(change)

        provider._client.record_delete.assert_not_called()

    def test_list_zones_configured(self):
        provider = UnifiProvider(
            'test',
            'unifi.local',
            'test-api-key',
            zones=['other.net.', 'example.com.'],
        )
        provider._client = MagicMock()

        result = provider.list_zones()

        self.assertEqual(['example.com.', 'other.net.'], result)
        provider._client.records.assert_not_called()

    def test_list_zones_configured_no_trailing_dot(self):
        provider = UnifiProvider(
            'test',
            'unifi.local',
            'test-api-key',
            zones=['other.net', 'example.com.'],
        )
        provider._client = MagicMock()

        result = provider.list_zones()

        self.assertEqual(['example.com.', 'other.net.'], result)
        provider._client.records.assert_not_called()

    def test_list_zones_configured_empty(self):
        provider = UnifiProvider(
            'test', 'unifi.local', 'test-api-key', zones=[]
        )
        provider._client = MagicMock()

        result = provider.list_zones()

        self.assertEqual([], result)
        provider._client.records.assert_not_called()

    def test_list_zones_auto_extract(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {'type': 'A_RECORD', 'domain': 'www.example.com'},
            {'type': 'A_RECORD', 'domain': 'mail.example.com'},
            {'type': 'A_RECORD', 'domain': 'host.other.net'},
            {'type': 'A_RECORD', 'domain': 'sub.deep.other.net'},
        ]

        result = provider.list_zones()

        self.assertEqual(['example.com.', 'other.net.'], result)

    def test_list_zones_empty(self):
        provider = self._get_provider()
        provider._client.records.return_value = []

        result = provider.list_zones()

        self.assertEqual([], result)

    def test_list_zones_none_response(self):
        provider = self._get_provider()
        provider._client.records.return_value = None

        result = provider.list_zones()

        self.assertEqual([], result)

    def test_list_zones_apex_record(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {'type': 'A_RECORD', 'domain': 'example.com'}
        ]

        result = provider.list_zones()

        self.assertEqual(['example.com.'], result)

    def test_list_zones_single_label(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {'type': 'A_RECORD', 'domain': 'localhost'},
            {'type': 'A_RECORD', 'domain': 'www.example.com'},
        ]

        result = provider.list_zones()

        self.assertEqual(['example.com.'], result)

    def test_list_zones_wildcard(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {'type': 'A_RECORD', 'domain': '*.dev.example.org'},
            {'type': 'A_RECORD', 'domain': '*.staging.example.org'},
            {'type': 'A_RECORD', 'domain': 'www.example.org'},
        ]

        result = provider.list_zones()

        self.assertEqual(['example.org.'], result)

    def test_list_zones_caches_records_for_populate(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        provider.list_zones()

        zone = self._get_zone()
        provider.populate(zone)

        provider._client.records.assert_called_once()

    def test_list_zones_cache_reused_for_all_populates(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'host.other.net',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
        ]

        provider.list_zones()

        zone1 = self._get_zone()
        provider.populate(zone1)

        zone2 = Zone('other.net.', [])
        provider.populate(zone2)

        # Cache is reused for all populate() calls after list_zones()
        self.assertEqual(1, provider._client.records.call_count)

    def test_populate_subzone_parent_child_isolation(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-parent',
                'domain': 'app.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-child-apex',
                'domain': 'platform.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-child-sub',
                'domain': 'app.platform.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '9.10.11.12',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-apex',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'ipv4Address': '13.14.15.16',
            },
        ]

        zone = Zone('example.com.', {'platform'})
        provider.populate(zone)

        names = sorted(r.name for r in zone.records)
        self.assertEqual(['', 'app'], names)

    def test_populate_subzone_deep_nesting(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-parent',
                'domain': 'app.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-platform',
                'domain': 'db.platform.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-deep',
                'domain': 'host.security.platform.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '9.10.11.12',
            },
        ]

        zone = Zone('example.com.', {'platform', 'security.platform'})
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        self.assertEqual('app', list(zone.records)[0].name)

    def test_populate_subzone_apex_records_pass(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-a',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'MX_RECORD',
                'id': 'rec-mx',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'mailServerDomain': 'mail.example.com',
                'priority': 10,
            },
            {
                'type': 'TXT_RECORD',
                'id': 'rec-txt',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'text': 'v=spf1 -all',
            },
        ]

        zone = Zone('example.com.', {'platform'})
        provider.populate(zone)

        types = {r._type for r in zone.records}
        self.assertEqual({'A', 'MX', 'TXT'}, types)

    def test_populate_subzone_srv_excluded(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'SRV_RECORD',
                'id': 'rec-srv-parent',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'service': '_sip',
                'protocol': '_tcp',
                'port': 5060,
                'priority': 10,
                'weight': 20,
                'serverDomain': 'sip.example.com',
            },
            {
                'type': 'SRV_RECORD',
                'id': 'rec-srv-sub',
                'domain': 'platform.example.com',
                'ttlSeconds': 300,
                'service': '_sip',
                'protocol': '_tcp',
                'port': 5060,
                'priority': 10,
                'weight': 20,
                'serverDomain': 'sip.platform.example.com',
            },
        ]

        zone = Zone('example.com.', {'platform'})
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        record = list(zone.records)[0]
        self.assertEqual('SRV', record._type)
        self.assertEqual('_sip._tcp', record.name)

    def test_populate_subzone_backcompat_no_subzones(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'app.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-2',
                'domain': 'deep.nested.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-3',
                'domain': 'example.com',
                'ttlSeconds': 300,
                'ipv4Address': '9.10.11.12',
            },
        ]

        zone = Zone('example.com.', set())
        provider.populate(zone)

        names = sorted(r.name for r in zone.records)
        self.assertEqual(['', 'app', 'deep.nested'], names)

    def test_apply_delete_skips_cross_zone_records(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-same',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-cross',
                'domain': 'www.other.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
        ]

        zone = self._get_zone()
        provider.populate(zone)

        record = list(zone.records)[0]
        change = MagicMock()
        change.existing = record

        provider._apply_Delete(change)

        provider._client.record_delete.assert_called_once_with('rec-same')

    def test_populate_subzone_wildcard_in_parent(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-wild-parent',
                'domain': '*.foo.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            },
            {
                'type': 'A_RECORD',
                'id': 'rec-wild-sub',
                'domain': '*.platform.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '5.6.7.8',
            },
        ]

        zone = Zone('example.com.', {'platform'})
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        self.assertEqual('*.foo', list(zone.records)[0].name)

    def test_data_for_cname_empty_records(self):
        provider = self._get_provider()
        with self.assertRaises(ValueError):
            provider._data_for_CNAME('CNAME', [])

    def test_params_for_srv_invalid_name(self):
        provider = self._get_provider()
        record = MagicMock()
        record.name = 'notsrv'
        record.zone = self._get_zone()
        with self.assertRaises(ValueError) as ctx:
            list(provider._params_for_SRV(record))
        self.assertIn('_service._protocol', str(ctx.exception))

    def test_record_matches_cross_zone_returns_false(self):
        provider = self._get_provider()
        zone = self._get_zone()
        octodns_record = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
        )
        api_record = {'type': 'A_RECORD', 'domain': 'www.other.com'}
        self.assertFalse(provider._record_matches(api_record, octodns_record))

    def test_populate_negative_ttl_ignored(self):
        provider = UnifiProvider(
            'test', 'unifi.local', 'test-api-key', default_ttl=600
        )
        provider._client = MagicMock()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': -1,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(600, list(zone.records)[0].ttl)

    def test_data_for_cname_duplicate_warns(self):
        provider = self._get_provider()
        records = [
            {'targetDomain': 'a.example.com', 'ttlSeconds': 300},
            {'targetDomain': 'b.example.com', 'ttlSeconds': 300},
        ]
        with self.assertLogs('UnifiProvider[test]', level='WARNING') as cm:
            data = provider._data_for_CNAME('CNAME', records)
        self.assertEqual('a.example.com.', data['value'])
        self.assertTrue(
            any('share one name' in m for m in cm.output), cm.output
        )

    def test_params_ttl_only_for_supported_types(self):
        provider = self._get_provider()
        zone = self._get_zone()

        a = Record.new(
            zone, 'www', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4']}
        )
        self.assertEqual(300, list(provider._params_for_A(a))[0]['ttlSeconds'])

        aaaa = Record.new(
            zone, 'v6', {'type': 'AAAA', 'ttl': 300, 'values': ['2001:db8::1']}
        )
        self.assertIn('ttlSeconds', list(provider._params_for_AAAA(aaaa))[0])

        cname = Record.new(
            zone,
            'alias',
            {'type': 'CNAME', 'ttl': 300, 'value': 'www.example.com.'},
        )
        self.assertIn('ttlSeconds', list(provider._params_for_CNAME(cname))[0])

        mx = Record.new(
            zone,
            '',
            {
                'type': 'MX',
                'ttl': 300,
                'values': [{'preference': 10, 'exchange': 'mail.example.com.'}],
            },
        )
        self.assertNotIn('ttlSeconds', list(provider._params_for_MX(mx))[0])

        txt = Record.new(
            zone, 'note', {'type': 'TXT', 'ttl': 300, 'values': ['hello']}
        )
        self.assertNotIn('ttlSeconds', list(provider._params_for_TXT(txt))[0])

        srv = Record.new(
            zone,
            '_sip._tcp',
            {
                'type': 'SRV',
                'ttl': 300,
                'values': [
                    {
                        'priority': 0,
                        'weight': 0,
                        'port': 5060,
                        'target': 'sip.example.com.',
                    }
                ],
            },
        )
        self.assertNotIn('ttlSeconds', list(provider._params_for_SRV(srv))[0])

    def test_populate_domain_case_insensitive(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'WWW.Example.COM',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        zone = self._get_zone()
        provider.populate(zone)

        self.assertEqual(1, len(zone.records))
        self.assertEqual('www', list(zone.records)[0].name)

    def test_populate_fetches_records_once(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        provider.populate(Zone('example.com.', []))
        provider.populate(Zone('example.com.', []))

        self.assertEqual(1, provider._client.records.call_count)

    def test_plan_and_apply_end_to_end(self):
        provider = self._get_provider()
        provider._client.records.return_value = [
            {
                'type': 'A_RECORD',
                'id': 'rec-1',
                'domain': 'www.example.com',
                'ttlSeconds': 300,
                'ipv4Address': '1.2.3.4',
            }
        ]

        desired = Zone('example.com.', [])
        desired.add_record(
            Record.new(
                desired, 'www', {'type': 'A', 'ttl': 300, 'values': ['9.9.9.9']}
            )
        )
        desired.add_record(
            Record.new(
                desired,
                'mail',
                {'type': 'A', 'ttl': 300, 'values': ['8.8.8.8']},
            )
        )

        plan = provider.plan(desired)
        self.assertIsNotNone(plan)
        provider.apply(plan)

        provider._client.record_delete.assert_called_once_with('rec-1')
        self.assertTrue(provider._client.record_create.called)
        self.assertNotIn(desired.name, provider._zone_records)
