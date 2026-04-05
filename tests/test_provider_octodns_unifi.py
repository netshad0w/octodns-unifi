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
            'domain': '_sip._tcp.example.com',
            'ttlSeconds': 600,
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
                'domain': '_sip._tcp.example.com',
                'ttlSeconds': 600,
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
        self.assertEqual('_sip._tcp.example.com', params['domain'])

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
                'domain': '_sip._tcp.example.com',
                'ttlSeconds': 600,
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
        provider.populate(zone)

        record = list(zone.records)[0]
        self.assertEqual(600, record.ttl)

    @patch('octodns_unifi.Session')
    def test_connection_error(self, mock_session_cls):
        mock_sess = MagicMock()
        mock_session_cls.return_value = mock_sess
        mock_sess.request.side_effect = RequestsConnectionError(
            'Connection refused'
        )

        client = UnifiClient('unifi.local', 'key')

        with self.assertRaises(UnifiClientException):
            client._request('GET', '/some/path')

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
