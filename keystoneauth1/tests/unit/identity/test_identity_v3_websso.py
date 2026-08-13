# Copyright 2026 Rackspace Technology, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import datetime
import io
import socket
from unittest import mock
import urllib.parse
import uuid

import fixtures

from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import websso
from keystoneauth1 import session
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils


KEYSTONE_TOKEN_VALUE = uuid.uuid4().hex


def _token_body(expires_in=3600):
    """Return an unscoped token body that expires ``expires_in`` from now."""
    body = copy.deepcopy(oidc_fixtures.UNSCOPED_TOKEN)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=expires_in
    )
    body['token']['expires_at'] = expires_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    return body


def _wait_running_flow(token=KEYSTONE_TOKEN_VALUE):
    """Stand in for _wait_for_token that runs the flow callback it is given."""

    def wait(
        redirect_host,
        redirect_port,
        keystone_origin,
        start_flow,
        timeout=websso._DEFAULT_TIMEOUT,
    ):
        start_flow()
        return token

    return wait


class CallbackAppTests(utils.TestCase):
    """Exercise the loopback listener without going near a socket."""

    KEYSTONE_ORIGIN = 'https://keystone.example.org:5000'

    def setUp(self):
        super().setUp()
        self.app = websso._CallbackApp(self.KEYSTONE_ORIGIN)

    def _environ(self, drop=(), body=None, **overrides):
        if body is None:
            body = f'token={KEYSTONE_TOKEN_VALUE}'
        environ = {
            'PATH_INFO': '/auth/websso/',
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'CONTENT_LENGTH': str(len(body)),
            'HTTP_SEC_FETCH_MODE': 'navigate',
            'HTTP_SEC_FETCH_DEST': 'document',
            'HTTP_SEC_FETCH_SITE': 'cross-site',
            'wsgi.input': io.BytesIO(body.encode('utf-8')),
        }
        environ.update(overrides)
        for key in drop:
            environ.pop(key, None)
        return environ

    def _call(self, **kwargs):
        started = []

        def start_response(status, headers):
            started.append((status, headers))

        body = b''.join(self.app(self._environ(**kwargs), start_response))
        return started[0][0], body

    def test_accepts_valid_post(self):
        status, body = self._call()

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)
        self.assertIn(b'<!doctype html>', body)

    def test_response_declares_utf8_html(self):
        started = []

        def start_response(status, headers):
            started.append((status, headers))

        self.app(self._environ(), start_response)
        headers = dict(started[0][1])

        self.assertEqual('text/html; charset=utf-8', headers['Content-Type'])

    def test_rejects_wrong_path(self):
        status, _ = self._call(PATH_INFO='/')

        self.assertEqual('404 Not Found', status)
        self.assertIsNone(self.app.token)

    def test_rejects_wrong_method(self):
        status, _ = self._call(REQUEST_METHOD='GET')

        self.assertEqual('405 Method Not Allowed', status)
        self.assertIsNone(self.app.token)

    def test_rejects_wrong_content_type(self):
        status, _ = self._call(CONTENT_TYPE='application/json')

        self.assertEqual('415 Unsupported Media Type', status)
        self.assertIsNone(self.app.token)

    def test_accepts_content_type_with_charset(self):
        status, _ = self._call(
            CONTENT_TYPE='application/x-www-form-urlencoded; charset=utf-8'
        )

        self.assertEqual('200 OK', status)

    def test_rejects_missing_content_length(self):
        status, _ = self._call(drop=['CONTENT_LENGTH'])

        self.assertEqual('411 Length Required', status)
        self.assertIsNone(self.app.token)

    def test_rejects_non_integer_content_length(self):
        status, _ = self._call(CONTENT_LENGTH='banana')

        self.assertEqual('411 Length Required', status)

    def test_rejects_oversized_body(self):
        status, _ = self._call(
            CONTENT_LENGTH=str(websso._MAX_CALLBACK_BODY + 1)
        )

        self.assertEqual('413 Content Too Large', status)
        self.assertIsNone(self.app.token)

    def test_rejects_missing_sec_fetch_mode(self):
        status, _ = self._call(drop=['HTTP_SEC_FETCH_MODE'])

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_rejects_scripted_fetch(self):
        # A cross-origin fetch() with a form content type is a "simple"
        # request, so it reaches us without a preflight. Fetch metadata is what
        # excludes it. Note that it does not exclude a scripted cross-origin
        # form submission, which is indistinguishable from Keystone's own.
        status, _ = self._call(
            HTTP_SEC_FETCH_MODE='no-cors', HTTP_SEC_FETCH_DEST='empty'
        )

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_rejects_mismatched_origin(self):
        status, _ = self._call(HTTP_ORIGIN='http://evil.example.net')

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_accepts_matching_origin(self):
        status, _ = self._call(HTTP_ORIGIN=self.KEYSTONE_ORIGIN)

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)

    def test_accepts_null_origin(self):
        # The Fetch standard serializes Origin as 'null' when the referrer
        # policy would strip the referrer, which covers the https to http
        # callback this flow relies on. A genuine POST looks like this, so it
        # has to be accepted even though an attacker's looks the same.
        status, _ = self._call(HTTP_ORIGIN='null')

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)

    def test_accepts_absent_origin(self):
        status, _ = self._call(drop=['HTTP_ORIGIN'])

        self.assertEqual('200 OK', status)

    def test_scripted_cross_origin_form_post_is_not_rejected(self):
        # Documents the known login CSRF exposure: a form submitted by another
        # page produces the same request as Keystone's auto-submitted form. If
        # this ever starts failing, a real binding mechanism has been found and
        # the warnings in the docs should be revisited.
        status, _ = self._call(HTTP_ORIGIN='null', body='token=attacker-token')

        self.assertEqual('200 OK', status)
        self.assertEqual('attacker-token', self.app.token)

    def test_rejects_missing_sec_fetch_dest(self):
        status, _ = self._call(drop=['HTTP_SEC_FETCH_DEST'])

        self.assertEqual('400 Bad Request', status)

    def test_rejects_wrong_sec_fetch_dest(self):
        status, _ = self._call(HTTP_SEC_FETCH_DEST='iframe')

        self.assertEqual('400 Bad Request', status)

    def test_rejects_sec_fetch_site_none(self):
        # 'none' means the user pasted the URL into the address bar.
        status, _ = self._call(HTTP_SEC_FETCH_SITE='none')

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_accepts_missing_sec_fetch_site(self):
        status, _ = self._call(drop=['HTTP_SEC_FETCH_SITE'])

        self.assertEqual('200 OK', status)

    def test_rejects_mismatched_referer(self):
        status, _ = self._call(HTTP_REFERER='https://evil.example.net/x')

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_accepts_matching_referer(self):
        status, _ = self._call(
            HTTP_REFERER=f'{self.KEYSTONE_ORIGIN}/v3/auth/OS-FEDERATION'
        )

        self.assertEqual('200 OK', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)

    def test_accepts_absent_referer(self):
        # The usual case: an HTTPS Keystone posting to an HTTP loopback
        # callback is a downgrade, so the browser strips the Referer.
        status, _ = self._call()

        self.assertEqual('200 OK', status)

    def test_rejects_missing_token_field(self):
        status, _ = self._call(body='notatoken=1')

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_rejects_empty_token_field(self):
        status, _ = self._call(body='token=')

        self.assertEqual('400 Bad Request', status)
        self.assertIsNone(self.app.token)

    def test_rejects_second_post(self):
        self.assertEqual('200 OK', self._call()[0])

        other = uuid.uuid4().hex
        status, _ = self._call(body=f'token={other}')

        self.assertEqual('409 Conflict', status)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)

    def test_rejected_post_does_not_prevent_a_later_good_one(self):
        self.assertEqual(
            '405 Method Not Allowed', self._call(REQUEST_METHOD='GET')[0]
        )
        self.assertIsNone(self.app.token)

        self.assertEqual('200 OK', self._call()[0])
        self.assertEqual(KEYSTONE_TOKEN_VALUE, self.app.token)


class LoopbackTests(utils.TestCase):
    def test_localhost_is_allowed(self):
        websso._assert_loopback('localhost')
        websso._assert_loopback('127.0.0.1')

    def test_non_loopback_is_rejected(self):
        with mock.patch.object(socket, 'getaddrinfo') as m:
            m.return_value = [
                (socket.AF_INET, None, None, '', ('192.0.2.10', 0))
            ]
            e = self.assertRaises(
                exceptions.OptionError,
                websso._assert_loopback,
                'somewhere.example.org',
            )

        self.assertIn('non-loopback', str(e))

    def test_unresolvable_is_rejected(self):
        with mock.patch.object(socket, 'getaddrinfo') as m:
            m.side_effect = socket.gaierror
            self.assertRaises(
                exceptions.OptionError, websso._assert_loopback, 'nope.invalid'
            )


class WaitForTokenTests(utils.TestCase):
    ORIGIN = 'https://keystone.example.org:5000'

    def _noop(self):
        pass

    def test_returns_the_token_once_posted(self):
        with mock.patch.object(
            websso.wsgiref.simple_server, 'make_server'
        ) as m:

            def handle_request():
                # Whatever the app records is what we should get back.
                m.call_args[0][2].token = KEYSTONE_TOKEN_VALUE

            m.return_value.__enter__.return_value = m.return_value
            m.return_value.handle_request.side_effect = handle_request

            token = websso._wait_for_token(
                'localhost', 9990, self.ORIGIN, self._noop
            )

        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)

    def test_callback_port_is_listening_before_the_flow_starts(self):
        # An identity provider with an established session posts the token
        # back as soon as the flow starts. Connecting from inside start_flow
        # pins the ordering: if the socket were not bound until afterwards,
        # this connect would be refused and the single callback lost.
        body = f'token={KEYSTONE_TOKEN_VALUE}'.encode()
        request = (
            b'POST /auth/websso/ HTTP/1.1\r\n'
            b'Host: localhost\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            b'Sec-Fetch-Mode: navigate\r\n'
            b'Sec-Fetch-Dest: document\r\n'
            b'Sec-Fetch-Site: cross-site\r\n'
            b'Connection: close\r\n'
            b'\r\n' + body
        )
        connections = []

        def start_flow():
            # Not wrapped in assertRaises: a refused connection here fails the
            # test with ConnectionRefusedError, which is the point.
            conn = socket.create_connection(('127.0.0.1', port), timeout=10)
            connections.append(conn)
            conn.sendall(request)

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]

        token = websso._wait_for_token(
            'localhost', port, self.ORIGIN, start_flow, timeout=10
        )

        self.addCleanup(connections[0].close)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)
        # The response only arrives once the serving loop has run, so reading
        # it here also confirms the request was accepted rather than rejected.
        self.assertIn(b'200 OK', connections[0].recv(4096))

    def test_flow_is_not_started_when_the_port_is_unavailable(self):
        started = []
        with socket.socket() as taken:
            taken.bind(('127.0.0.1', 0))
            taken.listen(1)
            port = taken.getsockname()[1]

            self.assertRaises(
                OSError,
                websso._wait_for_token,
                'localhost',
                port,
                self.ORIGIN,
                lambda: started.append(True),
            )

        self.assertEqual([], started)

    def test_timeout_raises(self):
        with mock.patch.object(
            websso.wsgiref.simple_server, 'make_server'
        ) as m:
            m.return_value.__enter__.return_value = m.return_value

            self.assertRaises(
                websso._MissingTokenError,
                websso._wait_for_token,
                'localhost',
                9990,
                self.ORIGIN,
                self._noop,
                timeout=0,
            )

        m.return_value.handle_request.assert_not_called()

    def test_port_in_use_propagates(self):
        with mock.patch.object(
            websso.wsgiref.simple_server, 'make_server'
        ) as m:
            m.side_effect = OSError('Address already in use')

            self.assertRaises(
                OSError,
                websso._wait_for_token,
                'localhost',
                9990,
                self.ORIGIN,
                self._noop,
            )


class WebSSOTests(utils.TestCase):
    def setUp(self):
        super().setUp()

        self.session = session.Session()
        self.AUTH_URL = 'http://keystone:5000/v3'
        self.IDENTITY_PROVIDER = 'bluepages'
        self.PROTOCOL = 'openid'

        self.cache_dir = self.useFixture(fixtures.TempDir()).path

    def _plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.AUTH_URL)
        kwargs.setdefault('identity_provider', self.IDENTITY_PROVIDER)
        kwargs.setdefault('protocol', self.PROTOCOL)
        kwargs.setdefault('cache_path', self.cache_dir)
        return websso.WebSSO(**kwargs)

    # -- URL construction ---------------------------------------------------

    def test_federated_token_url(self):
        self.assertEqual(
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso',
            self._plugin().federated_token_url,
        )

    def test_federated_token_url_with_trailing_slash(self):
        plugin = self._plugin(auth_url='http://keystone:5000/v3/')

        self.assertEqual(
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso',
            plugin.federated_token_url,
        )

    def test_federated_token_url_without_version(self):
        plugin = self._plugin(auth_url='http://keystone:5000')

        self.assertEqual(
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso',
            plugin.federated_token_url,
        )

    def test_default_redirect_uri(self):
        self.assertEqual(
            'http://localhost:9990/auth/websso/', self._plugin().redirect_uri
        )

    def test_custom_redirect_uri(self):
        plugin = self._plugin(redirect_host='127.0.0.1', redirect_port=9991)

        self.assertEqual(
            'http://127.0.0.1:9991/auth/websso/', plugin.redirect_uri
        )

    # -- browser handoff ----------------------------------------------------

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_browser_is_opened_with_encoded_origin(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        plugin = self._plugin()

        self.assertEqual(KEYSTONE_TOKEN_VALUE, plugin._get_auth_token())

        url = mock_open.call_args[0][0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual([plugin.redirect_uri], query['origin'])
        self.assertTrue(url.startswith(plugin.federated_token_url))
        # The Referer, when present, is Keystone's origin rather than ours.
        self.assertEqual(
            ('localhost', 9990, 'http://keystone:5000'),
            mock_wait.call_args[0][:3],
        )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_url_is_logged_even_when_the_browser_opens(
        self, mock_open, mock_wait
    ):
        # A successful return from webbrowser.open() does not mean the user
        # ended up on the page, so the URL has to be shown regardless.
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        plugin = self._plugin()

        plugin._get_auth_token()

        self.assertIn('To authenticate please go to', self.logger.output)
        self.assertIn(plugin.federated_token_url, self.logger.output)
        self.assertIn('origin=', self.logger.output)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_failure_to_open_a_browser_is_reported(self, mock_open, mock_wait):
        mock_open.return_value = False
        mock_wait.side_effect = _wait_running_flow()

        self._plugin()._get_auth_token()

        self.assertIn('To authenticate please go to', self.logger.output)
        self.assertIn('could not be opened', self.logger.output)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_nothing_user_facing_goes_to_stdout(self, mock_open, mock_wait):
        # stdout is where consumers put machine readable output, so the URL
        # must not be written there.
        mock_open.return_value = False
        mock_wait.side_effect = _wait_running_flow()
        stdout = self.useFixture(fixtures.StringStream('stdout'))

        with mock.patch('sys.stdout', stdout.stream):
            self._plugin()._get_auth_token()

        self.assertEqual('', stdout.getDetails()['stdout'].as_text())

    # -- end to end ---------------------------------------------------------

    def _stub_token_validation(self, body=None):
        return self.requests_mock.get(
            f'{self.AUTH_URL}/auth/tokens',
            json=body if body is not None else _token_body(),
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE},
        )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_get_unscoped_auth_ref(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin()

        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        self.assertRequestHeaderEqual('X-Subject-Token', KEYSTONE_TOKEN_VALUE)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_non_v3_token_response_is_rejected(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        # A v2 style body reaching the v3 endpoint is not something we can
        # rescope, so it must not be quietly accepted or cached.
        self._stub_token_validation(body={'access': {}})
        plugin = self._plugin()

        self.assertRaises(
            exceptions.InvalidResponse,
            plugin.get_unscoped_auth_ref,
            self.session,
        )
        self.assertFalse(plugin._cache_file().exists())

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_reauthentication_does_not_reuse_a_stale_auth_ref(
        self, mock_open, mock_wait
    ):
        # auth_ref holds the previous, possibly scoped, token while we are
        # being asked to authenticate again. It must not be mistaken for a
        # usable unscoped token.
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin(token_cache=websso.CACHE_DISABLED)

        plugin.get_unscoped_auth_ref(self.session)
        plugin.auth_ref = plugin.get_unscoped_auth_ref(self.session)
        plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(3, mock_open.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_scoped_auth_rescopes_the_unscoped_token(
        self, mock_open, mock_wait
    ):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        scoped_token = uuid.uuid4().hex
        self.requests_mock.post(
            f'{self.AUTH_URL}/auth/tokens',
            json=_token_body(),
            headers={'X-Subject-Token': scoped_token},
        )
        plugin = self._plugin(
            project_name='myproject', project_domain_name='Default'
        )

        auth_ref = plugin.get_auth_ref(self.session)

        self.assertEqual(scoped_token, auth_ref.auth_token)

    # -- cache --------------------------------------------------------------

    def test_cache_file_is_deterministic(self):
        self.assertEqual(
            self._plugin()._cache_file(), self._plugin()._cache_file()
        )

    def test_cache_file_varies_by_protocol(self):
        self.assertNotEqual(
            self._plugin(protocol='openid')._cache_file(),
            self._plugin(protocol='saml2')._cache_file(),
        )

    def test_cache_file_varies_by_identity_provider(self):
        self.assertNotEqual(
            self._plugin(identity_provider='one')._cache_file(),
            self._plugin(identity_provider='two')._cache_file(),
        )

    def test_cache_file_is_unambiguous_across_elements(self):
        # The elements must not be able to run together: 'foo'/'bar' and
        # 'foob'/'ar' are different identities and cannot share a cache file.
        self.assertNotEqual(
            self._plugin(
                identity_provider='foo', protocol='bar'
            )._cache_file(),
            self._plugin(
                identity_provider='foob', protocol='ar'
            )._cache_file(),
        )

    def test_cache_file_varies_by_auth_url(self):
        self.assertNotEqual(
            self._plugin(auth_url='http://one:5000/v3')._cache_file(),
            self._plugin(auth_url='http://two:5000/v3')._cache_file(),
        )

    def test_cache_file_ignores_scope(self):
        # This is the whole point: one browser login, any project.
        self.assertEqual(
            self._plugin(
                project_name='a', project_domain_name='d'
            )._cache_file(),
            self._plugin(
                project_name='b', project_domain_name='d'
            )._cache_file(),
        )

    def test_default_cache_dir_is_used_when_unset(self):
        plugin = websso.WebSSO(
            self.AUTH_URL, self.IDENTITY_PROVIDER, self.PROTOCOL
        )

        self.assertEqual(websso._default_cache_dir(), plugin.cache_path)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_token_is_cached_user_only(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin()

        plugin.get_unscoped_auth_ref(self.session)

        cache_file = plugin._cache_file()
        self.assertTrue(cache_file.exists())
        self.assertEqual(0o600, cache_file.stat().st_mode & 0o777)
        self.assertEqual(0o700, cache_file.parent.stat().st_mode & 0o777)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_cached_token_skips_the_browser(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()

        self._plugin().get_unscoped_auth_ref(self.session)
        self.assertEqual(1, mock_open.call_count)

        # A second, independent plugin instance must reuse the cache.
        auth_ref = self._plugin().get_unscoped_auth_ref(self.session)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        self.assertEqual(1, mock_open.call_count)
        self.assertEqual(1, mock_wait.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_expired_cache_reauthenticates(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation(body=_token_body(expires_in=-60))

        plugin = self._plugin()
        plugin.get_unscoped_auth_ref(self.session)
        cache_file = plugin._cache_file()
        self.assertTrue(cache_file.exists())

        self._plugin().get_unscoped_auth_ref(self.session)

        self.assertEqual(2, mock_open.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_corrupt_cache_is_discarded(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()

        plugin = self._plugin()
        cache_file = plugin._cache_file()
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text('this is not json', encoding='utf-8')

        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        self.assertEqual(1, mock_open.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_refresh_replaces_the_cached_token(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()

        self._plugin().get_unscoped_auth_ref(self.session)
        self.assertEqual(1, mock_open.call_count)

        replacement = uuid.uuid4().hex
        mock_wait.side_effect = _wait_running_flow(replacement)
        self.requests_mock.get(
            f'{self.AUTH_URL}/auth/tokens',
            json=_token_body(),
            headers={'X-Subject-Token': replacement},
        )
        plugin = self._plugin(token_cache=websso.CACHE_REFRESH)

        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        # A fresh browser round trip, and the new token is what got cached.
        self.assertEqual(2, mock_open.call_count)
        self.assertEqual(replacement, auth_ref.auth_token)
        self.assertIn(replacement, plugin._cache_file().read_text())

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_refresh_only_forces_one_round_trip(self, mock_open, mock_wait):
        # Otherwise a plugin configured this way would reopen the browser on
        # every rescope for the life of the process.
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin(token_cache=websso.CACHE_REFRESH)

        plugin.get_unscoped_auth_ref(self.session)
        plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(1, mock_open.call_count)

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_refresh_drops_the_cache_even_if_the_flow_fails(
        self, mock_open, mock_wait
    ):
        # The stale token must not survive to be picked up by a later run.
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        self._plugin().get_unscoped_auth_ref(self.session)
        cache_file = self._plugin()._cache_file()
        self.assertTrue(cache_file.exists())

        mock_wait.side_effect = websso._MissingTokenError
        plugin = self._plugin(token_cache=websso.CACHE_REFRESH)

        self.assertRaises(
            websso._MissingTokenError,
            plugin.get_unscoped_auth_ref,
            self.session,
        )
        self.assertFalse(cache_file.exists())

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_invalidate_removes_the_cached_token(self, mock_open, mock_wait):
        # A session invalidates the plugin after a 401 and retries. If the
        # rejected token stayed in the cache it would be read straight back.
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin()
        plugin.get_unscoped_auth_ref(self.session)
        self.assertTrue(plugin._cache_file().exists())

        self.assertTrue(plugin.invalidate())

        self.assertFalse(plugin._cache_file().exists())
        self.assertIsNone(plugin.auth_ref)

        plugin.get_unscoped_auth_ref(self.session)
        self.assertEqual(2, mock_open.call_count)

    def test_invalidate_without_a_cache_is_harmless(self):
        plugin = self._plugin()

        self.assertFalse(plugin.invalidate())

    def test_unknown_cache_mode_is_rejected(self):
        e = self.assertRaises(
            exceptions.OptionError, self._plugin, token_cache='sometimes'
        )

        self.assertIn('reuse, refresh, disabled', str(e))

    def test_a_boolean_cache_mode_is_rejected(self):
        # YAML turns several English words into booleans, so someone writing
        # 'token_cache: no' in clouds.yaml arrives here with False rather than
        # a string. Better to say so than to guess what was meant.
        self.assertRaises(
            exceptions.OptionError, self._plugin, token_cache=False
        )

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_cache_can_be_disabled(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        plugin = self._plugin(token_cache=websso.CACHE_DISABLED)

        plugin.get_unscoped_auth_ref(self.session)

        self.assertFalse(plugin._cache_file().exists())

    @mock.patch.object(websso, '_wait_for_token')
    @mock.patch.object(websso.webbrowser, 'open')
    def test_unwritable_cache_does_not_fail_auth(self, mock_open, mock_wait):
        mock_open.return_value = True
        mock_wait.side_effect = _wait_running_flow()
        self._stub_token_validation()
        # A path that cannot be a directory.
        blocker = self.cache_dir + '/blocked'
        with open(blocker, 'w') as f:
            f.write('')
        plugin = self._plugin(cache_path=blocker + '/sub')

        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        self.assertIn('Could not write the token cache', self.logger.output)
