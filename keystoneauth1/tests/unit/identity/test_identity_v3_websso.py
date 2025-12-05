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

import json
import socket
import tempfile
import uuid
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from unittest import mock

from keystoneauth1 import exceptions
from keystoneauth1 import session
from keystoneauth1.identity.v3 import websso
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils


KEYSTONE_TOKEN_VALUE = uuid.uuid4().hex


class WebSSOOpenIDConnectTests(utils.TestCase):
    """Test cases for the WebSSOOpenIDConnect authentication plugin."""

    def setUp(self):
        super().setUp()
        self.session = session.Session()

        self.AUTH_URL = 'http://keystone:5000/v3'
        self.IDENTITY_PROVIDER = 'bluepages'
        self.PROTOCOL = 'openid'
        self.PROJECT_NAME = 'foo project'
        self.REDIRECT_HOST = 'localhost'
        self.REDIRECT_PORT = 9990

        self.FEDERATION_AUTH_URL = (
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso'
        )

        # Create a temporary directory for cache testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = self.temp_dir.name

    def tearDown(self):
        super().tearDown()
        self.temp_dir.cleanup()

    def _get_plugin(self, **kwargs):
        """Helper to create a plugin with default and custom parameters."""
        params = {
            'auth_url': self.AUTH_URL,
            'identity_provider': self.IDENTITY_PROVIDER,
            'protocol': self.PROTOCOL,
            'redirect_host': self.REDIRECT_HOST,
            'redirect_port': self.REDIRECT_PORT,
            'cache_path': self.cache_path,
        }
        params.update(kwargs)
        return websso.WebSSOOpenIDConnect(**params)

    def test_federated_token_url(self):
        """Test that the federated token URL is constructed correctly."""
        plugin = self._get_plugin()
        expected_url = (
            f'{self.AUTH_URL}/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso'
        )
        self.assertEqual(expected_url, plugin.federated_token_url)

    def test_federated_token_url_with_trailing_slash(self):
        """Test URL construction with trailing slash in auth_url."""
        plugin = self._get_plugin(auth_url='http://keystone:5000/v3/')
        expected_url = (
            'http://keystone:5000/v3/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso'
        )
        self.assertEqual(expected_url, plugin.federated_token_url)

    def test_federated_token_url_without_v3(self):
        """Test URL construction when auth_url doesn't end with v3."""
        plugin = self._get_plugin(auth_url='http://keystone:5000')
        expected_url = (
            'http://keystone:5000/v3/auth/OS-FEDERATION/identity_providers/'
            f'{self.IDENTITY_PROVIDER}/protocols/{self.PROTOCOL}/websso'
        )
        self.assertEqual(expected_url, plugin.federated_token_url)

    def test_redirect_uri(self):
        """Test that redirect URI is constructed correctly."""
        plugin = self._get_plugin()
        expected_uri = f'http://{self.REDIRECT_HOST}:{self.REDIRECT_PORT}/auth/websso/'
        self.assertEqual(expected_uri, plugin.redirect_uri)

    def test_custom_redirect_port(self):
        """Test using a custom redirect port."""
        custom_port = 8080
        plugin = self._get_plugin(redirect_port=custom_port)
        expected_uri = f'http://{self.REDIRECT_HOST}:{custom_port}/auth/websso/'
        self.assertEqual(expected_uri, plugin.redirect_uri)

    def test_cache_id_generation(self):
        """Test that cache IDs are generated consistently."""
        plugin1 = self._get_plugin()
        plugin2 = self._get_plugin()
        self.assertEqual(plugin1._get_cache_id(), plugin2._get_cache_id())

    def test_cache_id_uniqueness(self):
        """Test that different configs generate different cache IDs."""
        plugin1 = self._get_plugin()
        plugin2 = self._get_plugin(identity_provider='different-idp')
        self.assertNotEqual(plugin1._get_cache_id(), plugin2._get_cache_id())

    def test_cache_path(self):
        """Test that cache path is constructed correctly."""
        plugin = self._get_plugin()
        cache_path = plugin._get_cache_path()
        self.assertTrue(cache_path.parent == Path(self.cache_path))
        self.assertTrue(str(cache_path).startswith(self.cache_path))

    def test_token_expired_with_valid_token(self):
        """Test that a valid token is not marked as expired."""
        plugin = self._get_plugin()
        # Create a token that expires in 1 hour
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': {
                'token': {
                    'expires_at': expires_at.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                }
            }
        }
        self.assertFalse(plugin._token_expired(data))

    def test_token_expired_with_expired_token(self):
        """Test that an expired token is marked as expired."""
        plugin = self._get_plugin()
        # Create a token that expired 1 hour ago
        expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': {
                'token': {
                    'expires_at': expires_at.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                }
            }
        }
        self.assertTrue(plugin._token_expired(data))

    def test_token_expired_with_malformed_data(self):
        """Test that malformed cache data is treated as expired."""
        plugin = self._get_plugin()
        self.assertTrue(plugin._token_expired({}))
        self.assertTrue(plugin._token_expired({'body': {}}))
        self.assertTrue(plugin._token_expired({'body': {'token': {}}}))

    def test_put_and_get_cached_data(self):
        """Test caching and retrieving token data."""
        plugin = self._get_plugin()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': {
                'token': {
                    'expires_at': expires_at.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                }
            }
        }

        # Put data in cache
        plugin._put_cached_data(data)

        # Verify cache file exists
        cache_file = plugin._get_cache_path()
        self.assertTrue(cache_file.exists())

        # Verify file permissions (user-only read/write)
        self.assertEqual(cache_file.stat().st_mode & 0o777, 0o600)

        # Retrieve cached data
        cached_data = plugin._get_cached_data()
        self.assertIsNotNone(cached_data)
        self.assertEqual(cached_data['auth_token'], data['auth_token'])

    def test_get_cached_data_returns_none_for_expired(self):
        """Test that expired cached data returns None."""
        plugin = self._get_plugin()
        expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': {
                'token': {
                    'expires_at': expires_at.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                }
            }
        }

        # Put expired data in cache
        plugin._put_cached_data(data)

        # Should return None for expired data
        cached_data = plugin._get_cached_data()
        self.assertIsNone(cached_data)

    def test_get_cached_data_returns_none_when_no_cache(self):
        """Test that get_cached_data returns None when cache doesn't exist."""
        plugin = self._get_plugin()
        cached_data = plugin._get_cached_data()
        self.assertIsNone(cached_data)

    @mock.patch('webbrowser.open')
    @mock.patch.object(websso, '_wait_for_token')
    def test_get_auth_token(self, mock_wait, mock_browser):
        """Test that _get_auth_token opens browser and waits for token."""
        mock_wait.return_value = KEYSTONE_TOKEN_VALUE
        plugin = self._get_plugin()

        token = plugin._get_auth_token()

        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)
        mock_browser.assert_called_once()
        mock_wait.assert_called_once_with(
            self.REDIRECT_HOST, self.REDIRECT_PORT
        )

        # Check that the browser was opened with the correct URL
        call_args = mock_browser.call_args
        url = call_args[0][0]
        self.assertIn(self.FEDERATION_AUTH_URL, url)
        self.assertIn('origin=', url)

    def test_get_token_metadata(self):
        """Test retrieving token metadata from Keystone."""
        plugin = self._get_plugin()

        # Mock the Keystone token validation endpoint
        token_data = oidc_fixtures.UNSCOPED_TOKEN
        self.requests_mock.get(
            f'{self.AUTH_URL}/auth/tokens',
            json=token_data,
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE}
        )

        response = plugin._get_token_metadata(self.session, KEYSTONE_TOKEN_VALUE)

        self.assertEqual(token_data, response)

    @mock.patch('webbrowser.open')
    @mock.patch.object(websso, '_wait_for_token')
    def test_get_unscoped_auth_ref(self, mock_wait, mock_browser):
        """Test getting an unscoped authentication reference."""
        mock_wait.return_value = KEYSTONE_TOKEN_VALUE
        plugin = self._get_plugin()

        # Mock the Keystone token validation endpoint
        token_data = oidc_fixtures.UNSCOPED_TOKEN
        self.requests_mock.get(
            f'{self.AUTH_URL}/auth/tokens',
            json=token_data,
            headers={'X-Subject-Token': KEYSTONE_TOKEN_VALUE}
        )

        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        self.assertIsNotNone(auth_ref)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, auth_ref.auth_token)
        mock_browser.assert_called_once()

    @mock.patch('webbrowser.open')
    @mock.patch.object(websso, '_wait_for_token')
    def test_cached_token_reused(self, mock_wait, mock_browser):
        """Test that cached tokens are reused without opening browser."""
        plugin = self._get_plugin()

        # Create valid cached data
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_data = oidc_fixtures.UNSCOPED_TOKEN.copy()
        token_data['token']['expires_at'] = expires_at.strftime(
            '%Y-%m-%dT%H:%M:%S.%f%z'
        )
        cached_data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': token_data
        }
        plugin._put_cached_data(cached_data)

        # Get auth ref - should use cache
        auth_ref = plugin.get_unscoped_auth_ref(self.session)

        self.assertIsNotNone(auth_ref)
        # Browser should not have been opened
        mock_browser.assert_not_called()
        mock_wait.assert_not_called()

    @mock.patch.object(websso, '_ClientCallbackServer')
    def test_wait_for_token_success(self, mock_server_class):
        """Test _wait_for_token successfully captures token."""
        mock_server = mock.Mock()
        mock_server.token = KEYSTONE_TOKEN_VALUE
        mock_server_class.return_value = mock_server

        token = websso._wait_for_token(self.REDIRECT_HOST, self.REDIRECT_PORT)

        self.assertEqual(KEYSTONE_TOKEN_VALUE, token)
        mock_server.handle_request.assert_called_once()
        mock_server.server_close.assert_called_once()

    @mock.patch.object(websso, '_ClientCallbackServer')
    def test_wait_for_token_no_token_received(self, mock_server_class):
        """Test _wait_for_token raises error when no token is received."""
        mock_server = mock.Mock()
        mock_server.token = None
        mock_server_class.return_value = mock_server

        self.assertRaises(
            websso._MissingTokenError,
            websso._wait_for_token,
            self.REDIRECT_HOST,
            self.REDIRECT_PORT
        )

    @mock.patch.object(websso, '_ClientCallbackServer')
    def test_wait_for_token_port_in_use(self, mock_server_class):
        """Test _wait_for_token handles port already in use."""
        mock_server_class.side_effect = socket.error("Port in use")

        self.assertRaises(
            socket.error,
            websso._wait_for_token,
            self.REDIRECT_HOST,
            self.REDIRECT_PORT
        )

    def test_plugin_with_project_scope(self):
        """Test creating plugin with project scope."""
        plugin = self._get_plugin(
            project_name=self.PROJECT_NAME,
            project_domain_name='Default'
        )

        self.assertEqual(self.PROJECT_NAME, plugin.project_name)
        self.assertEqual('Default', plugin.project_domain_name)

    def test_plugin_without_cache_path_uses_default(self):
        """Test that plugin uses platform default cache when not specified."""
        plugin = websso.WebSSOOpenIDConnect(
            auth_url=self.AUTH_URL,
            identity_provider=self.IDENTITY_PROVIDER,
            protocol=self.PROTOCOL
        )

        # Should have a cache path set (platform-specific)
        self.assertIsNotNone(plugin.cache_path)
        self.assertTrue(isinstance(plugin.cache_path, Path))

    def test_set_auth_state(self):
        """Test _set_auth_state correctly sets auth_ref."""
        plugin = self._get_plugin()

        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_data = oidc_fixtures.UNSCOPED_TOKEN.copy()
        token_data['token']['expires_at'] = expires_at.strftime(
            '%Y-%m-%dT%H:%M:%S.%f%z'
        )
        data = {
            'auth_token': KEYSTONE_TOKEN_VALUE,
            'body': token_data
        }

        plugin._set_auth_state(data)

        self.assertIsNotNone(plugin.auth_ref)
        self.assertEqual(KEYSTONE_TOKEN_VALUE, plugin.auth_ref.auth_token)

    def test_set_auth_state_with_invalid_data(self):
        """Test _set_auth_state handles invalid data gracefully."""
        plugin = self._get_plugin()

        # Should not raise exception with invalid data
        plugin._set_auth_state({})
        plugin._set_auth_state({'body': None})
        plugin._set_auth_state({'auth_token': None})
