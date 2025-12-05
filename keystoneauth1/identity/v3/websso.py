# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""OpenID Connect Web SSO authentication plugin.

This plugin implements web-based Single Sign-On (SSO) authentication using
OpenID Connect. It opens a browser for the user to authenticate with their
Identity Provider, then captures the resulting token via a local callback
server.

Based on the keystoneauth-websso plugin originally developed by:
- Spanish National Research Council
- INDIGO-DataCloud
"""

import json
import re
import socket
import webbrowser
from datetime import datetime
from datetime import timezone
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from pathlib import Path

import multipart
from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session

_logger = utils.get_logger(__name__)

__all__ = ('WebSSOOpenIDConnect',)


class _MissingTokenError(exceptions.AuthPluginException):
    """Could not get the authentication token."""

    message = "Could not get the token."


class _ClientCallbackServer(HTTPServer):
    """HTTP server to handle the OpenID Connect callback to localhost.

    This server will wait for a single request, storing the access_token
    obtained from the incoming request into the 'token' attribute.
    """

    token: str | None = None

    def server_bind(self) -> None:
        """Override original bind and set a timeout.

        Authentication may fail and we could get stuck here forever, so this
        method sets up a sane timeout.
        """
        # NOTE: cannot call super here, as HTTPServer does not have
        # object as an ancestor in some Python versions
        HTTPServer.server_bind(self)
        self.socket.settimeout(60)


class _ClientCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the OpenID Connect redirect callback.

    The OpenID Connect authorization code grant type is a redirection based
    flow where the client needs to be capable of receiving incoming requests
    (via redirection), where the access code will be obtained.

    This class implements a request handler that will process a single request
    and store the obtained code into the server's 'token' attribute.
    """

    def do_POST(self) -> None:
        """Handle a POST request and obtain an authorization token.

        This method will process the form data and extract the token
        from the completed mod_auth_openidc session.
        """
        if self.headers:
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_LENGTH": self.headers["Content-Length"],
                "CONTENT_TYPE": self.headers["Content-Type"],
                "wsgi.input": self.rfile,
            }
            forms, files = multipart.parse_form_data(environ)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Authentication Status OK</title>"
                b"<script>window.close()</script></head>"
                b"<body><p>The authentication flow has been completed.</p>"
                b"<p>You can close this window.</p>"
                b"</body></html>"
            )

            # Extract token from form data
            if "token" in forms:
                assert isinstance(self.server, _ClientCallbackServer)
                self.server.token = forms["token"]
        else:
            self.send_response(501)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Authentication Status Failed</title></head>"
                b"<body><p>The authentication flow failed.</p>"
                b"<p>You can close this window.</p>"
                b"</body></html>"
            )


def _wait_for_token(redirect_host: str, redirect_port: int) -> str:
    """Spawn an HTTP server and wait for the auth_token.

    :param redirect_host: The hostname where the authorization request will
                          be redirected. This normally is localhost. This
                          indicates the hostname where the callback http
                          server will listen.
    :type redirect_host: str

    :param redirect_port: The port where the authorization request will
                          be redirected. This indicates the port where the
                          callback http server will bind to.
    :type redirect_port: int

    :returns: The authentication token
    :rtype: str

    :raises _MissingTokenError: If token could not be obtained
    """
    server_address = (redirect_host, redirect_port)
    try:
        httpd = _ClientCallbackServer(server_address, _ClientCallbackHandler)
    except socket.error:
        _logger.error(
            "Cannot spawn the callback server on port "
            "%s, please specify a different port.",
            redirect_port,
        )
        raise

    # This will trigger _ClientCallbackHandler
    httpd.handle_request()
    httpd.server_close()

    if httpd.token:
        return httpd.token
    else:
        raise _MissingTokenError()


class WebSSOOpenIDConnect(federation.FederationBaseAuth):
    """Implementation for OpenID Connect Web SSO authentication.

    This plugin authenticates users through a web browser using OpenID Connect.
    It opens the user's default browser to the Identity Provider's login page,
    waits for authentication to complete via a local callback server, and then
    uses the resulting token to authenticate with Keystone.
    """

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        redirect_host: str = "localhost",
        redirect_port: int = 9990,
        cache_path: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
    ):
        """Initialize the OpenID Connect Web SSO plugin.

        :param auth_url: URL of the Identity Service
        :type auth_url: str

        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against. This parameter
                                  will be used to build a dynamic URL used to
                                  obtain unscoped OpenStack token.
        :type identity_provider: str

        :param protocol: Name of the protocol the client will authenticate
                         against.
        :type protocol: str

        :param redirect_host: The hostname where the authorization request will
                              be redirected. This normally is localhost. This
                              indicates the hostname where the callback http
                              server will listen.
        :type redirect_host: str

        :param redirect_port: The port where the authorization request will
                              be redirected. This indicates the port where the
                              callback http server will bind to.
        :type redirect_port: int

        :param cache_path: Directory path where token cache will be stored.
                           If not provided, uses platform-specific cache dir.
        :type cache_path: str
        """
        super().__init__(
            auth_url,
            identity_provider,
            protocol,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
        )
        if cache_path:
            self.cache_path = Path(cache_path)
        else:
            # Use platform-specific cache directory
            import platformdirs

            self.cache_path = Path(platformdirs.user_cache_dir('keystoneauth1'))

        self.redirect_host = redirect_host
        self.redirect_port = int(redirect_port)
        self.redirect_uri = f"http://{self.redirect_host}:{self.redirect_port}/auth/websso/"

    @property
    def federated_token_url(self) -> str:
        """URL where websso auth flow is started."""
        host = self.auth_url.rstrip("/")
        if not host.endswith("v3"):
            host += "/v3"
        values = {
            "host": host,
            "identity_provider": self.identity_provider,
            "protocol": self.protocol,
        }
        url = (
            "%(host)s/auth/OS-FEDERATION/identity_providers/"
            "%(identity_provider)s/protocols/%(protocol)s/websso"
        )
        url = url % values

        return url

    def _get_auth_token(self) -> str:
        """Spawn a browser session to start the authentication process.

        The user will be redirected to identity provider to sign in. Then a
        token will be generated and returned.

        :returns: Authentication token
        :rtype: str
        """
        webbrowser.open(
            self.federated_token_url + "?origin=" + self.redirect_uri, new=0
        )

        return _wait_for_token(self.redirect_host, self.redirect_port)

    def _get_token_metadata(
        self, session: ks_session.Session, auth_token: str
    ) -> dict[str, object]:
        """Use the keystone auth_token to get the token metadata.

        This includes information such as expiration time.

        :param session: A session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :param auth_token: The authentication token
        :type auth_token: str

        :returns: Response containing token metadata
        :rtype: dict
        """
        host = self.auth_url.rstrip("/")
        if not host.endswith("v3"):
            host += "/v3"

        headers = {"X-Auth-Token": auth_token, "X-Subject-Token": auth_token}

        response = session.get(
            host + "/auth/tokens", headers=headers, authenticated=False
        )
        return response.json()

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate with OpenID Connect Identity Provider.

        This is a multi-step process:

        1. Send user to a web browser to authenticate. User will be redirected
           to a local webserver so an auth_token can be captured

        2. Use the auth_token to get additional token metadata

        3. Cache token data and use cached data on subsequent calls

        Note: Cache filename is based on auth_url and identity_provider only
        as an unscoped token can then be cached for the user.

        :param session: A session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: A token data representation
        :rtype: :py:class:`keystoneauth1.access.AccessInfoV3`
        """
        cached_data = self._get_cached_data()

        if cached_data:
            self._set_auth_state(cached_data)

        if self.auth_ref is None:
            # Start Auth Process and get Keystone Auth Token
            auth_token = self._get_auth_token()

            # Use auth token to get token metadata
            response = self._get_token_metadata(session, auth_token)

            # Cache token and token metadata
            data = {"auth_token": auth_token, "body": response}
            self._put_cached_data(data)

            # Set auth_ref
            self._set_auth_state(data)

        assert isinstance(self.auth_ref, access.AccessInfoV3)  # nosec B101
        return self.auth_ref

    def _get_cached_data(self) -> dict[str, object] | None:
        """Get cached token data if available and not expired.

        :returns: Cached token data or None
        :rtype: dict or None
        """
        cache_path = self._get_cache_path()

        if cache_path.exists():
            with cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not self._token_expired(data):
                return data
        return None

    def _put_cached_data(self, data: dict[str, object]) -> None:
        """Write cache data to file.

        :param data: Token data to cache
        :type data: dict
        """
        if not self.cache_path.exists():
            self.cache_path.mkdir(parents=True)

        cache_path = self._get_cache_path()
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(data, f)

        # Set file permissions to user-only read/write
        cache_path.chmod(0o600)

    def _get_cache_path(self) -> Path:
        """Retrieve the location of the session cache.

        :returns: Path for the cache file
        :rtype: Path
        """
        return self.cache_path / self._get_cache_id()

    def _get_cache_id(self) -> str:
        """Generate cache filename from auth_url and identity provider.

        :returns: Cache filename
        :rtype: str
        """
        return "os-" + re.sub(
            "[^A-Za-z0-9-]+", "-", self.auth_url + "-" + self.identity_provider
        )

    def _token_expired(self, data: dict[str, object]) -> bool:
        """Check to see if the token is expired.

        :param data: Token data including expiration information
        :type data: dict

        :returns: True if expired, False otherwise
        :rtype: bool
        """
        body = data.get("body")
        if not isinstance(body, dict):
            return True

        token = body.get("token")
        if not isinstance(token, dict):
            return True

        expires_at = token.get("expires_at")
        if not isinstance(expires_at, str):
            return True

        expiration = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%f%z")
        now = datetime.now(timezone.utc)
        return expiration < now

    def _set_auth_state(self, data: dict[str, object]) -> None:
        """Set authentication state from cached data.

        :param data: Cached token data
        :type data: dict
        """
        body = data.get("body")
        if not isinstance(body, dict):
            return

        # Create a mock response object for access.create()
        class _MockResponse:
            def __init__(self, json_data: dict[str, object], token: str):
                self._json = json_data
                self.headers = {"X-Subject-Token": token}

            def json(self) -> dict[str, object]:
                return self._json

        auth_token = data.get("auth_token")
        if isinstance(auth_token, str):
            mock_resp = _MockResponse(body, auth_token)
            self.auth_ref = access.create(resp=mock_resp)
