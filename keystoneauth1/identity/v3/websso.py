# Copyright 2016 Spanish National Research Council
# Copyright 2016 INDIGO-DataCloud
# Copyright 2026 Rackspace Technology, Inc.
#
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

"""Keystone WebSSO authentication plugin.

Keystone's WebSSO endpoint delegates authentication to a browser. This plugin
opens the endpoint in the user's browser, listens on a loopback port for the
form POST that Keystone makes once the identity provider has authenticated the
user, and turns the token in that POST into an unscoped ``AccessInfo``.

The unscoped token is cached on disk so that rescoping to a different project
does not require authenticating in a browser again.

WebSSO is not a standardised protocol. Keystone defined it so that Horizon
could authenticate users against an external identity provider, and modelled
it on the SAML 2.0 Web Browser SSO Profile: as in that profile's HTTP POST
binding, the identity service returns an auto-submitting HTML form which posts
the credential to a pre-registered, trusted origin. Because Keystone compares
that origin against its ``[federation] trusted_dashboard`` list verbatim, the
callback path and default port used here are the ones given in the Horizon and
Keystone federation installation guides rather than values of our choosing.

.. warning::

   The callback is open to login CSRF and cannot be closed to it. While the
   listener is running, any page open in the user's browser can submit a form
   to the callback port and have its own Keystone token accepted, which would
   leave the user operating as whoever obtained that token.

   Nothing in the request distinguishes such a submission from Keystone's. The
   Fetch Metadata headers of a scripted cross-origin form submission are
   identical to those of Keystone's auto-submitted form, and on the https to
   http callback that this flow relies on the Fetch standard serializes
   ``Origin`` as ``null`` and drops ``Referer`` for both.

   Binding the callback to the request it belongs to would need a nonce in the
   ``origin`` parameter, and there is nowhere to put one: Keystone requires
   that parameter to match a ``trusted_dashboard`` entry exactly, so it cannot
   carry per-request data. The window is limited instead: the listener binds to
   loopback only, runs only while a login is in progress, stops at the first
   token it accepts, and times out.
"""

import hashlib
import ipaddress
import json
import os
import pathlib
import socket
import sys
import time
import typing as ty
import urllib.parse
import webbrowser
import wsgiref.simple_server

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session

if ty.TYPE_CHECKING:
    # wsgiref.types is new in Python 3.11 and is only needed to annotate
    # the callback application, so it is not imported at runtime.
    import wsgiref.types

_logger = utils.get_logger(__name__)

__all__ = ('WebSSO',)

# Keystone renders a form that POSTs the token to the ``origin`` URL, and
# ``origin`` has to match an entry in the server's ``[federation]
# trusted_dashboard`` list verbatim. Neither the path nor the query string can
# therefore vary between deployments.
_CALLBACK_PATH = '/auth/websso/'

_DEFAULT_REDIRECT_HOST = 'localhost'
_DEFAULT_REDIRECT_PORT = 9990

# How long to wait for the user to complete authentication in their browser.
_DEFAULT_TIMEOUT = 60

# The body only ever carries a single Keystone token, so anything remotely
# large is not something we sent the user to fetch.
_MAX_CALLBACK_BODY = 64 * 1024

_FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded'

#: Reuse a cached unscoped token when one is available.
CACHE_REUSE = 'reuse'
#: Discard any cached token, authenticate again, and cache the result. Use
#: this when the cached token is known to be bad.
CACHE_REFRESH = 'refresh'
#: Neither read nor write the cache.
CACHE_DISABLED = 'disabled'

#: Accepted values for the ``token_cache`` argument. None of these are words
#: that YAML reads as booleans, so they survive a ``clouds.yaml`` round trip.
CACHE_MODES = (CACHE_REUSE, CACHE_REFRESH, CACHE_DISABLED)

_SUCCESS_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Authentication complete</title>
    <script>window.close()</script>
  </head>
  <body>
    <p>Authentication is complete. You can close this window.</p>
  </body>
</html>
"""

_FAILURE_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Authentication failed</title>
  </head>
  <body>
    <p>This request was rejected. You can close this window.</p>
  </body>
</html>
"""


class _MissingTokenError(exceptions.AuthPluginException):
    """Keystone never delivered a token to the callback listener."""

    message = "Could not get a token from the WebSSO callback."


def _origin(url: str) -> str:
    """Reduce a URL to its scheme and authority, lowercased."""
    parsed = urllib.parse.urlsplit(url)
    return f'{parsed.scheme}://{parsed.netloc}'.lower()


def _default_cache_dir() -> pathlib.Path:
    """Return the platform specific directory for the token cache."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or '~/AppData/Local'
    elif sys.platform == 'darwin':
        base = '~/Library/Caches'
    else:
        base = os.environ.get('XDG_CACHE_HOME') or '~/.cache'

    return pathlib.Path(base).expanduser() / 'keystoneauth' / 'websso'


def _assert_loopback(host: str) -> None:
    """Check that ``host`` only resolves to loopback addresses.

    The callback receives an unscoped Keystone token in a plain HTTP request,
    so the listener must not be reachable from another machine.
    """
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise exceptions.OptionError(
            f'Could not resolve the redirect host {host!r}.'
        )

    for info in addresses:
        # Strip any IPv6 zone index before parsing.
        address = str(info[4][0]).partition('%')[0]
        if not ipaddress.ip_address(address).is_loopback:
            raise exceptions.OptionError(
                f'The redirect host {host!r} resolves to the non-loopback '
                f'address {address}. The WebSSO callback receives an '
                f'unscoped token and must not be exposed on a network '
                f'interface.'
            )


class _CallbackApp:
    """WSGI application that receives Keystone's WebSSO form POST.

    Accepts exactly one well formed POST and records the token from it. The
    listener is bound to a port that any page in the user's browser can post
    to, and nothing in the request proves it came from Keystone, so see the
    note on login CSRF in the module docstring.
    """

    def __init__(self, keystone_origin: str):
        self.token: str | None = None
        self._keystone_origin = keystone_origin

    def __call__(
        self,
        environ: 'wsgiref.types.WSGIEnvironment',
        start_response: 'wsgiref.types.StartResponse',
    ) -> list[bytes]:
        status, page = self._handle(environ)
        body = page.encode('utf-8')
        start_response(
            status,
            [
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Content-Length', str(len(body))),
            ],
        )
        return [body]

    def _handle(
        self, environ: 'wsgiref.types.WSGIEnvironment'
    ) -> tuple[str, str]:
        if environ.get('PATH_INFO') != _CALLBACK_PATH:
            return '404 Not Found', _FAILURE_HTML

        if environ.get('REQUEST_METHOD') != 'POST':
            return '405 Method Not Allowed', _FAILURE_HTML

        content_type = str(environ.get('CONTENT_TYPE', ''))
        if content_type.split(';')[0].strip().lower() != _FORM_MEDIA_TYPE:
            return '415 Unsupported Media Type', _FAILURE_HTML

        try:
            length = int(str(environ.get('CONTENT_LENGTH', '')))
        except ValueError:
            return '411 Length Required', _FAILURE_HTML

        if length < 0:
            return '411 Length Required', _FAILURE_HTML

        if length > _MAX_CALLBACK_BODY:
            return '413 Content Too Large', _FAILURE_HTML

        rejection = self._check_request_shape(environ)
        if rejection is not None:
            return rejection

        body = environ['wsgi.input'].read(length)
        fields = urllib.parse.parse_qs(body.decode('utf-8', 'replace'))
        token = next(iter(fields.get('token', [])), '')
        if not token:
            return '400 Bad Request', _FAILURE_HTML

        if self.token is not None:
            return '409 Conflict', _FAILURE_HTML

        self.token = token
        return '200 OK', _SUCCESS_HTML

    def _check_request_shape(
        self, environ: 'wsgiref.types.WSGIEnvironment'
    ) -> tuple[str, str] | None:
        """Reject requests that do not look like Keystone's callback.

        These checks narrow what reaches the token handling below. None of
        them identify the sender: a page can submit a form to this port and
        produce the same request shape Keystone does. See the note on login
        CSRF in the module docstring.
        """
        # Keystone's callback template auto-submits a form, so its POST always
        # arrives as a top-level document navigation. Requiring that rejects
        # fetch() and XMLHttpRequest, which would otherwise reach us because a
        # form content type makes them "simple" cross-origin requests that need
        # no preflight.
        if environ.get('HTTP_SEC_FETCH_MODE') != 'navigate':
            _logger.debug('Rejected callback: not a navigation request')
            return '400 Bad Request', _FAILURE_HTML

        if environ.get('HTTP_SEC_FETCH_DEST') != 'document':
            _logger.debug('Rejected callback: not a document request')
            return '400 Bad Request', _FAILURE_HTML

        # 'none' means the user navigated here directly, which Keystone's
        # cross-site form post never does.
        if environ.get('HTTP_SEC_FETCH_SITE') == 'none':
            _logger.debug('Rejected callback: not a cross-site request')
            return '400 Bad Request', _FAILURE_HTML

        # A cross-origin POST navigation carries an Origin, but per the Fetch
        # standard it is serialized as 'null' when the referrer policy would
        # strip the referrer, which includes the https to http downgrade this
        # callback relies on. So a genuine POST from an HTTPS Keystone gives us
        # 'null' and we have to accept it. A real origin that is not Keystone's
        # cannot be genuine, though, so reject that.
        origin = environ.get('HTTP_ORIGIN')
        if origin not in (None, 'null') and (
            _origin(str(origin)) != self._keystone_origin
        ):
            _logger.debug('Rejected callback: unexpected origin')
            return '400 Bad Request', _FAILURE_HTML

        # The Referer is stripped outright on that same downgrade, so it is
        # normally absent. Check it only when the browser sends one.
        referer = environ.get('HTTP_REFERER')
        if referer and _origin(str(referer)) != self._keystone_origin:
            _logger.debug('Rejected callback: unexpected referer')
            return '400 Bad Request', _FAILURE_HTML

        return None


class _QuietWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """Request handler that keeps its access log off stderr."""

    def log_message(self, format: str, *args: ty.Any) -> None:
        """Do not log requests to stderr."""


def _wait_for_token(
    redirect_host: str,
    redirect_port: int,
    keystone_origin: str,
    start_flow: ty.Callable[[], None],
    timeout: float = _DEFAULT_TIMEOUT,
) -> str:
    """Serve the callback endpoint until Keystone posts a token to it.

    ``start_flow`` is called once the callback port is listening, and is what
    sends the user into the flow.
    """
    _assert_loopback(redirect_host)

    app = _CallbackApp(keystone_origin)
    try:
        httpd = wsgiref.simple_server.make_server(
            redirect_host,
            redirect_port,
            app,
            handler_class=_QuietWSGIRequestHandler,
        )
    except OSError:
        _logger.error(
            'Cannot spawn the callback server on port %s, please specify a '
            'different port.',
            redirect_port,
        )
        raise

    with httpd:
        # Start the flow only now that the socket is bound and listening.
        # Keystone posts the token back as soon as the identity provider is
        # done, which with an established session can be before this function
        # would otherwise have got as far as accepting connections. There is
        # only one callback, so losing it means losing the login.
        start_flow()

        # handle_request() returns after any single request, including the ones
        # we reject, so keep serving until a token turns up or time runs out.
        deadline = time.monotonic() + timeout
        while app.token is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            httpd.timeout = remaining
            httpd.handle_request()

    if not app.token:
        raise _MissingTokenError()

    return app.token


class WebSSO(federation.FederationBaseAuth):
    """Authenticate using Keystone's browser based WebSSO flow.

    The user is sent to Keystone's WebSSO endpoint in their browser and
    authenticates there against the configured identity provider. Keystone
    then posts the resulting unscoped token back to a listener this plugin
    runs on a loopback port.

    The callback URL, ``http://<redirect_host>:<redirect_port>/auth/websso/``,
    must appear verbatim in the server's ``[federation] trusted_dashboard``
    list or Keystone refuses to complete the flow.
    """

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        *,
        redirect_host: str = _DEFAULT_REDIRECT_HOST,
        redirect_port: int = _DEFAULT_REDIRECT_PORT,
        cache_path: str | None = None,
        token_cache: str = CACHE_REUSE,
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
        self.redirect_host = redirect_host
        self.redirect_port = int(redirect_port)
        self.redirect_uri = (
            f'http://{self.redirect_host}:{self.redirect_port}{_CALLBACK_PATH}'
        )
        if token_cache not in CACHE_MODES:
            raise exceptions.OptionError(
                f'token_cache must be one of '
                f'{", ".join(CACHE_MODES)}, not {token_cache!r}.'
            )

        self.token_cache = token_cache
        self._cache_refreshed = False
        self.cache_path = (
            pathlib.Path(cache_path).expanduser()
            if cache_path
            else _default_cache_dir()
        )

    def invalidate(self) -> bool:
        """Discard the current token, including any cached copy of it.

        A session calls this when a request comes back unauthorized, so the
        cached copy has to go as well. Leaving it would mean the token that was
        just rejected is read straight back in and the retry fails the same
        way, with nothing to break the cycle until the token expires.
        """
        invalidated = super().invalidate()

        if self.token_cache != CACHE_DISABLED:
            try:
                self._cache_file().unlink()
            except OSError:
                pass
            else:
                invalidated = True

        return invalidated

    @property
    def _base_url(self) -> str:
        """The versioned root of the identity service."""
        host = self.auth_url.rstrip('/')
        if not host.endswith('v3'):
            host += '/v3'
        return host

    @property
    def federated_token_url(self) -> str:
        """URL that starts the WebSSO flow."""
        return (
            f'{self._base_url}/auth/OS-FEDERATION/identity_providers/'
            f'{self.identity_provider}/protocols/{self.protocol}/websso'
        )

    def _get_auth_token(self) -> str:
        """Send the user to their browser and wait for the token."""
        query = urllib.parse.urlencode({'origin': self.redirect_uri})
        url = f'{self.federated_token_url}?{query}'

        def open_browser() -> None:
            # Always show the URL. webbrowser.open() reports success whenever
            # it finds something to launch, which is not the same as the user
            # ending up on the page: xdg-open can exit zero having done
            # nothing, and over a remote shell the browser it picks may not be
            # one the user can see. This goes to the log, and so to standard
            # error, rather than standard output, where it would corrupt
            # machine readable output.
            _logger.warning('To authenticate please go to: %s', url)

            if not webbrowser.open(url, new=0):
                _logger.warning('A browser could not be opened for you.')

        return _wait_for_token(
            self.redirect_host,
            self.redirect_port,
            _origin(self.auth_url),
            open_browser,
        )

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Return an unscoped token, authenticating in a browser if needed.

        A cached unscoped token is reused when one is available, so that
        rescoping to a different project does not send the user back to their
        browser. Keystone only tells us the token itself, so the token is
        validated against the identity service to pick up its expiry and
        catalog.
        """
        cached = self._load_cached_auth_ref()
        if cached is not None:
            return cached

        auth_token = self._get_auth_token()

        response = session.get(
            f'{self._base_url}/auth/tokens',
            headers={
                'X-Auth-Token': auth_token,
                'X-Subject-Token': auth_token,
            },
            authenticated=False,
        )
        auth_ref = access.create(body=response.json(), auth_token=auth_token)
        if not isinstance(auth_ref, access.AccessInfoV3):
            raise exceptions.InvalidResponse(response=response)

        self._save_cached_auth_ref(auth_ref)

        return auth_ref

    def _cache_file(self) -> pathlib.Path:
        """Return the file the unscoped token for this identity is cached in.

        The scope is deliberately not part of the key. The cached token is
        unscoped, so one browser login can be rescoped to any project the
        user has access to.
        """
        digest = hashlib.sha256()
        for element in (
            self.auth_url.rstrip('/'),
            self.identity_provider,
            self.protocol,
        ):
            digest.update(element.encode('utf-8'))
            # Terminate each element so that the elements cannot be read out
            # of the hash input in more than one way. Without this, an
            # identity provider named 'foo' with protocol 'bar' would share a
            # cache file with one named 'foob' using protocol 'ar'. A null
            # byte is safe as the terminator because none of the elements, a
            # URL and two identity service resource names, can contain one.
            digest.update(b'\x00')

        return self.cache_path / f'{digest.hexdigest()}.json'

    def _load_cached_auth_ref(self) -> access.AccessInfoV3 | None:
        """Return a usable cached unscoped token, if there is one.

        Deliberately does not touch ``auth_ref``: while reauthenticating that
        still holds the previous, possibly scoped, token and overwriting it
        here would hide the fact that we need to authenticate again.
        """
        if self.token_cache == CACHE_DISABLED:
            return None

        path = self._cache_file()

        if self.token_cache == CACHE_REFRESH and not self._cache_refreshed:
            # The caller has told us the cached token is no good. Drop it
            # rather than just skipping it, so that a failure later on cannot
            # fall back to it. Only once per plugin: the replacement we are
            # about to fetch is fine to reuse.
            self._cache_refreshed = True
            _logger.debug('Discarding the cached token in %s on request', path)
            path.unlink(missing_ok=True)
            return None

        try:
            state = path.read_text(encoding='utf-8')
        except OSError:
            return None

        auth_ref = None
        try:
            # The same representation that get_auth_state() produces.
            data = json.loads(state)
            auth_ref = access.create(
                body=data['body'], auth_token=data['auth_token']
            )
        except (ValueError, KeyError, TypeError):
            # A damaged cache must never stop us authenticating.
            _logger.debug('Ignoring unreadable token cache %s', path)

        if not isinstance(auth_ref, access.AccessInfoV3):
            auth_ref = None
        elif auth_ref.will_expire_soon(self.MIN_TOKEN_LIFE_SECONDS):
            auth_ref = None

        if auth_ref is None:
            path.unlink(missing_ok=True)

        return auth_ref

    def _save_cached_auth_ref(self, auth_ref: access.AccessInfoV3) -> None:
        """Write an unscoped token to the cache."""
        if self.token_cache == CACHE_DISABLED:
            return

        # Mirrors get_auth_state() so that the two remain interchangeable.
        state = json.dumps(
            {'auth_token': auth_ref.auth_token, 'body': auth_ref._data}
        )

        path = self._cache_file()
        try:
            self.cache_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Create the file 0600 up front. Writing it and adjusting the mode
            # afterwards would leave the token readable for a moment.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, 'w', encoding='utf-8') as f:
                f.write(state)
        except OSError:
            _logger.warning('Could not write the token cache %s', path)
