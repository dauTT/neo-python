"""
This module contains methods and classes which are needed for implementing Basic HTTP authentication
with the twisted framework.

See also:
* https://zodml.org/sites/default/files/Twisted_Network_Programming_Essentials.pdf (pag 81, authentication)
* https://twistedmatrix.com/documents/16.4.1/web/howto/web-in-60/http-auth.html
* https://twistedmatrix.com/documents/17.5.0/core/howto/cred.html

"""

from twisted.web import resource, guard
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.portal import IRealm, Portal
from zope.interface import Interface, implementer
from twisted.cred.checkers import ANONYMOUS, AllowAnonymousAccess
from twisted.web.resource import Resource
from zope.interface import implements
from twisted.internet.defer import succeed, fail
from twisted.cred.error import UnauthorizedLogin
from twisted.cred import error
from twisted.internet.defer import Deferred

from neo.api.JSONRPC.ExtendedJsonRpcApi import ExtendedJsonRpcApi, ExtendedJsonRpcApiAuth
from neo.Wallets.utils import to_aes_key

from neo.api.utils import LimitedSizeDict
import time


@implementer(IRealm)
class HTTPAuthRealm(object):

    def __init__(self, port_rpc, wallet):
        self.port_rpc = port_rpc
        self.wallet = wallet 

    def requestAvatar(self, avatarId, mind, *interfaces):

        if avatarId is not ANONYMOUS:
            api_server_rpc = ExtendedJsonRpcApiAuth(self.port_rpc, wallet=self.wallet)
        else:
            api_server_rpc = ExtendedJsonRpcApi(self.port_rpc, wallet=self.wallet)

        avatar = api_server_rpc.app.resource()

        return resource.IResource, avatar, lambda: None


@implementer(ICredentialsChecker)
class BasicUserPassCredentialChecker(object):
    credentialInterfaces = (IUsernamePassword,)

    # The following OrderedDict only track the errors of the most recent 100 users
    consecutive_errors_history = LimitedSizeDict(size_limit=100)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def backoff(self, n: int, t: float):
        time.sleep(t * 2 ** (n - 1))

    def get_consecutive_errors(self, username): 
        consecutive_errors = self.consecutive_errors_history.get(username)
        if consecutive_errors:
            if consecutive_errors < 100:
                consecutive_errors += 1
                self.consecutive_errors_history[username] = consecutive_errors
        else:
            consecutive_errors = 1
            self.consecutive_errors_history[username] = consecutive_errors
        return consecutive_errors

    def requestAvatarId(self, credentials):
        for interface in self.credentialInterfaces:
            if interface.providedBy(credentials):
                break
            else:
                raise error.UnhandledCredentials()

        if (credentials.username.decode("utf-8") == self.username and to_aes_key(credentials.password.decode("utf-8")) == self.password):

            return succeed(credentials.username)
        else:
            consecutive_errors = self.get_consecutive_errors(credentials.username.decode("utf-8"))
            self.backoff(consecutive_errors, 2)

            return fail(UnauthorizedLogin("Invalid username or password"))


def guard_resource_with_http_auth(credentialChecker, port_rpc, wallet):

    checkers = [credentialChecker, AllowAnonymousAccess()]

    credentialFactory = guard.BasicCredentialFactory('auth')

    resource = guard.HTTPAuthSessionWrapper(Portal(HTTPAuthRealm(port_rpc, wallet), checkers),
                                            [credentialFactory]
                                            )

    return resource
