# coding: utf-8

from .api import (
    acl_entry,
    request_user_confirmation,
    confirm_user,
    login_user,
    logout_user,
    authenticate_and_login_user,
    block_user,
    grant_role_to_user,
    change_user_password,
    begin_password_reset,
    reset_user_password
)
from .sessionuser import SessionUser
from .exceptions import *
#from .model import User -- TODO can't import here, config gets imported too early


def includeme(config):
    from eor_settings import ParseSettings

    from .config import config as my_config
    my_config.set_defaults()

    (ParseSettings(config.get_settings(), prefix='eor-auth')
        .bool('debug-auth', default=False)
        .string('vk-app-id', default=None)
        .string('vk-app-secret', default=None))

    _configure_authn(config)
    _configure_authz(config)

    # TODO consolidate resource factories
    from pyramid.security import authenticated_userid, Allow, Authenticated, DENY_ALL
    
    class ResourceFactory(object):
        __acl__ = [
            (Allow, Authenticated, 'auth')
        ]
        def __init__(self, request):
            pass # dynamic acl generation is possible here
    
    def add(*args, **kwargs):
        kwargs['factory'] = ResourceFactory
        return config.add_route(*args, **kwargs)

    # add('register-social',       R'/auth/register/social',            request_method=['GET', 'POST'])

    add('eor-auth.vk-login',            R'/auth/login/vk',                   request_method='GET')
    add('eor-auth.vk-login-cb',         R'/auth/login/vk-callback',          request_method='GET')

    # add('eor-auth.twitter-login',       R'/auth/login/twitter',              request_method=['GET'])
    # add('eor-auth.twitter-login-cb',    R'/auth/login/twitter-callback',     request_method=['GET'])

    add('eor-auth.facebook-login',      R'/auth/login/facebook',             request_method=['GET'])
    add('eor-auth.facebook-login-cb',   R'/auth/login/facebook-callback',    request_method=['GET'])

    config.scan('.social')


def _configure_authn(config):
    from pyramid.authentication import SessionAuthenticationPolicy
    from pyramid.events import NewRequest
    from .sessionuser import (
        get_principals_for_userid_callback,
        request_get_user,
        new_request_listener
    )

    authn_policy = SessionAuthenticationPolicy(
        callback=get_principals_for_userid_callback,
        debug=False
    )
    config.set_authentication_policy(authn_policy)

    config.add_request_method(request_get_user, 'user', reify=True)
    config.add_subscriber(new_request_listener, NewRequest)


def _configure_authz(config):
    from pyramid.authorization import ACLAuthorizationPolicy

    authz_policy = ACLAuthorizationPolicy()
    #authz_policy = ACLAuthorizationPolicy2() # TODO
    config.set_authorization_policy(authz_policy)
