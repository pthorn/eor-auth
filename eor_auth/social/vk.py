# coding: utf-8

import logging
log = logging.getLogger(__name__)

from urllib.parse import urlencode
from collections import OrderedDict

from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.view import view_config

import requests

from ..config import config
from eor_settings import get_setting

from .base import Social


class Vk(Social):
    """
    https://vk.com/dev/authcode_flow_user
    """

    def __init__(self, request):
        super().__init__(request)

        if (not get_setting('eor-auth.vk-app-id') or
            not get_setting('eor-auth.vk-app-secret')):
            log.error('Vk(): required settings not specified: eor-auth.vk-app-id, eor-auth.vk-app-secret')
            raise HTTPNotFound()

        self.access_token = None
        self.vk_user_id = None
        self.vk_login = None
        self.real_name = None
        self.email = None

    def get_user_by_social_id(self):
        return config.user_model.get_by_vk_id(self.vk_user_id)

    def save_for_user(self, user):
        user.save_vk_session(self.vk_user_id, self.access_token)

    def get_session_object(self):
        return {
            'vk': {
                'user-id': self.vk_user_id,
                'access-token': self.access_token
            },
            'login': self.vk_login,
            'email': self.email,
            'real-name': self.real_name
        }

    @view_config(route_name='eor-auth.vk-login')
    def vk_login_view(self):
        query_string = urlencode(OrderedDict(
            client_id      = get_setting('eor-auth.vk-app-id'),
            redirect_uri   = self.request.route_url('eor-auth.vk-login-cb'),
            display        = 'page',
            response_type  = 'code',
            scope          = 'status,email,wall,offline',  # https://vk.com/dev/permissions
            v              = '5.53'
        ))

        authorize_url = 'http://oauth.vk.com/authorize?' + query_string
        return HTTPFound(authorize_url)

    @view_config(route_name='eor-auth.vk-login-cb')
    def vk_login_callback_view(self):
        if 'error' in self.request.GET:
            error_code = self.request.GET.get('error', '')
            error_description = self.request.GET.get('error_description', '')

            # GET /auth/login/vk-callback
            #    ?error=access_denied
            #    &error_reason=user_denied
            #    &error_description=User+denied+your+request

            log.warn('vk_login_callback(): login error: %s, error_description: %s',
                     error_code, error_description)

            return self.handle_login_error('social-error',
                detail='%s: %s' % (error_code, error_description))

        try:
            code = self.request.GET['code']
            log.debug('vk_login_callback(): code: %s', code)
        except KeyError as e:
            log.error('vk_login_callback(): "code" parameter not present')
            return self.handle_login_error('social-error', detail='параметр "code" не передан')

        resp = requests.post(
            'https://oauth.vk.com/access_token',
            data = {
                'client_id':     get_setting('eor-auth.vk-app-id'),
                'client_secret': get_setting('eor-auth.vk-app-secret'),
                'code':          code,
                'redirect_uri':  self.request.route_url('eor-auth.vk-login-cb')
            }
        )

        try:
            json = resp.json()
        except ValueError as e:
            log.error('vk_login_callback(): /oauth/access_token: expected json, got: %s', resp.text)
            return self.handle_login_error('social-error', detail=resp.text)

        if 'access_token' in json:
            self.access_token = json['access_token']
            self.vk_user_id = str(json['user_id'])
            self.vk_login = json.get('username', '')
            self.real_name = json.get('full_name', '')
            self.email = json.get('email', '')  # TODO ?
            log.debug('vk_login_callback(): /oauth/access_token: access_token: %s, user_id: %s, resp: %s',
                self.access_token, self.vk_user_id, json)
        else:
            # {"error":"invalid_grant","error_description":"Code is invalid or expired."}
            error_code = json.get('error', '')
            error_description = json.get('error_description', '')

            log.error('vk_login_callback(): /oauth/access_token: error: %s', resp.text)
            return self.handle_login_error('social-error', detail=error_description)

        return self.on_success()
