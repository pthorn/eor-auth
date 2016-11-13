# coding: utf-8

import logging
log = logging.getLogger(__name__)

from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.renderers import render_to_response

from ..api import login_user


class SocialDelegate(object):

    def __init__(self, views):
        self.views = views
        self.request = self.views.request

    def on_logged_in(self, user):
        # add_flash_message(self.request, 'logged-in')
        return self.redirect_after_login(headers=login_user(self.request, user))

    def on_login_error(self, message_id, detail=None):
        # add_flash_message(self.request, message_id, detail=detail)
        return HTTPFound(location=self.request.route_path('login'))

    def on_connected_account(self, user):
        # add_flash_message(self.request, 'added-social-account')
        return self.redirect_after_login()

    def on_register(self):
        return HTTPFound(self.request.route_path('register-social'))

    def redirect_after_login(self, headers=None):
        path = self.request.session.get('after-login', '/')

        try:
            del self.request.session['after-login']
        except KeyError:
            pass

        return HTTPFound(location=path, headers=headers)


class SocialDelegateXHR(object):

    def __init__(self, views):
        self.views = views

    def on_logged_in(self, user):
        resp = render_to_response('eor_auth.social:templates/callback-response.mako', {
            'status': 'logged-in',
            'data': {
                'id': user.id,
                'login': user.login,
                'name': user.name,
                'roles': {},  # TODO
                'csrf_token': self.request.session.new_csrf_token()
            }
        }, request=self.request)
        resp.headers.update(login_user(self.request, user))
        return resp

    def on_login_error(self, message_id, detail=None):
        return render_to_response('eor_auth.social:templates/callback-response.mako', {
            'status': 'error',
            'message': message_id,
            'detail': detail
        }, request=self.request)

    def on_register(self):
        return render_to_response('eor_auth.social:templates/callback-response.mako', {
            'status': 'registration',
            'data': self.get_session_object()  # TODO
        }, request=self.request)
