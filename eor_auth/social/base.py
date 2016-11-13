# coding: utf-8

import logging
log = logging.getLogger(__name__)

from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.renderers import render_to_response

from sqlalchemy.orm.exc import NoResultFound

from ..config import config


class Social(object):
    def __init__(self, request):
        self.request = request
        self.delegate = config.social_delegate(self)

    def get_user_by_social_id(self):
        raise NotImplementedError()

    def save_for_user(self, user):
        raise NotImplementedError()

    def get_session_object(self):
        raise NotImplementedError()

    def on_success(self):
        if self.request.user:
            return self.connect_account()
        else:
            return self.login_or_register()

    def connect_account(self):
        user = self.request.user.entity

        try:
            user2 = self.get_user_by_social_id()  # TODO
            if user != user2:
                log.warn('other user already has this social id: user: %s, other user: %s',
                         self.request.user.id, user2.id)
                return self.handle_login_error('other-user-has-same-social-id')
        except NoResultFound:
            pass

        self.save_for_user(user)
        log.info('added social account for user %s', user.id)

        return self.delegate.on_connected_account(user)

    def login_or_register(self):
        try:
            user = self.get_user_by_social_id()
        except NoResultFound:
            # no user with this social id -> save data to session
            # and display registration form
            self.request.session['social-session'] = self.get_session_object()
            return self.delegate.on_register()

        if not user.can_login():
            return self.handle_login_error('bad-login')

        self.save_for_user(user)
        log.info('login via social network, user %s, ip %s', user.id, self.request.ip)

        return self.delegate.on_logged_in(user)

    def handle_login_error(self, message_id, detail=None):
        return self.delegate.on_login_error(message_id, detail)
