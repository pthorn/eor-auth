# coding: utf-8

import logging
log = logging.getLogger(__name__)

from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.renderers import render_to_response

from sqlalchemy.orm.exc import NoResultFound


def register_user_from_social(request, new_user_entity):
    if 'social-session' not in request.session:
        log.warn('register_user_from_social(): no social account info in user session')
        return False

    session = request.session['social-session']

    if 'twitter' in session:
        s = session['twitter']
        new_user_entity.save_twitter_session(s['user-id'], s['access-token'], s['secret'])

    if 'facebook' in session:
        s = session['facebook']
        new_user_entity.save_facebook_session(s['user-id'], s['access-token'], s['expires'])

    if 'vk' in session:
        s = session['vk']
        new_user_entity.save_vk_session(s['user-id'], s['access-token'])

    del request.session['social-session']

    return True
