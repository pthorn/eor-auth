# coding: utf-8

"""
security-sensitive actions on users
for use in views
"""

import logging
log = logging.getLogger(__name__)

import datetime

from pyramid.security import remember, forget

from .config import config
from .exceptions import *
from .password import generate_confirm_code


def construct_principal(object_type, permission):
    return '%s/%s' % (object_type, permission)


def acl_entry(allow_deny, object_type, permission):
    return (allow_deny, construct_principal(object_type, permission), permission)

##
## registration
##

def request_user_confirmation(request, user_entity):
    confirm_code = generate_confirm_code()
    user_entity.set_confirm_code(confirm_code)  # also sets timestamp and resets is_confirmed
    log.info('request_user_confirmation(): user %s / %s, ip %s',
             user_entity.login, user_entity.id, request.ip)
    return confirm_code


def confirm_user(request, user_entity, confirm_code, hours=48):
    if datetime.datetime.utcnow() - user_entity.confirm_time > datetime.timedelta(hours=hours):
        log.warn('confirm_user(): user %s / %s expired (> %s hours), deleting, ip %s',
                 user_entity.login, user_entity.id, hours, request.ip)
        raise ConfirmCodeExpired()

    if user_entity.confirm_code != confirm_code:
        log.error('confirm_user(): bad confirm code, user %s / %s, ip %s',
                  user_entity.login, user_entity.id, request.ip)
        raise BadConfirmCode()

    user_entity.activate_and_reset_confirm_code()
    log.info('confirm_user(): confirmed, user %s / %s, ip %s',
             user_entity.login, user_entity.id, request.ip)


##
## login / logout
##

def login_user(request, user_entity):
    """
    log user in
    note: this function does no checks!
    :param request: Pyramid request object
    :param user_entity: SQLAlchemy entity
    :return headers
    """
    # note: this automatically places the new SessionUser object into the session
    session_user = config.session_class.create_and_save_to_session(request, user_entity)

    log.info('login, user %s / %s, ip %s',
             user_entity.login, user_entity.id, request.ip)
    return remember(request, session_user.id)  # remember() is not required


def logout_user(request):
    """
    log user out, end the session
    response.headers.update(logout_user(request))
    :param request: Pyramid request object
    :return http headers
    """
    if not request.user:
        return None

    log.info('logout, user %s / %s, ip %s',
             request.user.entity.login, request.user.id, request.ip)
    request.session.invalidate()
    return forget(request)


def authenticate_and_login_user(request, user_entity, password):
    if not user_entity.check_password(password):
        log.info('login failed: bad password, user %s, ip %s' % (user_entity.login, request.ip))
        return None

    if not user_entity.can_login():
        log.info('login failed: user %s, status %s, ip %s' % (user_entity.login, user_entity.status, request.ip))
        return None

    return login_user(request, user_entity)


##
## permissions
##

def block_user():
    # TODO ?
    pass


def grant_role_to_user(user_entity):
    pass


##
## change password
##

def change_user_password(user_entity, old_password, new_password):
    if not user_entity.check_password(old_password):
        log.info('change password: bad old password, user: %s, ip: %s', request.user.id, request.ip)
        return False

    user.set_new_password(new_password)
    log.info('password changed, user: %s, ip: %s', request.user.id, request.ip)
    return True


##
## password reset
##

PASSWORD_RESET_CODE = 'eor-password-reset-code'
PASSWORD_RESET_TIMESTAMP = 'eor-password-reset-timestamp'

# TODO
def begin_password_reset(request, user_entity):
    if not user_entity.can_login():
        log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)
        return False  # TODO Exception

    request.session[PASSWORD_RESET_CODE] = generate_confirm_code()
    request.session[PASSWORD_RESET_TIMESTAMP] = datetime.datetime.utcnow()
    log.info('password reset requested, user: %s, ip: %s', request.user.id, request.ip)


def reset_user_password(request, user_entity, reset_code, new_password):
    try:
        try:
            correct_reset_code = request.session[PASSWORD_RESET_CODE]
            requested_ts = request.session[PASSWORD_RESET_TIMESTAMP]
        except KeyError:
            log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)
            return False  # TODO Exception

        if reset_code != correct_reset_code:
            log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)
            return False  # TODO Exception

        now_ts = datetime.datetime.utcnow()
        if now_ts - requested_ts > datetime.timedelta(hours=hours):
            log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)
            return False  # TODO Exception

        if not user_entity.can_login():
            log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)
            return False  # TODO Exception

        user_entity.set_new_password(new_password)
        log.info('password reset, user: %s, ip: %s', request.user.id, request.ip)

    finally:
        try:
            del request.session[PASSWORD_RESET_CODE]
            del request.session[PASSWORD_RESET_TIMESTAMP]
        except KeyError:
            pass
