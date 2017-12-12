# coding: utf-8

import logging
log = logging.getLogger(__name__)

import datetime

from sqlalchemy.orm.exc import NoResultFound

from .config import config
from .api import construct_principal


def init(config):
    from pyramid.events import NewRequest

    config.add_request_method(request_get_user, 'user', reify=True)
    config.add_subscriber(new_request_listener, NewRequest)


class SessionUser(object):
    """
    An object representing an authenticated user.

    Is placed into session in login() - TODO not updated when user details are updated
    Does not store authorization information.

    For tracking last activity time, time of last database update is stored.
     if that time is > 5 min ago, write to the database and reset it.
    """

    @classmethod
    def create_from_session(cls, request):
        """
        create and return a SessionUser object for current user, or return None
        """
        try:
            session_dict = request.session[config.session_key]
        except KeyError:
            return None

        obj = cls(session_dict)

        return obj._on_new_request(request)  # returns obj or None

    @classmethod
    def create_and_save_to_session(cls, request, user_entity):
        """
        create new SessionUser object and put it into session
        should only be called when logging user in
        """
        user_entity.update_last_login()
        user_entity.update_last_activity()

        session_dict = {
            'id': user_entity.id,
            'last_activity': datetime.datetime.utcnow()
        }

        obj = cls(session_dict)
        obj.entity = user_entity
        request.session[config.session_key] = session_dict

        return obj

    def __init__(self, session_dict):
        self.session_dict = session_dict
        self.entity = None  # populated in self._on_new_request()

    @property
    def id(self):
        return self.session_dict['id']

    @property
    def login(self):
        return self.entity.login

    def get_roles(self):
        return self.entity.roles  # TODO detach from session so they can't be changed!

    def get_role_ids(self):
        return [role.id for role in self.entity.roles]

    def has_role(self, role_id):
        return next((role for role in self.entity.roles if role.id == role_id), None) is not None

    def get_principals(self):
        perms = []
        for role in self.entity.roles:
            perms += [construct_principal(perm.object_type, perm.permission) for perm in role.permissions]

        return perms

    def has_permission(self, object_type, permission, object_id=None):
        # TODO object id
        for role in self.entity.roles:
            for perm in role.permissions:
                if perm.object_type == object_type and perm.permission == permission:
                    return True

        return False

    def _on_new_request(self, request):
        """
        called only from SessionUser.create_from_session()
        """
        try:
            self.entity = config.user_model.get_by_id_with_permissions(self.session_dict['id'])
        except NoResultFound:
            log.warn('user entity %s not found, logging out', self.session_dict['id'])
            request.session.invalidate()
            return None

        if not self.entity.can_login():
            log.warn('user entity %s (%s) not allowed to login, logging out', self.entity.id, self.entity.login)
            request.session.invalidate()
            return None

        self._update_activity()
        self.entity.eor_auth_flush_and_expunge()

        return self

    def _update_activity(self):
        """
        update last activity time in database if it's older than n minutes
        """
        if (datetime.datetime.utcnow() - self.session_dict['last_activity'] >
           datetime.timedelta(minutes=config.activity_update_min)):
            log.debug('update_activity(), id %s', self.id)
            self.entity.update_last_activity()
            self.session_dict['last_activity'] = datetime.datetime.utcnow()
            # TODO session.changed()!


    def __unicode__(self):
        return u'SessionUser(id={id}, email={email}, real_name={real_name}'.format(
            id = self.id,
            email = self.email,
            real_name = self.real_name
        )


def request_get_user(request):
    """
    reified property request.user
    """
    return config.session_class.create_from_session(request)


def new_request_listener(event):
    """
    NewRequest listener
    http://docs.pylonsproject.org/docs/pyramid/en/1.5-branch/api/events.html#pyramid.events.NewRequest
    """
    user = event.request.user
