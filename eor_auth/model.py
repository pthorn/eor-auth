# coding: utf-8

import logging
log = logging.getLogger(__name__)

import datetime
import uuid

from sqlalchemy import Column
from sqlalchemy.schema import Table, ForeignKey, FetchedValue
from sqlalchemy.types import Integer, Unicode, Float, Boolean, Date, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, backref, joinedload, joinedload_all, contains_eager
from sqlalchemy.sql import and_, or_, not_, text
from sqlalchemy.sql.expression import func, case

from zope.sqlalchemy import mark_changed

from .config import config
from .password import hash_password, check_password
#from .user_mixins import SocialMixin


class Role(config.sqlalchemy_base):

    __tablename__ = 'roles'

    id             = Column(Unicode, primary_key=True)
    name           = Column(Unicode)
    description    = Column(Unicode)

    _rest_search_columns = [id, name, description]


user_role_link = Table(
    'user_role_link',   config.sqlalchemy_base.metadata,
    Column('user_id',  Unicode, ForeignKey('users.id'),  primary_key=True),
    Column('role_id',  Integer, ForeignKey('roles.id'),  primary_key=True)
)


class RolePermission(config.sqlalchemy_base):

    __tablename__ = 'role_permissions'

    role_id        = Column(Unicode, ForeignKey('roles.id'), primary_key=True)
    object_type    = Column(Unicode)
    object_id      = Column(Unicode)
    permission     = Column(Unicode, primary_key=True)

    role = relationship(Role, backref="permissions")


class User(config.sqlalchemy_base):  #, SocialMixin):

    __tablename__ = 'users'

    id                     = Column(UUID, FetchedValue(), primary_key=True)
    login                  = Column(Unicode)  # unique

    is_enabled             = Column(Boolean, server_default='false')
    is_confirmed           = Column(Boolean, server_default='false')

    password_hash          = Column(Unicode, server_default='')

    confirm_code           = Column(Unicode)   # nullable
    confirm_time           = Column(DateTime)  # nullable

    name                   = Column(Unicode, server_default='')

    facebook_user_id       = Column(Unicode) # NULL, unique
    facebook_access_token  = Column(Unicode,  server_default='')

    vk_user_id             = Column(Unicode) # NULL, unique
    vk_access_token        = Column(Unicode,  server_default='')

    registered             = Column(DateTime, FetchedValue())
    last_login             = Column(DateTime)
    last_activity          = Column(DateTime)

    comment                = Column(Unicode, server_default='')

    roles = relationship(Role, secondary=user_role_link, backref="users")

    _rest_search_columns = [login, name]

    @classmethod
    def get_by_id(cls, id):
        return (config.sqlalchemy_session.query(cls)
            .filter(cls.id == id)
            .one())

    @classmethod
    def get_by_login(cls, login):
        return config.sqlalchemy_session.query(cls)\
            .filter(func.lower(cls.login) == login.lower())\
            .one()

    @classmethod
    def get_by_id_with_permissions(cls, user_id):
        return (config.sqlalchemy_session().query(cls)
            .filter(cls.id == user_id)
            .outerjoin(cls.roles, Role.permissions)
            .options(contains_eager(cls.roles, Role.permissions))
            .one())

    def update_last_login(self):
        self.last_login = datetime.datetime.utcnow()

    def update_last_activity(self):
        self.last_activity = datetime.datetime.utcnow()

    def eor_auth_flush_and_expunge(self):
        config.sqlalchemy_session().flush()
        config.sqlalchemy_session().expunge(self)

    ## authentication

    def check_password(self, password):
        """
        check whether password is valid
        :return boolean
        """
        return check_password(password, self.password_hash)

    def set_new_password(self, password):
        self.password_hash = hash_password(password)
        return self

    ## authorization

    def can_login(self):
        return self.is_enabled and self.is_confirmed

    ## social

    @classmethod
    def get_by_facebook_id(cls, facebook_id):
        return (config.sqlalchemy_session().query(cls)
            .filter(cls.facebook_user_id == facebook_id)
            .one())

    def save_facebook_session(self, facebook_user_id, access_token, expires):
        self.facebook_user_id = facebook_user_id
        self.facebook_access_token = access_token
        self.facebook_expires = expires

    @classmethod
    def get_by_vk_id(cls, vk_id):
        return (config.sqlalchemy_session().query(cls)
            .filter(cls.vk_user_id == vk_id)
            .one())

    def save_vk_session(self, vk_user_id, access_token):
        self.vk_user_id = vk_user_id
        self.vk_access_token = access_token

    ## email confirmation

    @classmethod
    def get_by_confirm_code(cls, confirm_code):
        return (config.sqlalchemy_session().query(cls)
            .filter(cls.confirm_code == confirm_code)
            .one())

    def set_confirm_code(self, confirm_code):
        self.is_confirmed = False
        self.confirm_code = confirm_code
        self.confirm_time = datetime.datetime.utcnow()

    def activate_and_reset_confirm_code(self):
        self.is_confirmed = True
        self.confirm_code = None
        self.confirm_time = None
