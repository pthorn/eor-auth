# coding: utf-8

class Config(object):
    """
    from eor_auth import config as auth_config
    from eor.models import Session
    auth_config.sqlalchemy_session = Session
    """

    def __init__(self):
        self.sqlalchemy_base = None
        self.sqlalchemy_session = None
        self.user_model = None
        self.session_class = None
        self.use_xhr = False
        self.social_delegate = None

    def set_defaults(self):
        if not self.sqlalchemy_base:
            raise RuntimeError('eor_auth.config.config.sqlalchemy_base is not set')

        if not self.sqlalchemy_session:
            raise RuntimeError('eor_auth.config.config.sqlalchemy_session is not set')

        if not self.user_model:
            from .model import User
            self.user_model = User

        if not self.session_class:
            from .sessionuser import SessionUser
            self.session_class = SessionUser

        if not self.social_delegate:
            from .social.delegate import SocialDelegate, SocialDelegateXHR
            self.social_delegate = SocialDelegateXHR if self.use_xhr else SocialDelegate


config = Config()
