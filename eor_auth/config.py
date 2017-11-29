# coding: utf-8

class Config(object):
    def __init__(self):
        self.sqlalchemy_base = None
        self.sqlalchemy_session = None
        self.user_model = None
        self.session_class = None
        #self.use_xhr = False
        #self.social_delegate = None

    def _from_settings(self, settings):
        def get_default_user_model():
            from .model import User
            return User

        def get_default_session_class():
            from .sessionuser import SessionUser
            return SessionUser

        # def get_default_social_delegate():
        #     from .social.delegate import SocialDelegate, SocialDelegateXHR
        #     return SocialDelegateXHR if self.use_xhr else SocialDelegate

        self.sqlalchemy_base = settings['eor_auth.sqlalchemy_base']
        self.sqlalchemy_session = settings['eor_auth.sqlalchemy_session']
        self.user_model = settings.get('eor_auth.user_model', get_default_user_model())
        self.session_class = settings.get('eor_auth.session_class', get_default_session_class())
        #self.social_delegate =

config = Config()
