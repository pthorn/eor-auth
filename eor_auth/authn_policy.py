from pyramid.authentication import CallbackAuthenticationPolicy

from .config import config


def init(config):
    policy = EORAuthenticationPolicy()
    config.set_authentication_policy(policy)


class EORAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(self):
        self.callback = get_principals_for_userid_callback
        self.debug = True

    def unauthenticated_userid(self, request):
        try:
            return request.user.id  # can be forced with eor_auth.force_user_id
        except AttributeError:
            return None

    def remember(self, request, userid, **kw):
        """ Store a userid in the session."""
        pass  # SessionUser.create_and_save_to_session() does it
        # request.session[self.userid_key] = userid
        # return []

    def forget(self, request):
        """ Remove the stored userid from the session."""
        if config.session_key in request.session:
            del request.session[config.session_key]
        return []


def get_principals_for_userid_callback(userid, request):
    """
    return None if the userid doesn’t exist
    or a sequence of principal identifiers (possibly empty) if the user does exist
    """
    return request.user.get_principals() if request.user else None

