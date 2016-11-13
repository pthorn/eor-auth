
from urllib.parse import urlencode
from collections import OrderedDict

from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.view import view_config

import requests

from ..config import config
from eor_settings import get_setting

from .base import Social


class Facebook(Social):
    def __init__(self, request):
        super().__init__(request)

        self.access_token = None
        self.vkontakte_user_id = None
        self.vk_login = None
        self.real_name = None
        self.email = None

    def get_user_by_social_id(self):
        return config.user_model.get_by_vkontakte_id(self.vkontakte_user_id)

    def save_for_user(self, user):
        user.save_vkontakte_session(self.vkontakte_user_id, self.access_token)

    def save_into_session(self):
        self.request.session['social-session'] = {
            'vkontakte': {
                'user-id': self.vkontakte_user_id,
                'access-token': self.access_token
            },
            'login': self.vk_login,
            'email': self.email,
            'real-name': self.real_name
        }

    @view_config(route_name='eor-auth.facebook-login')
    def facebook(self):
        app_id = get_setting('eor.vkontakte-app-id')
        if not app_id:
            log.warn('vkontakte_login(): parameter not specified: vkontakte-app-id')
            return HTTPNotFound()

        query_string = urlencode(OrderedDict(
            client_id      = app_id,
            redirect_uri   = self.request.route_url('eor-auth.facebook-login-cb'),
            display        = 'page',
            response_type  = 'code',
            scope          = 'status,email,wall,offline',  # https://vk.com/dev/permissions
            v              = '5.37'
        ))

        authorize_url = 'http://oauth.vk.com/authorize?' + query_string
        return HTTPFound(authorize_url)

    @view_config(route_name='eor-auth.facebook-login-cb')
    def facebook_login_callback(self):
        if 'error' in self.request.GET:
            error_code = self.request.GET.get('error', '')
            error_description = self.request.GET.get('error_description', '')

            # GET /auth/login/vkontakte-callback
            #    ?error=access_denied
            #    &error_reason=user_denied
            #    &error_description=User+denied+your+request

            log.warn('vkontakte_login_callback(): login error: %s, error_description: %s',
                     error_code, error_description)

            return handle_login_error(self.request, 'social-error',
                                      detail='%s: %s' % (error_code, error_description))

        try:
            code = self.request.GET['code']
            log.debug('vkontakte_login_callback(): code: %s', code)
        except KeyError as e:
            log.error('vkontakte_login_callback(): "code" parameter not present')
            return handle_login_error(self.request, 'social-error', detail='параметр "code" не передан')

        resp = requests.post(
            'https://oauth.vk.com/access_token',
            data = {
                'client_id':     get_setting('eor.vkontakte-app-id'),
                'client_secret': get_setting('eor.vkontakte-app-secret'),
                'code':          code,
                'redirect_uri':  self.request.route_url('eor-auth.facebook-login-cb')
            }
        )

        try:
            json = resp.json()
        except ValueError as e:
            log.error('vkontakte_login_callback(): /oauth/access_token: expected json, got: %s', resp.text)
            return handle_login_error(self.request, 'social-error', detail=resp.text)

        if 'access_token' in json:
            self.access_token = json['access_token']
            self.vkontakte_user_id = json['user_id']
            self.vk_login = json.get('username', '')
            self.real_name = json.get('full_name', '')
            self.email = json.get('email', '')  # TODO ?
            log.debug('vkontakte_login_callback(): /oauth/access_token: access_token: %s, user_id: %s, resp: %s',
                self.access_token, self.vkontakte_user_id, json)
        else:
            # {"error":"invalid_grant","error_description":"Code is invalid or expired."}
            error_code = json.get('error', '')
            error_description = json.get('error_description', '')

            log.error('vkontakte_login_callback(): /oauth/access_token: error: %s', resp.text)
            return handle_login_error(self.request, 'social-error', detail=error_description)

        return self.login()


'''
##
## login via facebook
##

@view_config(route_name='facebook-login')
def facebook_login(request):
    query_string = urlencode(OrderedDict(
        client_id     = app_conf('facebook-app-id'),
        redirect_uri  = request.route_url('facebook-login-cb'),
        response_type = 'code',
        scope = 'user_status,read_stream'  #  [u'export_stream', u'public_profile', u'read_stream', u'user_status']
    ))
    authorize_url = 'https://www.facebook.com/dialog/oauth?' + query_string
    return HTTPFound(authorize_url)


@view_config(route_name='facebook-login-cb')
def facebook_login_callback(request):
    """
    https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/
    """

    if 'error' in request.GET:
        log.warn('facebook_login_callback(): error = {0}, error_reason = {1}'.format(request.GET['error'], request.GET.get('error_reason')))
        return handle_login_error(request, 'social-error', detail=request.GET.get('error_reason'))

    if 'error_message' in request.GET:
        log.warn('facebook_login_callback(): error_code = {0}, error_message = {1}'.format(request.GET.get('error_code'), request.GET.get('error_message')))
        return handle_login_error(request, 'social-error', detail=request.GET.get('error_message'))

    try:
        code = request.GET['code']
    except KeyError as e:
        log.error('facebook_login_callback(): "code" parameter is not present')
        return handle_login_error(request, 'social-error', detail= '"code" parameter is not present')

    log.debug('facebook_login_callback(): code = {0}'.format(code))

    ## exchange code for an access token

    resp = requests.get(
        'https://graph.facebook.com/oauth/access_token',
        params = {
            'client_id': app_conf('facebook-app-id'),
            'client_secret': app_conf('facebook-app-secret'),
            'code': code,
            'redirect_uri': request.route_url('facebook-login-cb') # TODO ??
        }
    )

    # TODO [] -> get()
    if resp.headers['content-type'].startswith('application/json'):
        json = resp.json()
        log.error('facebook_login_callback(): /oauth/access_token returned error: type = {0}, code = {1}, message: {2}'.format(
            json['error']['type'], json['error']['code'], json['error']['message']
        ))
        return handle_login_error(request, 'social-error', detail=json['error']['message'])

    body_parsed = parse_qs(resp.text)
    try:
        access_token = body_parsed['access_token'][0]
        expires = datetime.datetime.now() + datetime.timedelta(0, int(body_parsed['expires'][0]))
    except (KeyError, ValueError, IndexError) as e:
        log.error('facebook_login_callback(): error parsing /oauth/access_token response: error = {0}, response: {1}'.format(e, resp.text))
        return handle_login_error(request, 'social-error', detail=resp.text)

    log.debug('facebook_login_callback(): access_token = {access_token}, expires = {expires}'.format(
        access_token = access_token, expires = expires
    ))

    ## get user info for the access token
    ## https://developers.facebook.com/docs/graph-api/reference/user/
    ## {u'username': u'pavel.efremov.146', u'first_name': u'Pavel', u'last_name': u'Efremov', u'verified': True, u'name': u'Pavel Efremov', u'locale': u'en_US', u'gender': u'male', u'updated_time': u'2014-03-10T07:32:26+0000', u'link': u'https://www.facebook.com/pavel.efremov.146', u'timezone': 4, u'id': u'100007909573593'}

    resp = requests.get(
        'https://graph.facebook.com/me',
        params = {
            'access_token': access_token
        }
    )

    # TODO what error messages are possible?
    error = resp.json().get('error', resp.json().get('data', {}).get('error'))  # TODO ?
    if error:
        log.error('facebook_login_callback(): /me returned error: {0}'.format(error))
        return handle_login_error(request, 'social-error', detail=error)

    # TODO this can also be used to check if user session is valid
    data = resp.json()
    facebook_user_id = data['id']
    login            = data.get('username', '')
    real_name        = data.get('name', '')

    # TODO also available: username, name, first_name, last_name, link

    log.debug('facebook_login_callback(): facebook user id = {0}, name = {1}, link = {2}'.format(
        facebook_user_id, data['name'], data['link']
    ))

    ## login logic

    def get_user_by_facebook_id():
        return models.User.get_by_facebook_id(facebook_user_id)

    def save_facebook_session(user):
        user.save_facebook_session(facebook_user_id, access_token, expires)

    def facebook_session_into_session():
        request.session['social-session'] = {
            'facebook': {
                'user-id': facebook_user_id,
                'access-token': access_token,
                'expires': expires
            },
            'login': login,
            'real-name': real_name
        }

    return login_via_social_account(request, get_user_by_facebook_id, save_facebook_session, facebook_session_into_session)
'''