
class ResponseHandler(object):

    def __init__(self, social):
        self.social = social

    def login_error(self):
        pass

    def account_connected(self):
        pass

    def redirect_to_registration_form(self):
        pass

    def logged_in(self):
        pass

    def _redirect_after_login(self, headers=None):
        path = self.request.session.get('after-login', '/')

        try:
            del self.request.session['after-login']
        except KeyError:
            pass

        return HTTPFound(location=path, headers=headers)


class SPAResponseHandler(ResponseHandler):

    def login_error(self):
        return render_to_response('eor_auth.social:templates/callback-response.mako', {
            'status': 'error',
            'message': message_id,
            'detail': detail
        }, request=self.request)

    def account_connected(self):
        pass

    def redirect_to_registration_form(self):
        return render_to_response('eor_auth.social:templates/callback-response.mako', {
            'status': 'registration',
            'data': self.get_session_object()  # TODO
        }, request=self.request)

    def logged_in(self):
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
