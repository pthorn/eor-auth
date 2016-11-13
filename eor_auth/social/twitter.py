"""
##
## login via twitter
## https://dev.twitter.com/docs/auth/implementing-sign-twitter
##

def get_twitter_oauth_service():
    return OAuth1Service(
        name='twitter',
        consumer_key      = app_conf('twitter-api-key'),
        consumer_secret   = app_conf('twitter-api-secret'),
        request_token_url = 'https://api.twitter.com/oauth/request_token',
        access_token_url  = 'https://api.twitter.com/oauth/access_token',
        authorize_url     = 'https://api.twitter.com/oauth/authorize',
        base_url          = 'https://api.twitter.com/1.1/'
    )


@view_config(route_name='twitter-login')
def twitter_login(request):

    # TODO check if user already has a twitter session

    twitter = get_twitter_oauth_service()

    # 1. get request tokens, set callback url
    #    check oauth_callback_confirmed=true
    #    store request token w/ secret

    # TODO send oauth_callback !!!
    try:
        request_token, request_token_secret = twitter.get_request_token(params={'oauth_callback': request.route_url('twitter-login-cb')})
    except (RequestException, KeyError) as e:
        # KeyError seems to be raised when api key/secret is wrong
        log.warn('twitter_login: error getting request tokens: {0}'.format(e))
        return handle_login_error(request, 'social-error')

    request.session['twitter-request-secret'] = request_token_secret
    log.debug('twitter_login: request_token={rt}, request_token_secret={rts}'.format(rt=request_token, rts=request_token_secret))

    # 2. redirect to twitter.get_authorize_url(request_token)

    authorize_url = twitter.get_authorize_url(request_token)
    return HTTPFound(authorize_url)


@view_config(route_name='twitter-login-cb')
def twitter_login_callback(request):
    # 3. convert request token to access token
    #    request will contain request token and oauth_verifier
    #    fetch secret for the request token from db for signing?
    #    send it and request token to get access token + secret
    #    save access token + secret to database
    # n. redirect to whatever url

    try:
        request_token = request.GET['oauth_token']
        oauth_verifier = request.GET['oauth_verifier']
        log.debug('twitter_login_callback: called with request_token={rt}, oauth_verifier={ov}'.format(rt=request_token, ov=oauth_verifier))
    except KeyError as e:
        log.warn('twitter_login_callback: request parameter not present: {0}'.format(e))
        return handle_login_error(request, 'social-error')

    try:
        request_token_secret = request.session['twitter-request-secret']
        del request.session['twitter-request-secret']
    except KeyError as e:
        log.warn('twitter_login_callback: no twitter-request-secret in session: {0}'.format(e))
        return handle_login_error(request, 'social-error')

    log.debug('twitter_login_callback: getting access tokens, request_token={rt}, request_token_secret={rs}'.format(rt=request_token, rs=request_token_secret))
    try:
        session = get_twitter_oauth_service().get_auth_session(
            request_token, request_token_secret,
            method='POST', data={'oauth_verifier': oauth_verifier}
        )
    except Exception as e:
        log.warn('twitter_login_callback: error requesting access tokens: {0}'.format(e))
        return handle_login_error(request, 'social-error')

    log.debug('twitter_login_callback: access_token={at}, access_token_secret={ats}'.format(at=session.access_token, ats=session.access_token_secret))

    req = session.get('account/verify_credentials.json', params={'skip_status': 'true'}, verify=True)
    json = req.json()
    twitter_user_id = json['id_str']
    screen_name = json.get('screen_name', '')
    real_name = json.get('name', '')
    log.debug('twitter_login_callback: verify_credentials: user_id={id}, screen_name={sn}'.format(id=twitter_user_id, sn=screen_name))

    ## login logic

    def get_user_by_twitter_id():
        return models.User.get_by_twitter_id(twitter_user_id)

    def save_twitter_session(user):
        user.save_twitter_session(twitter_user_id, session.access_token, session.access_token_secret)

    def twitter_session_into_session():
        request.session['social-session'] = {
            'twitter': {
                'user-id': twitter_user_id,
                'access-token': session.access_token,
                'secret': session.access_token_secret,
            },
            'login': screen_name,
            'real-name': real_name
        }

    return login_via_social_account(request, get_user_by_twitter_id, save_twitter_session, twitter_session_into_session)
"""