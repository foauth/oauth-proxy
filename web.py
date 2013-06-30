import datetime
from functools import wraps
import os
import re
import sys

from flask import request, flash, redirect, render_template, abort, url_for, make_response
from flask.ext.login import current_user, login_user, logout_user, login_required

from foauth import OAuthDenied, OAuthError
import config
import forms
import models

HOST_HEADERS = [
    'Authorization',
    'Host',
    'X-Forwarded-For',
    'X-Forwarded-Port',
    'X-Forwarded-Proto',
    'X-Forwarded-Protocol',
    'X-Heroku-Dynos-In-Use',
    'X-Heroku-Queue-Depth',
    'X-Heroku-Queue-Wait-Time',
    'X-Real-Ip',
    'X-Request-Start',
    'X-Varnish',
]


@config.app.errorhandler(403)
def forbidden(e):
    return make_response(render_template('403.html'), 403)


@config.app.route('/', methods=['GET'])
def index():
    try:
        user_count = models.User.query.count()
    except:
        # Normally a bare except would be a bad idea, but in this case it makes
        # sense because any problem obtaining the number of users is equivalent
        # to having no users, and we need to recover gracefully in the event
        # that the database hasn't yet been configured.
        user_count = 0

    return render_template('index.html',
        env=os.environ,
        custom_domain=re.match('[a-z]+-[a-z]+-[0-9]+\.herokuapp\.com', request.host),
        service_count=len(config.services),
        user_count=user_count,
    )


@config.app.route('/login/', methods=['GET'])
def login():
    if current_user.is_authenticated():
        return redirect(url_for('services'))

    return render_template('login.html', form=forms.Login())


@config.app.route('/login/', methods=['POST'])
def login_post():
    form = forms.Login(request.form)
    if form.validate():
        user = models.User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('services'))
        else:
            flash('Incorrect login', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html', form=form)


@config.app.route('/logout/', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('index'))


@config.app.route('/services/', methods=['GET'])
def services():
    services = sorted((s.alias, s) for s in config.services)
    return render_template('services.html', services=config.services)


def auth_endpoint(func):
    @wraps(func)
    def wrapper(alias, *args, **kwargs):
        try:
            service = config.alias_map[alias]
        except KeyError:
            abort(404)
        return func(service, *args, **kwargs)
    return wrapper


@config.app.route('/services/<alias>/authorize', methods=['POST'])
@login_required
@auth_endpoint
def authorize(service):
    scopes = request.form.getlist('scope')
    try:
        return service.authorize(scopes)
    except OAuthError:
        flash('Error occured while authorizing %s' % service.name, 'error')
        return redirect(url_for('services'))


@config.app.route('/services/<alias>/callback', methods=['GET'])
@login_required
@auth_endpoint
def callback(service):
    user_key = models.Key.query.filter_by(user_id=current_user.id,
                                          service_alias=service.alias).first()
    try:
        data = service.callback(request.args, 'callback')
        if not user_key:
            user_key = models.Key(user_id=current_user.id,
                                  service_alias=service.alias)
        user_key.update(data)
        if 'service_user_id' not in data:
            user_key.service_user_id = service.get_user_id(user_key)
        models.db.session.add(user_key)
        flash('Granted access to %s' % service.name, 'success')

    except OAuthError:
        flash('Error occurred while authorizing %s' % service.name, 'error')

    except OAuthDenied, e:
        # User denied the authorization request
        if user_key:
            models.db.session.delete(user_key)
        flash(e.args[0], 'error')

    models.db.session.commit()
    return redirect(url_for('services'))


@config.app.route('/<domain>/<path:path>', methods=['OPTIONS', 'GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
@config.app.route('/<domain>/', defaults={'path': u''}, methods=['OPTIONS', 'GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
def api(domain, path):
    # Allow clients to override the method being provided, in case the client
    # or network doesn't natively support PATCH. For example, Amazon discards
    # PATCH requests before they ever reach Heroku, much less foauth.org.
    if request.method == 'POST':
        override = request.headers.get('X-Http-Method-Override')
        if override == 'PATCH':
            request.environ['REQUEST_METHOD'] = override

    auth = request.authorization
    if auth:
        user = models.User.query.filter_by(email=auth.username).first()
        if user and user.check_password(auth.password):
            try:
                service = config.domain_map[domain]
            except KeyError:
                abort(404)

            key = get_user_key(service, user)
            resp = service.api(key, domain, '/%s' % path, request.method,
                               request.args, request.form or request.data,
                               prepare_headers(request.headers))
            content = resp.raw.read()

            if 'Transfer-Encoding' in resp.headers and \
               resp.headers['Transfer-Encoding'].lower() == 'chunked':
                # WSGI doesn't handle chunked encodings
                del resp.headers['Transfer-Encoding']
            if 'Connection' in resp.headers and \
               resp.headers['Connection'].lower() == 'keep-alive':
                # WSGI doesn't handle keep-alive
                del resp.headers['Connection']

            return config.app.make_response((content,
                                             resp.status_code,
                                             resp.headers))
    abort(403)


def prepare_headers(headers):
    # Make sure we have a mutable dictionary
    headers = dict(headers)

    # These are specific to the host environment and shouldn't be forwarded
    for header in HOST_HEADERS:
        if header in headers:
            del headers[header]

    # These are invalid if using the empty defaults
    if 'Content-Length' in headers and headers['Content-Length'] == '':
        del headers['Content-Length']
    if 'Content-Type' in headers and headers['Content-Type'] == '':
        del headers['Content-Type']

    return headers


def get_user_key(service, user):
    key = user.keys.filter_by(service_alias=service.alias).first()
    if not key:
        abort(403)
    if key.is_expired():
        # Key has expired
        if key.refresh_token:
            data = service.refresh_token(key.refresh_token)
            key.update(data)
            models.db.session.add(key)
            models.db.session.commit()
        else:
            # Unable to refresh the token
            abort(403)
    return key


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    config.app.run(host='0.0.0.0', port=port)
