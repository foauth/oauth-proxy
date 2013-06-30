from flask.ext.wtf import Form, TextField, PasswordField, BooleanField, validators

import models


class Login(Form):
    email = TextField('Email address', validators=[
        validators.Email('Please supply an email address.')
    ])
    password = PasswordField('Password', validators=[
        validators.Required('Please supply a password.')
    ])


class Password(Form):
    password = PasswordField('Password', [
        validators.Required('How else will we know it&rsquo;s really you?'),
    ])
    retype = PasswordField('Password (again)', [
        validators.EqualTo('password', message='If you can&rsquo;t type it twice now, you&rsquo;ll never be able to log in with it.')
    ])
