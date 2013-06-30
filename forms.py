from flask.ext.wtf import Form, TextField, PasswordField, BooleanField, validators
import wtforms.form

import models


class SetUser(wtforms.form.Form):
    email = TextField('Email address', [
        validators.Required("It's okay, we won't email you unless you want us to."),
        validators.Email("Um, that doesn't look like an email address."),
    ])
    password = PasswordField('Password', [
        validators.Required("How else will we know it's really you?"),
    ])
    retype = PasswordField('Password (again)', [
        validators.EqualTo('password', message="If you can't type it twice now, you'll never be able to log in with it."),
    ])


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
