import getpass
import os
import sys
from werkzeug.datastructures import MultiDict

import models
import forms

# Make sure the database gets installed properly
models.db.create_all()

values = MultiDict()
form = forms.SetUser(values)


values['email'] = sys.argv[1] if len(sys.argv) > 1 else raw_input('%s: ' % form.email.label.text)
form = forms.SetUser(values)
form.validate()
if form.email.errors:
    sys.exit('\n'.join(' ! %s' % e for e in form.email.errors))

if models.User.query.filter_by(email=form.email.data).count():
    print '%s already exists, setting the password' % form.email.data


values['password'] = getpass.getpass('%s: ' % form.password.label.text)
form = forms.SetUser(values)
form.validate()
if form.password.errors:
    sys.exit('\n'.join(' ! %s' % e for e in form.password.errors))


values['retype'] = getpass.getpass('%s: ' % form.retype.label.text)
form = forms.SetUser(values)
form.validate()
if form.retype.errors:
    sys.exit('\n'.join(' ! %s' % e for e in form.retype.errors))


user = models.User.query.filter_by(email=form.email.data).first()
if user:
    user.set_password(form.password.data)
    msg = 'Updated password for %s' % user.email
else:
    user = models.User(email=form.email.data, password=form.password.data)
    msg = 'Created account for %s' % user.email

models.db.session.add(user)
models.db.session.commit()
print msg
