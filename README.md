Private OAuth Proxy
===================

Intead of using [foauth.org](https://foauth.org/), you can use this project to
host your own proxy service for free on Heroku. It requires more initial
configuration, but you get all the benefits, and you can be in complete control
of your user account and authorizations.

Installation
------------

Clone the repository.

    $ git clone https://github.com/foauth/oauth-proxy
    $ cd oauth-proxy

Create a Heroku app.

    $ heroku create
    $ git push heroku master

The remainder of the instructions are presented contextually within the app
itself. Just open it in your browser and follow along. Refresh the page after
each step to make sure you've completed it.

    $ heroku open
