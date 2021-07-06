from __future__ import division

"""import cStringIO"""
import copy
import logging
import os
import random
import re
import string
import datetime
import json
import ssl


import tornado.auth
import tornado.escape

import tornado.httpserver

import tornado.ioloop

import tornado.options

import tornado.web


import uuid
import pymongo


from tornado.options import define, options
import os
import json
import csv

import chardet
import logging

import jwt
from functools import wraps


"""
env options are
    dev and prod
ENV is the key
    while dev is the default
"""
env = os.environ.get('ENV','dev')
if env == 'prod':
    DEBUG=False
else:
    DEBUG=True
UPLOADS_DIR='uploads'
if not DEBUG:
    UPLOADS_DIR='/home/uploads'
define("port", default=9999, type=int)


def token_required(f):
    @wraps(f)
    def decorator( *args, **kwargs):
        current_user=None
        #print(args)
        request_handler = args[0]
        token = None
        #print(request_handler.request.headers)
        if 'Authorization' in request_handler.request.headers:
            token = request_handler.request.headers['Authorization']
            logging.info(type(token))
            print('This is token')
            #token = bytes(token)
        print(token)
        if not bool(token):
            json_err = {'message':'a valid token is missing'}
            request_handler.write(json.dumps(json_err, default=json_util.default))
            request_handler.set_header('Content-Type', 'application/json')
            request_handler.finish()
            return
        try:
            data = jwt.decode(token, settings['cookie_secret'])
            logging.info(data)
            current_user = request_handler.db['Users'].find_one({'_id':ObjectId(data['public_id'])})
        except:
            json_error = {'message': 'token is invalid'}

            request_handler.write(json.dumps(json_error, default=json_util.default))
            request_handler.set_header('Content-Type', 'application/json')
            request_handler.finish()
        logging.info(current_user)
        return f( *args, **kwargs)

    return decorator

class BaseHandler(tornado.web.RequestHandler):
    def data_received(self, chunk):
        pass

    def __init__(self, application, request, **kwargs):
        super(BaseHandler, self).__init__(application, request, **kwargs)
        self.response = dict()
        if self.get_current_user_name():
            self.response['name'] = self.get_current_user_name()

    def get_current_user(self):
        user = self.get_secure_cookie("rth_user")
        if not user:
            return None
        return tornado.escape.xhtml_escape(user)

    def get_current_user_name(self):
        user = self.get_secure_cookie("rth_user_name")
        if not user:
            return None
        return tornado.escape.xhtml_escape(user)

    @property
    def current_timestamp(self):
        return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')

    @property
    def db(self):
        _db = None
        if not hasattr(BaseHandler, '_db'):
            _db = myClient["realtour"]
        return _db

    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def format_for_firestore(self, mydict):
        for k in mydict:
            # if isinstance(mydict[k], str):
            #     mydict[k] = mydict[k].decode('utf-8')
            if isinstance(mydict[k], dict):
                mydict[k] = self.format_for_firestore(mydict[k])
            if isinstance(mydict[k], list):
                mydict[k] = [self.format_for_firestore(x) for x in mydict[k]]
        return mydict

    def render(self, template, **kwargs):
        #TODO change this to user id instead
        #kwargs['request_user'] = self.get_current_user_name()
        kwargs['messages'] = []
        super(BaseHandler, self).render(template, **kwargs)

class HomeHandler(BaseHandler):
    def get(self):
        self.render('index.html')


class SSLVerification(BaseHandler):
    def get(self):
        self.write("92298104295451E2513E98FBFEF5D64BE02586A4736A8E8D3A7B887207B76908 comodoca.com 5fe5180e7d990")
        self.finish()

urls = [

    (r"/", HomeHandler),

    (r"/uploads/(.*)", tornado.web.StaticFileHandler, {'path': UPLOADS_DIR}),

    (r"/pro/uploads/(.*)", tornado.web.StaticFileHandler, {'path': UPLOADS_DIR}),

    (r"/assets/(.*)", tornado.web.StaticFileHandler, {'path': 'assets'}),

    (r"/images/(.*)", tornado.web.StaticFileHandler, {'path': 'assets/images'}),


]

settings = dict({
    "template_path": os.path.join(os.path.dirname(__file__), "templates"),
    "static_path": os.path.join(os.path.dirname(__file__), "assets"),
    "cookie_secret": "VLWx0rigAiXSaTX2P4V8O",
    "login_url": "/auth/signin",
    "xsrf_cookies": False,
    "compiled_template_cache": False,
    "debug": DEBUG,
    "autoreload": True,
    "static_hash_cache": False,
})

app = tornado.web.Application(urls, **settings)


def main():
    tornado.options.parse_command_line()
    # localhost http server test
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    # ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # ssl_ctx.load_cert_chain("../server.crt", keyfile="../server.key")
    # ssl_ctx.load_verify_locations("../ca.crt")
    # ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    # https_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx)
    # https_server = tornado.httpserver.HTTPServer(app, ssl_options=dict(
    #    certfile="../server.crt", keyfile="../server.key", cert_reqs=ssl.CERT_REQUIRED,
    #    ca_certs="../ca.crt"))
    # https_server.listen(443)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    myClient = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
    main()
