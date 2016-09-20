# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import os
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        t = jinja_env.get_template(template)
        return t.render(**kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Accounts(db.Model):
    #add helper function for splitting password property
    def split_password(self):
        return self.password.split("|")

    def get_ID(self):
        return self.key().id()

    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    #email = db.EmailProperty()#Not currently adding email. Can't figure out how to make optional
class MainPage(Handler):
    def get(self):
        self.redirect('/signup')

class SignUpPage(Handler):
    def get(self):
        self.render("user_signup_form.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        is_valid_user = valid_username(username)
        if password and verify:
            if password == verify:
                is_valid_pass = valid_password(password)
        else:
            is_valid_pass = False
        is_valid_email = valid_email(email)

        if is_valid_user and is_valid_pass and is_valid_email:
            if check_user_inuse(username):##Check if username is already in the database
                error_user = "Username already in use"
                self.render("user_signup_form.html", error_user = error_user)
            else: #Add user to database

            #Attempt to create new user
                #Salt and hash password for user
                salt_hash_pw = make_pw_hash(username, password)
                #Create new entity for user
                newuser = Accounts(user = username, password = salt_hash_pw) #Not currently adding email. Can't figure out how to make optional
                newuser.put() #Put new user into DB
                make_cookie_for_entity(self, newuser)#Set cookie for user
                self.redirect("/welcome")
        else:
            error_user=""
            error_pass=""
            error_email=""
            if not is_valid_user:
                error_user = "Username not valid"
            if not is_valid_pass:
                error_pass = "Password is not valid"
            if not is_valid_email:
                error_email = "Email is not valid"
            self.render("user_signup_form.html", error_user = error_user,
                                                error_pass = error_pass,
                                                error_email = error_email,
                                                username = username,
                                                email = email)#, text = text)
        #Need to write redirect if success
        #Need to write helpers to check if data is valid


class WelcomeHandler(Handler):
    def get(self): #Get cookie from user browser. Lookup information in databse and display name
        userID_cookie = str(self.request.cookies.get("user-id"))
        broken_cookie = split_cookie(userID_cookie)
        account_id = int(broken_cookie[0])
        hash_pw = broken_cookie[1]
        if (valid_cookie(account_id, hash_pw)):
            self.write("Welcome %s" % (get_account_ent(account_id).user))
        else:
            self.redirect("/signup")

class SignInHandler(Handler):
    def get(self):
        self.render("signin_page.html")

    def post(self): #User enters login information
        username = self.request.get("username")
        password = self.request.get("password")
        is_valid_user = valid_username(username)
        is_valid_pass = valid_password(password)

        if is_valid_user and is_valid_pass:
            username_entity = check_user_inuse(username)
            if username_entity:
                hash_salt_password = username_entity.split_password()
                if username_entity.password == make_pw_hash(username, password, hash_salt_password[1]):#Get the hash,salt and check provided username+password+salt against value of Accounts.password (hash,salt)
                    #Call make_cookie_for_entity()
                    make_cookie_for_entity(self, username_entity)
                    self.redirect('/welcome')
                else:
                    self.render("signin_page.html", error = "That's the incorrect password. Please try again")
            else:
                self.redirect('/signup') #Make error message. Render to page

app = webapp2.WSGIApplication([
                            ('/', MainPage),
                            ('/signup', SignUpPage),
                            ('/welcome', WelcomeHandler),
                            ('/signin', SignInHandler)],
                            debug=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    else:
        return True

def check_user_inuse(username):
    q = db.GqlQuery("""SELECT * FROM Accounts WHERE user = '%s'""" % username)
    return q.get() #Returns None if no matches are found (Username not in database)

def create_salt():
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=""):
    if not salt:
        salt = create_salt()
    hashedpw = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s|%s" % (hashedpw, salt)

def valid_pw(name, pw, h):
    pass_salt = string.split(h,"|")[1]
    check_pass = make_pw_hash(name, pw, pass_salt)
    return (h == check_pass)
   
def valid_cookie(account_id, pw_hash): #check if DB ID matches with cookie hash password
    cookie_account = get_account_ent(account_id)
    if cookie_account:
        return pw_hash == (cookie_account.password).split("|")[0]
    else:
        return False

def get_account_ent(account_id):
    return Accounts.get_by_id(account_id)

def split_cookie(h):
    user_cookie = h.split("|")
    return user_cookie

def make_cookie_for_entity(self, entity):
    newuser_id = entity.get_ID() #Get ID of new entity
    pass_hash = entity.password.split("|")[0]
    cookie_value = str('user-id=%s|%s' % (newuser_id, pass_hash))
    self.response.headers.add_header('Set-Cookie', '%s; Path=/' % cookie_value)

