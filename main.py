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
        self.write(self.render_str(template, handler = self, **kw))

    def make_cookie_for_page(self, entity):
        newuser_id = entity.get_ID() #Get ID of new entity
        pass_hash = entity.password.split("|")[0]
        cookie_value = str('user-id=%s|%s' % (newuser_id, pass_hash))
        self.response.headers.add_header('Set-Cookie', '%s; Path=/' % cookie_value)

    @staticmethod
    def split_cookie(h): #Can this go in Handler class?
        user_cookie = h.split("|")
        return user_cookie

    def valid_cookie(self): #check if DB ID matches with cookie hash password
        if self.request.cookies.get("user-id"):
            hash_pw = self.get_hash_from_cookie()        
            cookie_account = self.get_account_from_cookie() #Add to Handler class?
            if cookie_account:
                return hash_pw == (cookie_account.password).split("|")[0]
            else:
                return False
        else:
            return False

    def get_account_from_cookie(self):
        userID_cookie = str(self.request.cookies.get("user-id"))
        broken_cookie = self.split_cookie(userID_cookie)
        account_id = int(broken_cookie[0])
        return Accounts.get_account_ent(account_id)

    def get_hash_from_cookie(self):
        userID_cookie = str(self.request.cookies.get("user-id"))
        broken_cookie = self.split_cookie(userID_cookie)
        return broken_cookie[1]



class Accounts(db.Model):
    #add helper function for splitting password property
    def split_password(self):
        return self.password.split("|")

    def get_ID(self):
        return self.key().id()

    @classmethod
    def get_account_ent(cls, account_id):
        return cls.get_by_id(account_id)

    @staticmethod
    def check_user_inuse(username):
        q = db.GqlQuery("""SELECT * FROM Accounts WHERE user = '%s'""" % username)
        return q.get() #Returns None if no matches are found (Username not in database)

    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    #email = db.StringProperty()#Not currently adding email. Can't figure out how to make optional
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class BlogPage(Handler):

    def get(self, **kw):
        if self.valid_cookie():
            posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
            self.render("blog-page.html", posts=posts, **kw)
        else:
            self.redirect('signin')

class MainPage(Handler):
    def get(self):
        self.redirect('/signin')

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
            if Accounts.check_user_inuse(username):##Check if username is already in the database
                error_user = "Username already in use"
                self.render("user_signup_form.html", error_user = error_user)
            else: #Add user to database

            #Attempt to create new user
                #Salt and hash password for user
                salt_hash_pw = make_pw_hash(username, password)
                #Create new entity for user
                newuser = Accounts(user = username, password = salt_hash_pw) #Not currently adding email. Can't figure out how to make optional
                newuser.put() #Put new user into DB
                self.make_cookie_for_page(newuser)#Set cookie for user
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
                                                email = email)


class NewPost(Handler):

    def get(self): #Need to fix. Add helper method strictly for rendering new form html
        self.render("submit-form.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content") #May encounter error by interacting with Jinja content variable for form inheritenace. Be aware. Consider switching variable names. But it is likely that the block code gets run and the content within the block is plain/text and the function for moving the content block completes before the remaining code is parsed, thereby lmiting the scope of the content variable.
        
        
        if subject and content:
            newpost = Blog(subject = subject, content = content) #Should ensure that Int is generated for ID
            newpost.put()
            post_num = str(newpost.key().id())
            self.redirect("/" + post_num) # Need to have newpost redirect to Unique ID page for post
        else:
            error = "we need both subject and content"
            self.render("submit-form.html", error = error, subject = subject, content = content)

class FormPage(Handler):
    def get(self, post_id):
     #Should check to verify if Int
        post = Blog.get_by_id(int(post_id))
        if post:
            self.render("new-post.html", post = post)
        else:
            self.write("That is not a post")

class WelcomeHandler(Handler):
    def get(self): #Get cookie from user browser. Lookup information in databse and display name
        if (self.valid_cookie()):
            self.write("Welcome %s" % (self.get_account_from_cookie().user))
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
            username_entity = Accounts.check_user_inuse(username)
            if username_entity:
                hash_salt_password = username_entity.split_password()
                if username_entity.password == make_pw_hash(username, password, hash_salt_password[1]):#Get the hash,salt and check provided username+password+salt against value of Accounts.password (hash,salt)
                    self.make_cookie_for_page(username_entity) #Make cookie
                    self.redirect('/welcome')
                else:
                    self.render("signin_page.html", error = "That's the incorrect password. Please try again")
            else:
                self.redirect('/signup') #Make error message. Render to page

class LogoutHandler(Handler): #deletes cookie and redirects user to signup page

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')
        self.redirect("/signup")


app = webapp2.WSGIApplication([
                            ('/', MainPage),
                            ('/signup', SignUpPage),
                            ('/welcome', WelcomeHandler),
                            ('/signin', SignInHandler),
                            ('/logout', LogoutHandler),
                            ('/blog', BlogPage),
                            ('/newpost', NewPost),
                            ('/([0-9]+)', FormPage)
                            ],
                            debug=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username): #Maybe all these go in the Handler class. Or how a LoginsHandler class
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    else:
        return True

def create_salt(): #Put in Accounts class or some salting/hashing class
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
   



