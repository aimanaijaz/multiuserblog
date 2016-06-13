#import statements
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

#import google datastore
from google.appengine.ext import db
# sets the locaiton of the templates folder
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# invokes the jinja2 envronment pointing it to the location of templates.
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'faith'
# Regular expressions used for user signup and login form validations
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

#functions to help with user validations
def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#functions to help with password hashing
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
# Keys
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def like_key(post = 'default'):
    return db.Key.from_path('like', post)

def comment_key(post = 'default'):
    return db.Key.from_path('comment', post)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    author = db.StringProperty(required = True)
    comments = db.IntegerProperty(default = 0)
    likes = db.IntegerProperty(default = 0)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Like(db.Model):
    user = db.StringProperty(required = True)
    post = db.StringProperty(required = True)
   

class Comment(db.Model):
    post = db.StringProperty(required = True)
    comment = db.StringProperty(required = True)
    author = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
#Signup Page
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError
# Register
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')
# Login page
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')
#Main page of the blog where all posts are displayed      
class MainPage(BlogHandler):
    def get(self):
        # Displays the latest posts
        posts = greetings = Post.all().order('-created')
        if self.user:
            self.render('front.html', posts = posts)
        else:
            self.render('publicfront.html', posts=posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        # Obtains post based on the id in the get query
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)
        params = dict(post = post)
        params['id'] = int(post_id)
        # Querying the datastore for comments on that particular post
        comments = db.GqlQuery("Select * FROM Comment WHERE post = '%s' ORDER BY created DESC" % str(post_id))
        if comments.get():
            params['comments'] = comments
        if self.user:
            # Querying the datastore for likes on that particular post
            like = db.GqlQuery("Select * FROM Like WHERE user = '%s' and post = '%s'"% (self.user.name, str(post_id))) 
            if like.get():
              params['like'] = like
            if not post:
              self.error(404)
              return
            self.render("permalink.html", **params)
        else:
            self.render("publicpermalink.html", **params)

    def post(self,post_id):
        # Obtain id from the textbox
        self.id = self.request.get('id')
        params = dict(id = self.id)
        # Obtain comment from the form
        self.comment = self.request.get('comment')
        pkey = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(pkey)
        # Posting new comments and incrementing
        c = Comment(post = self.id, comment = self.comment, author = self.user.name, parent = comment_key())
        c.put()
        post.comments = post.comments + 1
        post.put()
        self.redirect('/blog/%s' % self.id)

# This class adds a new post   
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self):
        # Obtain id from the get query
        post_id = self.request.get('id')
        if not self.user:
            self.redirect('/login')
        else:
            pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(pkey)
            # Check if the user is the author of the post
            if self.user.name != post.author:
                self.redirect('/blog/%s' % post_id)
            else:
                params = dict(id = int(post_id))
                params['post'] = post
                if not post:
                    self.error(404)
                    return
                self.render('editpost.html', **params)                     

    def post(self):
        # Obtain id from the textbox
        self.id = self.request.get('id')
        pkey = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(pkey)
        # Get subject and content
        self.subject = self.request.get('subject')
        self.content = self.request.get('content')
        params = dict(subject = self.subject, content = self.content, id = self.id)
        # Sets the subject the content and pushes the edited post to the datastore
        post.subject = self.subject
        post.content = self.content
        post.put()
        self.redirect('/blog/%s' %self.id)

class DeletePost(BlogHandler):
    def get(self):
        # Obtain the id from the get query
        p_id = self.request.get('id')
        if not self.user:
            self.redirect('/login')
        else:
            pkey = db.Key.from_path('Post', int(p_id), parent=blog_key())
            post = db.get(pkey)
            # Check if the user is the author of the post
            if self.user.name != post.author:
                self.redirect('/blog/%s' % p_id)
            else:
                params = dict(id = int(p_id))
                params['post'] = post
                if not post:
                    self.error(404)
                    return
                self.render('deletepost.html', **params)          

    def post(self):
        # Obtain id from the textbox
        self.id = self.request.get('id')
        pkey = db.Key.from_path('Post', int(self.id), parent=blog_key())
        post = db.get(pkey)
        # delete from datastore
        post.delete()
        self.redirect('/')
            
class EditComment(BlogHandler):
    def get(self):
        # Obtain the comment id from the get query
        c_id = self.request.get('id')
        if not self.user:
            self.redirect('/login')
        else:
            ckey = db.Key.from_path('Comment', int(c_id), parent=comment_key())
            comm = db.get(ckey)
            params = dict(id = int(c_id), comment = comm)
            # Check if the user is the author of the comment
            if self.user.name == comm.author:
                post_key = db.Key.from_path('Post', int(comm.post), parent=blog_key())
                post = db.get(post_key)
                params['post'] = post
                self.render('editcomment.html', **params)
            elif not comm:
                self.error(404)
                return
            else:
                self.redirect('/blog/%s' % post.key().id())
    def post(self):
        #Obtain id from textbox
        self.id = self.request.get('id')
        ckey = db.Key.from_path('Comment', int(self.id), parent=comment_key())
        comm = db.get(ckey)
        # Obtain new comment from textarea
        self.comm = self.request.get('comment')
        #Edit the comment and push it to the datastore
        comm.comment = self.comm
        comm.put()
        self.redirect('/blog/%s' % comm.post)

class DeleteComment(BlogHandler):
    def get(self):
        #Obtain id from get query
        c_id = self.request.get('id')
        if not self.user:
            self.redirect('/login')
        else:
            ckey = db.Key.from_path('Comment', int(c_id), parent=comment_key())
            comm = db.get(ckey)
            params = dict(id = int(c_id), comment = comm)
            # Check if user is the author of the comment
            if self.user.name == comm.author:
                pkey = db.Key.from_path('Post', int(comm.post), parent=blog_key())
                post = db.get(pkey)
                params['post'] = post
                self.render('deletecomment.html', **params) 
            elif not comm:
                self.error(404)
                return
            else:
                self.redirect('/blog/%s' % post.key().id())       
    def post(self):
        # Obtain id from textbox
        self.id = self.request.get('id')
        ckey = db.Key.from_path('Comment', int(self.id), parent=comment_key())
        comm = db.get(ckey)
        pkey = db.Key.from_path('Post', int(comm.post), parent=blog_key())
        post = db.get(pkey)
        #Delete comment and decrement from datastore
        comm.delete()
        post.comments = post.comments - 1
        post.put()
        self.redirect('/blog/%s' % post.key().id())

class LikeButton(BlogHandler):
    def get(self):
        # Fetch the post id from the get query
        self.post = self.request.get('post')
        if not self.user:
            self.redirect('/login')
        else:
            pkey = db.Key.from_path('Post', int(self.post), parent=blog_key())
            post = db.get(pkey)
            # Check if user likes a post or not
            like = db.GqlQuery("Select * FROM Like WHERE user = '%s' and post = '%s'" % (self.user.name, self.post))
            # Check if the user not the author of the post ( User cannot like his own post)
            if self.user.name != post.author: 
                like = Like(user = self.user.name, post = self.post)
                like.put()
                post.likes = post.likes + 1
                post.put()
                self.redirect('/blog/%s' % self.post)
            elif like.get():
                self.redirect('/blog/%s' % self.post)

# This variable sets the atributes of the individual HTML files that will be served using google app engine.              
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/editpost', EditPost),
                               ('/deletepost', DeletePost),
                               ('/editcomment', EditComment),
                               ('/deletecomment', DeleteComment),
                               ('/like/', LikeButton),
                               ],
                              debug=True)
