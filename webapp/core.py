#! /usr/bin/python3
"""
Rough webapp for final
This script is basic and monolithic
I will probably split it later
"""
import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort,\
    render_template, flash

#The following two libraries are part of the standard Python library, and contain widely accepted hashing functions
#I will use pbkdf2, a hashing algorithm considered "good" for passwords, and definitely better than just SHA-1.
import hashlib
import binascii
HASH_ROUNDS = 100000 # constant for how many rounds of SHA-256 to run on password hash

app = Flask(__name__) # start a Flask webapp from this instance
app.config.from_object(__name__) #Use config variables in this file

#the g object serves as a place to store global data between requests and sessions


app.config.update(dict(
    DATABASE=os.path.join(app.root_path, "data.db"),
    SECRET_KEY="development_key",
    USERNAME="ADMIN",
    APPNAME = "Monster Lockdown Security System",
    ORGNAME = "Cybersleuth Security",
    PASSWORD="default"))

app.config.from_envvar('CYBERSLEUTH_SETTINGS', silent=True)

"""MODEL"""

def connect_db():
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    if not hasattr(g, "sqlite_db"):
        g.sqlite_db = connect_db();
    return g.sqlite_db;

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, "sqlite_db"):
        g.sqlite_db.close()


def init_db():
    db = get_db()
    with app.open_resource('db_init/schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit();

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print('Initialized the database.')

#TODO function to get user fields for controller
#TODO function to create and save a new user
#TODO function to enter a user's data

"""VIEWS"""

#FIXME
@app.route('/')
def homepage():
    try:
        return render_template('home.html')
    except Exception as e:
        print(e)
        return "Hello world. NOW FIXME"


#display login prompt
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = dict(foo='none')
    if request.method == 'POST':
        valid_user = True
        #FIXME: handle user submission
        #FIXME: reject invalid input
        #FIXME 3 factor auth
        if valid_user:
            session['logged_in'] = True;
            session['username'] = request.form['username']
            flash("You were logged in")
            return redirect(url_for("homepage"))
        else:
            session['logged_in'] = False
            #FIXME include other auth failures
            flash("Failure")
            return redirect(url_for("login"))
    #if this is not a post, return the login page
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("You were logged out")
    return redirect(url_for('homepage'))

@app.route('/register')
def register():
    if not session.get('logged_in'):
        flash("Please log out to register a new account.")
        return redirect(url_for('homepage'))
    else:
        return render_template('register.html')

#TODO 404 page
#TODO TOTP (time based onetime pass)

"""CONTROLLER"""
#TODO functions to authenticate user
#FIXME stub
def verify_password(user, plain_passwd):
    db = get_db()
    cur = db.execute("select passwd, salt FROM accounts WHERE 'user'=?", user)
    try:
        hashed_passwd, salt = cur.fetchone()
    #FIXME: This is very lazy exception handling
    except:
        print("DB ERROR of some sort, returning false")
        return False

    this_hash = hash_password(plain_passwd, salt)
    #NOTE: should I convert these to hexadeximal? Store the bytes?
    if this_hash == hashed_passwd:
        return True
    else:
        return False

#FIXME stub
def verify_TOMP():
    return True

#FIXME stub
def verify_image():
    return True

#TODO FIXME
def register_accout(username, passwd, image, security_question, security_answer, is_admin=False):
    salt = create_salt()
    #FIXME validate username
    #FIXME validate passwd
    #FIXME validate image
    totp = 0 #FIXME placeholder value until totp is implemented.
    hashed_passwd = hash_password()

    db = get_db()
    db.execute("insert into accounts ('user', passwd, salt," + \
               "totp_token, image, security_question, security_answer, isAdministrator) " + \
               "values (?, ?, ?, ?, ?, ?, ?)", \
               (username, hashed_passwd, salt, totp, image, security_question, security_answer, is_admin)
    )
    db.commit()
    #TODO error handling

def hash_password(passwd, salt):
    pass_hash = hashlib.pbkdf2_hmac('sha256', passwd, salt, HASH_ROUNDS)
    return binascii.hexlify(pass_hash)

#Gets 32 bytes of random data
def create_salt():
    return os.urandom(32)

#Python idiom that more or less means, if we're running this script manually, run this code.
if __name__ == "__main__":
    app.run()
