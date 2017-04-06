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
    #FIXME line below will erase all data on startup, should be removed
    #But great for testing!
    rv.row_factory = sqlite3.Row
    #init_db(rv) #uncomment to init db
    return rv

def get_db():
    if not hasattr(g, "sqlite_db"):
        g.sqlite_db = connect_db();
    return g.sqlite_db;

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, "sqlite_db"):
        g.sqlite_db.close()


def init_db(db):
    with app.open_resource('db_init/schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit();

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print('Initialized the database.')

def get_user(username):
    db = get_db()
    #print(username)
    cur = db.execute("select * FROM accounts WHERE user=?", (username,))
    result = cur.fetchone()
    return result


"""VIEWS"""
#FIXME
@app.route('/')
def homepage():
    return render_template('home.html')


#display login prompt
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = dict(foo='none')
    if request.method == 'POST':
        #FIXME: handle user submission
        this_user = get_user(request.form["username"])
        if this_user:
            #FIXME check password
            valid_user = verify_password(this_user['user'], request.form['password'])
            #FIXME 3 factor auth
        else:
            valid_user = False

        if valid_user:
            session['logged_in'] = True;
            session['username'] = request.form['username']
            flash("You were logged in")
            return redirect(url_for("homepage"))
        else:
            session.pop('logged_in', None)
            #FIXME include other auth failures
            flash("Invalid Username or Password")
            return redirect(url_for("login"))
    #if this is not a post, return the login page
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("You were logged out")
    return redirect(url_for('homepage'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        flash("Please log out to register a new account.")
        return redirect(url_for('homepage'))
    elif request.method == 'POST':
        f = request.form
        reg_status = register_account(f['username'], f['passwd'], f['sec-image'], f['totp'], f['question'], f['answer'], 0)
        if reg_status['success']:
            flash("Account created successfully.  Please log in.")
            return redirect(url_for("login"))
        else:
            flash(reg_status['message'])
        #log new user to db
    #default return and GET response
    return render_template('register.html')

#TODO 404 page
#TODO TOTP (time based onetime pass)

"""CONTROLLER"""
#TODO functions to authenticate user
#FIXME stub
def verify_password(user, plain_passwd):
    db = get_db()
    cur = db.execute("select passwd, salt FROM accounts WHERE user=?", (user,))
    try:
        hashed_passwd, salt = cur.fetchone()
    #FIXME: This is very lazy exception handling
    except:
        print("DB ERROR of some sort, returning false")
        return False

    bin_salt = binascii.unhexlify(salt)
    this_hash = hash_password(plain_passwd, bin_salt)
    print("Good hash: {}".format(hashed_passwd))
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
#NOTE consider hash+salt for answer
def register_account(username, passwd, image, totp, security_question, security_answer, is_admin=False):
    status = {'success': False, 'message': "Failure: Cause unknown"}
    salt = create_salt()
    #FIXME validate username
    #FIXME validate passwd
    #FIXME validate image
    totp = 0 #FIXME placeholder value until totp is implemented.
    hashed_passwd = hash_password(passwd, binascii.unhexlify(salt))

    db = get_db()
    db.execute("insert into accounts " + \
               "values (?, ?, ?, ?, ?, ?, ?, ?)", \
               (username, is_admin, hashed_passwd, salt, totp, image, security_question, security_answer)
    )
    db.commit()
    status['success'] = True
    status['message'] = "User registered"
    #TODO remove this in final version
    for row in db.execute("select * from accounts"):
        for key_ in row.keys():
            print ("{}: {}".format(key_, row[key_]))
    return status

def hash_password(passwd, salt):
    try:
        pass_hash = hashlib.pbkdf2_hmac('sha256', passwd.encode('utf-8'), salt, HASH_ROUNDS)
    except AttributeError:
        pass_hash = hashlib.pbkdf2_hmac('sha256', passwd, salt, HASH_ROUNDS)
    result = binascii.hexlify(pass_hash)
    print("Password hash: {}".format(result))
    return result

#Gets 32 bytes of random data
def create_salt():
    binary_salt = os.urandom(32)
    return binascii.hexlify(binary_salt)

#Python idiom that more or less means, if we're running this script manually, run this code.
if __name__ == "__main__":
    app.run()
