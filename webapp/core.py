#! /usr/bin/python3
"""
Rough webapp for final
This script is basic and monolithic
I will probably split it later
"""
#Fixme: add email field and verification link
#FIXME: Forgot password link
#FIXME: add lockout
import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort,\
    render_template, flash

#The following two libraries are part of the standard Python library, and contain widely accepted hashing functions
#I will use pbkdf2, a hashing algorithm considered "good" for passwords, and definitely better than just SHA-1.
import hashlib
import binascii
import base64
import hmac
import random
import time #Used for TOTP algorithm

HASH_ROUNDS = 100000 # constant for how many rounds of SHA-256 to run on password hash

app = Flask(__name__) # start a Flask webapp from this instance
app.config.from_object(__name__) #Use config variables in this file


app.config.update(dict(
    DATABASE=os.path.join(app.root_path, "data.db"),
    RESET_DB = True, #purge and recreate DB on user registration, useful for testing
    SKIP_TOTP = True, #Consider all codes valid, useful for testing
    DUMP_TABLES = False, #Print contents of tables on insert
    SECRET_KEY="development_key", #replace in production, used to encrypt sessions cookie to prevent user modification.
    APPNAME = "Monster Lockdown Security System",
    ORGNAME = "Cybersleuth Security",
    MAX_ATTEMPTS = 3
    ))

app.config.from_envvar('CYBERSLEUTH_SETTINGS', silent=True)

"""MODEL"""

def connect_db():
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    #NOTE commented line below will erase all data on startup, should be removed unless testing
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

#find url for an image based on its title
def get_image_url(image_title):
    db = get_db()
    cur = db.execute("select * FROM images WHERE title=?", (image_title,))
    result = cur.fetchone()
    return url_for("static", filename=result['file'])

def get_random_images(exclude):
    db = get_db()
    print(exclude)
    cur = db.execute("select * FROM images WHERE title NOT LIKE ? ORDER BY RANDOM() LIMIT 8", (exclude,))
    result = []
    for row in cur.fetchall():
        result.append({'title': row['title'], 'file': url_for("static", filename=row['file'])})
    return result

def add_attempt(username):
    db = get_db()
    cur = db.execute("update accounts set attempts = attempts + 1 where user=?", (username,))
    db.commit()

def reset_attempts(username):
    db = get_db()
    cur = db.execute("update accounts set attempts = 0 where user=?", (username,))
    db.commit()

def get_attempts(username):
    db = get_db()
    cur = db.execute("select attempts from accounts where user=?", (username,))
    return int(cur.fetchone()[0])

"""VIEWS"""


@app.route('/')
def homepage():
    return render_template('home.html')


#display login prompt
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['user'] = request.form['username']
        this_user = get_user(session['user'])
        if this_user:
            #check if locked
            if (get_attempts(session['user']) > app.config['MAX_ATTEMPTS']):
                revoke(session)
                flash("Your account is locked.  Please contact your admin.")
                return redirect(url_for("homepage"))
            #check_password
            valid_user = verify_password(this_user['user'], request.form['password'])
            if valid_user:
                session['valid_password'] = True
                return redirect(url_for('image_select'))
            else:
                add_attempt(session['user'])

        #If either password or username are wrong
        valid_user = False
        revoke(session)
        flash("Invalid Username or Password")
        return redirect(url_for("login"))

    #if this is a get request, return the login page
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        flash("Reset link sent to " + request.form['email'])
        return redirect(url_for("homepage"))
    return render_template("forgot_password.html")

@app.route('/image_select', methods=['GET', 'POST'])
def image_select():
    if request.method == 'POST':
        if session.get('user'):
            user = get_user(session['user'])
            if request.form['sec-image'] == user['image']:
                session['valid_image']=True
                return redirect(url_for('totp_entry'))
        else:
            flash("Invalid image choice, please try again")
            add_attempt(session.get('user'))
            revoke(session)
            return redirect(url_for('login'))
    else:
        #FIXME: add user image and 8 random ones
        if session.get('user'):
            user = get_user(session['user'])
            sec_images = [{'title': user['image'], 'file': get_image_url(user['image'])}]
            sec_images.extend(get_random_images(user['image']))
            ran = random.randint(0, 8)
            (sec_images[0], sec_images[ran]) = (sec_images[ran], sec_images[0])
            return render_template("pictures.html", sec_images=sec_images)
        else:
            revoke(session)
            return redirect(url_for('login'))


@app.route('/totp_entry', methods=['GET', 'POST'])
def totp_entry():
    if request.method == "POST":
        if session.get('user'):
            user = get_user(session['user'])
            totpIsValid = verify_TOTP(user['totp_token'], request.form['code'])
            if totpIsValid:
                session['valid_totp'] = True
                return redirect(url_for("security_question_entry"))
        #Fall through if invalid code
        add_attempt(session.get('user'))
        revoke(session)
        flash("Invalid code.  Please try again")
        return redirect(url_for('login'))
    else:
        return render_template('totp_entry.html')

@app.route('/sec_question_entry', methods=['GET', 'POST'])
def security_question_entry():
    if session.get('user') and session['valid_totp']:
        user = get_user(session['user'])
        if request.method == 'POST':
            #FIXME add hashing for security answer
            if user['security_answer'] == request.form['security_answer']:
                session['logged_in'] = True
                reset_attempts(session['user'])
                return redirect(url_for('homepage'))
            else:
                add_attempt(session.get('user'))
                revoke(session)
                flash("Incorrect answer")
                return redirect(url_for('login'))
        else:
            security_question = user['security_question']
            return render_template("security_question_entry.html", security_question = security_question)
    else:
        revoke(session)
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        flash("Please log out to register a new account.")
        return redirect(url_for('homepage'))
    else:
        revoke(session) #Clear cookie/session for safety
    if request.method == 'POST':
        f = request.form
        reg_status = register_account(f['username'], f['passwd'], f['sec-image'], f['totp'], f['question'], f['answer'], f['email'], f['home_address'], f['phone_number'], f['social_security'])
        if reg_status['success']:
            flash("Account created successfully.  Please log in.")
            return redirect(url_for("login"))
        else:
            flash(reg_status['message'])
        #log new user to db
    #default return and GET response
    return render_template('register.html')

@app.route('/user_info')
def user_info():
    if session.get('logged_in'):
        user = get_user(session['user'])
        user_ = {'user': session['user'], 'email': user['email'], 'home_address': user['home_address'], 'social_security': user['social_security']}
        return render_template('user_info.html', user=user_)

@app.route('/logout')
def logout():
    revoke(session)
    flash("You are now logged out")
    return redirect(url_for("homepage"))


#TODO 404 page

"""CONTROLLER"""
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

#TOTP algorithm that takes a private key, a code from the user, a starting time after the unix epoch, and a time interval.  Here, we default to 0 (0 seconds after Jan 1st, 1970 in time library) and 30 seconds (a reasonable time for the user to enter a code)
def verify_TOTP(key, code, epoch=0, timeInterval=30):
    if app.config['SKIP_TOTP']:
        return True

    unix_time = time.time()
    steps = (unix_time - epoch) // timeInterval;
    valid_codes = [generate_HOTP(key, steps + x) for x in range(-1, 2)] # see what codes are okay for one step ago, now, and one step in the future
    # These three codes account for clock skew and slow user input.
    for valid_code in valid_codes:
        if code == valid_code:
            return True
    return False


# Google Authenticator has a fairly simple algorithm if you have a built-in SHA1 algorithm.  Essentially, hash, then truncate to six digits.
# resources:
#https://en.wikipedia.org/wiki/Google_Authenticator
#http://stackoverflow.com/a/23221582
def generate_HOTP(key, steps):
    try:
        hash = hmac.new(base64.b32decode(key), steps, hashlib.sha1)            #following two lines are from stackoverflow answer
    except binascii.Error:
        return 0
        offset = int(hash[-1, 16])
    binary = int(hash[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)[-6:] #take last six digits

def verify_image(image, correct_image):
    return image == correct_image

#TODO FIXME
#NOTE consider hash+salt for answer
def register_account(username, passwd, image, totp, security_question, security_answer, email, home_address, phone_number, social_security, is_admin=False, attempts=0):
    status = {'success': False, 'message': "Failure: Cause unknown"}
    salt = create_salt()
    totp = 0 #FIXME placeholder value until totp is implemented.
    hashed_passwd = hash_password(passwd, binascii.unhexlify(salt))

    db = get_db()
    if app.config['RESET_DB']: init_db(db)
    db.execute("insert into accounts " + \
               "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", \
               (username, is_admin, email, home_address, phone_number, social_security, hashed_passwd, salt, totp, image, security_question, security_answer, attempts)
    )
    db.commit()
    status['success'] = True
    status['message'] = "User registered"
    if app.config['DUMP_TABLES']:
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


#Clear out validation information between login attempts
def revoke(session):
    session.pop('user', None)
    session.pop('valid_password', None)
    session.pop('valid_image', None)
    session.pop('valid_totp', None)
    session.pop('valid_sec_question', None)
    session.pop('logged_in', None)

#Python idiom that more or less means:
#if we're running this script from the command line
#instead of from a server, run this code.
if __name__ == "__main__":
    app.run()
