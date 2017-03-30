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

app = Flask(__name__) # start a Flask webapp from this instance
app.config.from_object(__name__) #Use config variables in this file

#the g object serves as a place to store global data between requests and sessions

g.APPNAME = "Monster Lockdown Security System"
g.ORGNAME = "Cybersleuth Security"

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, "data.db"),
    SECRET_KEY="development_key",
    USERNAME="ADMIN",
    PASSWORD="default"))

app.config.from_envvar('CYBERSLUTH_SETTINGS', silent=True)

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
@app.route('/login')
def login():
    error = dict(foo='none')
    if request.method == 'POST':
        #FIXME: handle user submission
        #FIXME: reject invalid input
        #FIXME 3 factor auth
        session['logged_in'] = True;
        flash("You were logged in")
        return redirect(url_for("homepage"))
    #if this is not a post, return the login page
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("You were logged out")
    return redirect(url_for('homepage'))

@app.route('/register')
def register():
    return "Sign up for our invite list, my pal!"

#TODO 404 page
#TODO TOTP (time based onetime pass)

"""CONTROLLER"""
#TODO functions to authenticate user


#Python idiom that more or less means, if we're running this script manually, run this code.
if __name__ == "__main__":
    app.run()
