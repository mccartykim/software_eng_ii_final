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

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, "data.db"),
    SECRET_KEY="development_key",
    USERNAME="ADMIN",
    PASSWORD="default"))

app.config.from_envvar('CYBERSLUTH_SETTINGS', silent=True)

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



#FIXME
@app.route('/')
def homepage():
    return "Hello world. NOW FIXME"

#display login prompt
@app.route('/login')
def login():
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
