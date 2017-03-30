#! /usr/bin/python3
"""
This file is to contain logic for views, that is logic to do with templates and user interactions
Database logic goes in Model
"""

from core import app

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
