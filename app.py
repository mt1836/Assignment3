import subprocess, bcrypt
from flask import Flask, render_template, url_for, flash, redirect, session, g, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from forms import RegistrationForm, LoginForm, SpellCheckForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
#app.config['WTF_CSRF_ENABLED'] = False
userinfo = None

@app.route("/")

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    global userinfo
    global salt
    
    if request.method == 'POST':
        if form.validate_on_submit():    
            if userinfo == None:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
                userinfo = {form.username.data:{'username':form.username.data, 'password':hashed, 'phone_number':form.phone_number.data}}
                regstatus = 'Success you have been successfully registered!'
                return render_template('register.html', title='Register', form=form, regstatus=regstatus)
            elif (userinfo.get(form.username.data)) == None:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
                userinfo = {form.username.data:{'username':form.username.data, 'password':hashed, 'phone_number':form.phone_number.data}}
                regstatus = 'Success you have been successfully registered!'
                return render_template('register.html', title='Register', form=form, regstatus=regstatus)
            else:
                regstatus = 'Username already exists!'
                return render_template('register.html', title='Register', form=form, regstatus=regstatus)
        else:
            regstatus = 'Failure to register.  Please complete the required fields appropriately'
            return render_template('register.html', title='Register', form=form, regstatus=regstatus)
    else:
        return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    global userinfo
    global salt
    session.pop('user', None)   
    if userinfo == None:
        result = 'Incorrect'
        return render_template('login.html', title='Login', form=form, result=result)
    elif form.validate_on_submit():
        hashed_login = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
        if userinfo.get(form.username.data) == None:
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.phone_number.data == (userinfo.get(form.username.data)).get('phone_number') and hashed_login == (userinfo.get(form.username.data)).get('password'):
            session['user'] = form.username.data
            result = 'success'
            return render_template('login.html', title='Login', form=form, result=result)
        elif hashed_login != (userinfo.get(form.username.data)).get('password') or form.username.data != (userinfo.get(form.username.data)).get('username'):
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.phone_number.data != (userinfo.get(form.username.data)).get('phone_number'):
            result = 'Two-factor failure'
            return render_template('login.html', title='Login', form=form, result=result)
    else:
        return render_template('login.html', title='Login', form=form)


@app.route("/logout", methods=['GET'])
def logout():
    form = LoginForm()
    if userinfo == None:
        return render_template('login.html', title='Login', form=form)
    session.pop('user')
    return redirect(url_for('login'))
    

@app.route("/spell_check", methods=['GET', 'POST'])
def spell_check():
    form = SpellCheckForm()
    global input_text
    global spellcheck_results
    if g.user:
        if form.validate_on_submit():
            input_text = form.checktext.data
            input_file = open("spellcheckfile.txt","w")
            input_file.write(input_text)
            input_file.close()
            spellcheck_results = subprocess.check_output(["./a.out", "spellcheckfile.txt", "wordlist.txt"])
            spellcheck_results = spellcheck_results.decode('utf-8')
            spellcheck_results = spellcheck_results.replace("\n",", ")
            spellcheck_results = spellcheck_results.rstrip(", ")
            spellcheck_file = open("resultsfile.txt","w")
            spellcheck_file.write(spellcheck_results)
            spellcheck_file.close()
            return render_template('spell_check.html', title='Spell Checker Results', form=form, spellcheck_results=spellcheck_results, input_text=input_text)
        else:
            return render_template('spell_check.html', title='Spell Checker', form=form)
    else:
        return redirect(url_for('login'))


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


if __name__ == '__main__':
    app.run(debug=True)
