from datetime import datetime
import subprocess, bcrypt
from flask import Flask, render_template, url_for, flash, redirect, session, g, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, current_user, logout_user, login_required
from forms import RegistrationForm, LoginForm, SpellCheckForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#app.config['WTF_CSRF_ENABLED'] = False

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(11))
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.password}', '{self.phone}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    spell_submitted = db.Column(db.Text, nullable=False)
    spell_results = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.user_id}', '{self.date_posted}', '{self.spell_submitted}', '{self.spell_results}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def setup_db():
    db.drop_all()
    db.create_all()


@app.route("/")

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    global salt
    if request.method == 'POST':
        if form.validate_on_submit():
            userinfo = User.query.filter_by(username=form.username.data).first()
            if userinfo == None:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
                userinfo = User(username=form.username.data, password=hashed, phone=form.phone_number.data)
                db.session.add(userinfo)
                db.session.commit()
                print(userinfo)
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
    global salt
    session.pop('user', None)   
    user = User.query.filter_by(username=form.username.data).first()
    if form.validate_on_submit():
        hashed_login = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
        print(user)
        print(user.phone)
        print(form.phone_number.data)
        print(user.username)
        print(form.username.data)
        print(user.password)
        print(hashed_login)
        if user == None:
            print('hello1')
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.username.data == user.username and hashed_login == user.password and form.phone_number.data == user.phone:
            print('hello2')
            login_user(user, remember=form.remember.data)
            result = 'success'
            return render_template('login.html', title='Login', form=form, result=result)
        elif hashed_login != user.password or form.username.data != user.username:
            print('hello3')
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.phone_number.data != user.phone:
            result = 'Two-factor failure'
            return render_template('login.html', title='Login', form=form, result=result)
    else:
        print('hello4')
        return render_template('login.html', title='Login', form=form)


@app.route("/logout", methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('login'))
    

@app.route("/spell_check", methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheckForm()
    global input_text
    global spellcheck_results
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


setup_db()
if __name__ == '__main__':
    app.run(debug=True)
    
