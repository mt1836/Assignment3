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
    salt = db.Column(db.String(), nullable=False)
    posts = db.relationship('Post', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.password}', '{self.phone}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    spell_submitted = db.Column(db.Text, nullable=False)
    spell_results = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.id}', '{self.user_id}', '{self.spell_submitted}', '{self.spell_results}', '{self.date_posted}')"


class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.user_id}', '{self.login_timestamp}', '{self.logout_timestamp}')"


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
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user == None:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw((form.password.data).encode('utf-8'),salt)
                user = User(username=form.username.data, password=hashed, phone=form.phone_number.data, salt=salt)
                db.session.add(user)
                db.session.commit()
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
    logout_user()  
    user = User.query.filter_by(username=form.username.data).first()
    print(user)
    if form.validate_on_submit():
        print('hello')
        hashed_login = bcrypt.hashpw((form.password.data).encode('utf-8'),user.salt)
        if user == None:
            print('hello1')
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.username.data == user.username and hashed_login == user.password and form.phone_number.data == user.phone:
            print('hello2')
            print(form.username.data)
            print(user.username)
            print(hashed_login)
            print(user.password)
            print(form.phone_number.data)
            print(user.phone)

            login_user(user, remember=form.remember.data)
            result = 'success'
            return render_template('login.html', title='Login', form=form, result=result)
        elif hashed_login != user.password or form.username.data != user.username:
            print('hello3')
            print(form.username.data)
            print(user.username)
            print(hashed_login)
            print(user.password)
            print(form.phone_number.data)
            print(user.phone)
            result = 'Incorrect'
            return render_template('login.html', title='Login', form=form, result=result)
        elif form.phone_number.data != user.phone:
            print('hello4')
            result = 'Two-factor failure'
            return render_template('login.html', title='Login', form=form, result=result)
    else:
        print('hello5')
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
        spell_check = Post(spell_submitted=input_text, spell_results=spellcheck_results, user=current_user, date_posted=datetime.now())
        db.session.add(spell_check)
        db.session.commit()
        spellcheck_file.write(spellcheck_results)
        spellcheck_file.close()
        return render_template('spell_check.html', title='Spell Checker Results', form=form, spellcheck_results=spell_check.spell_results, input_text=spell_check.spell_submitted)
    else:
        return render_template('spell_check.html', title='Spell Checker', form=form)


setup_db()
if __name__ == '__main__':
    app.run(debug=True)
    
