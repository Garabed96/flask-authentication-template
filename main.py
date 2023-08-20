import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, Email

app = Flask(__name__)
Bootstrap(app)




app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 

# with app.app_context():
#     db.create_all()


class UserForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    email = EmailField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('register')


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')


@login_required
@app.route('/')
def home():
    return render_template("index.html", logged_in=True)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = UserForm()
    error = None
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            error='That email already exists.'
            return render_template('register.html', form=form, error=error)
        else:
            new_user = User(
                    name=(form.name.data).title(),
                    email=form.email.data,
                    password=generate_password_hash(
                        password=form.password.data,
                        method='pbkdf2:sha256',
                        salt_length=8)
                )
            try:
                print(new_user.name)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('secrets'))
            except Exception as e:
                print(e)
                return redirect('/register')
    else:
        return render_template("register.html", form=form)


@login_required
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('secrets'))
        elif user == error:
            error = 'That email does not exist, please try again'
        elif user and not check_password_hash(user.password, form.password.data):
            error = 'Password incorrect, please try again.'
            # return redirect(url_for('login'))
    return render_template("login.html", form=form, error=error)



@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", logged_in=True, name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    return send_from_directory(app.static_folder, 'files/cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=444, host='0.0.0.0')
