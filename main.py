from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import json

with open('config.json', 'r') as c:
    params = json.load(c)["params"]

local_server = True
app = Flask(__name__)

if local_server:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['local_uri']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['prod_uri']

db = SQLAlchemy(app)

app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'studentlogin'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


bcrypt = Bcrypt(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    dob = db.Column(db.String(50))
    year_of_admn = db.Column(db.String(50))
    address = db.Column(db.String(50))
    phoneno = db.Column(db.String(50))
    email = db.Column(db.String(50))

    def __init__(self, id, name, age, gender, dob, year_of_admn, address, phoneno, email):
        self.id = id
        self.name = name
        self.age = age
        self.gender = gender
        self.dob = dob
        self.year_of_admn = year_of_admn
        self.address = address
        self.phoneno = phoneno
        self.email = email


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('index.html', params=params)


@app.route('/studentlogin', methods=['GET', 'POST'])
def studentlogin():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('student_dashboard'))
    return render_template('studentlogin.html', form=form, params=params)


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    student = Student.query.all()
    return render_template('student_dashboard.html', params=params, student=student)


@app.route('/logout', methods=['GET', 'POST'])

def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/studentregistration', methods=['GET', 'POST'])
def studentregistration():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('studentlogin'))
    return render_template('studentregistration.html', form=form, params=params)


@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin' and password == 'admin':
            return redirect('/dashboard')

    return render_template('adminlogin.html')


@app.route('/dashboard')
def dashboard():
    student = Student.query.all()
    return render_template('dashboard.html', params=params, student=student)


@app.route('/add', methods=['GET', 'POST'])
def add_student():
    student = Student.query.all()
    if request.method == 'POST':
        id = int(request.form['id'])
        name = request.form['name']
        age = int(request.form['age'])
        gender = request.form['gender']
        dob = request.form['dob']
        year_of_admn = request.form['year_of_admn']
        address = request.form['address']
        phoneno = request.form['phoneno']
        email = request.form['email']

        student = Student(id=id, name=name, age=age, gender=gender, dob=dob, year_of_admn=year_of_admn,
                          address=address, phoneno=phoneno, email=email)
        db.session.add(student)
        db.session.commit()

        return redirect('/dashboard')

    return render_template('add.html', params=params, student=student)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_student(id):
    student = Student.query.get(id)

    if request.method == 'POST':
        student.name = request.form['name']
        student.age = int(request.form['age'])
        student.gender = request.form['gender']
        student.dob = request.form['dob']
        student.year_of_admn = request.form['year_of_admn']
        student.address = request.form['address']
        student.phoneno = request.form['phoneno']
        student.email = request.form['email']

        db.session.commit()
        return redirect('/dashboard')

    return render_template('edit.html', params=params, student=student)


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete_student(id):
    student = Student.query.get(id)

    if request.method == 'POST':
        db.session.delete(student)
        db.session.commit()
        return redirect('/dashboard')

    return render_template('delete.html', student=student, params=params)


if __name__ == '__main__':
    app.run(debug=True)
