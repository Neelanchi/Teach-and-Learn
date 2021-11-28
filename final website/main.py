## IMPORTING MODULES ##
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, abort
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
# from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import secrets
from PIL import Image
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@localhost/login"
app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://sql6454558:jbr9BSbwIT@sql6.freemysqlhosting.net/sql6454558'
app.secret_key='supersecret'
# app.config['UPLOAD_FOLDER']='C:\\Users\\neela\\Desktop\\final website\\static'
db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
## if we access account page without logging in it will direct us to login page
login_manager.login_view='login'
## message will be flashed in 'info' class of bootstrap that first login and then access this page
login_manager.login_message_category='info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')


    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')


    def validate_email(self,email):
        if email.data != current_user.email:
           user = User.query.filter_by(email=email.data).first()
           if user:
                raise ValidationError('That email is already taken. Please choose a different one.')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80),unique=True, nullable=False)
    email = db.Column(db.String(120),unique=True, nullable=False)
    img_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(250), nullable=False)
    questions = db.relationship('Questions',backref='author', lazy=True)
    liked = db.relationship('Ques_like',backref='c_user', lazy=True)
    liked_ans = db.relationship('Ans_like',backref='c_user', lazy=True)

    def like_question(self, question):
        if not self.has_liked_question(question):
            like = Ques_like(u_id=self.id, q_id=question.id)
            db.session.add(like)

    def unlike_question(self, question):
        if self.has_liked_question(question):
            Ques_like.query.filter_by(
                u_id=self.id,
                q_id=question.id).delete()

    def has_liked_question(self, question):
        return Ques_like.query.filter(
            Ques_like.u_id == self.id,
            Ques_like.q_id == question.id).count() > 0

    def like_answer(self, answer):
        if not self.has_liked_answer(answer):
            like = Ans_like(u_id=self.id, a_id=answer.id)
            db.session.add(like)

    def unlike_answer(self, answer):
        if self.has_liked_answer(answer):
            Ans_like.query.filter_by(
                u_id=self.id,
                a_id=answer.id).delete()

    def has_liked_answer(self, answer):
        return Ans_like.query.filter(
            Ans_like.u_id == self.id,
            Ans_like.a_id == answer.id).count() > 0


class Questions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
    date = db.Column(db.String(80),nullable=False, default=datetime.utcnow)
    question = db.Column(db.String(80),nullable=False)
    subject = db.Column(db.String(120),nullable=False)
    extra_info = db.Column(db.String(80))
    archived = db.Column(db.Integer, default=0)
    # img=db.Column(db.String(20), nullable=True)
    likes = db.relationship('Ques_like',backref='ques', lazy=True)
    answers = db.relationship('Answer', backref='ques', lazy=True)


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    q_id = db.Column(db.Integer, db.ForeignKey('questions.id'),nullable=False)
    user = db.Column(db.Integer,nullable=False)
    answer = db.Column(db.String(80), nullable=False)
    date = db.Column(db.String(80),nullable=False, default=datetime.utcnow)
    likes = db.relationship('Ans_like', backref='ans', lazy=True)


class Ques_like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    q_id = db.Column(db.Integer,db.ForeignKey('questions.id'),nullable=False)
    u_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

class Ans_like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    a_id = db.Column(db.Integer,db.ForeignKey('answer.id'),nullable=False)
    u_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

@app.route("/")
@app.route("/home", methods=["GET", "POST"])
def home():
    if request.method == 'POST':
        # f=request.files['img_file']
        # f.save(os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(f.filename)))


        q=request.form.get('ques')
        s=request.form.get('subj')
        e=request.form.get('extra')
        user_id = current_user.id

        # img=request.form.get('img')
        question=Questions(question=q, subject=s, extra_info=e, user_id=current_user.id)
        db.session.add(question)
        db.session.commit()
        ## add redirect
        flash('Your question has been successfuly submitted.','success')
        return redirect(url_for('home'))
    # q_like=Questions_like.query.filter_by().all()
    questions = Questions.query.filter_by(archived=0).all()
    return render_template("dashboard1.html", questions = questions)


@app.route("/register",methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form =  RegisterationForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=generate_password_hash(form.password.data))
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created. You can now login','success')
        return redirect(url_for('login'))
    return render_template('register.html',title= 'Register', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form =  LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if user and bcrypt.check_password_hash(user.password.encode('utf-8'), form.password.data.encode('utf-8')):
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')

            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password','danger')
    return render_template('login.html',title='login',form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path,'static/profile_pics',picture_fn)
    output_size = (125,125)
    i=Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    form= UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture((form.picture.data))
            current_user.img_file = picture_file
        current_user.username=form.username.data
        current_user.email=form.email.data
        db.session.commit()
        flash("Your account has been updated",'success')
        return redirect(url_for('account'))
    elif request.method=='GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.img_file)
    return render_template('account.html',title='Account',image_file=image_file, form=form)

@app.route("/question/<int:question_id>",methods=['GET','POST'])
def question(question_id):
    question = Questions.query.get_or_404(question_id)
    if request.method == 'POST':
        ans=request.form.get('ans')
        question_id=question.id
        user_id = current_user.id
        answer=Answer(q_id=question_id,user=user_id,answer=ans)
        db.session.add(answer)
        db.session.commit()
        flash('Your answer has been successfuly submitted.','success')
        return redirect(url_for('question',question_id=question.id))
    else:
        answers=Answer.query.filter_by(q_id=question_id).all()
        users=User.query.filter_by().all()
        print(users[0].username)
        userDetails={}
        for user in users:
            userDetails[user.id]=user.username
        print(userDetails)
        return render_template('question.html',title=question.question, question=question,answers=answers,userDetails=userDetails)

@app.route("/userQuestionTile/<int:question_id>",methods=['GET','POST'])
def userQuestionTile(question_id):
    question = Questions.query.get_or_404(question_id)
    answers = Answer.query.filter_by(q_id=question_id).all()
    users = User.query.filter_by().all()
    print(users[0].username)
    userDetails = {}
    for user in users:
        userDetails[user.id] = user.username
    print(userDetails)
    return render_template('user_question_tile.html', title=question.question, question=question, answers=answers,userDetails=userDetails)

@app.route("/archive/<int:question_id>")
def archive(question_id):
    question=Questions.query.get(question_id)
    question.archived=1
    db.session.commit()
    flash('Your question is archived. Now only you can see this question','success')
    return redirect(url_for('user_questions'))

@app.route("/restore/<int:question_id>")
def restore(question_id):
    question=Questions.query.get(question_id)
    question.archived=0
    db.session.commit()
    flash('Your question is restored. Now everyone can see this question','success')
    return redirect(url_for('user_questions'))

@app.route("/user-questions")
def user_questions():
    questions=Questions.query.filter_by(user_id=current_user.id).all()
    return render_template('user_questions.html', questions=questions)

@app.route("/like1/<int:question_id>/<action>")
@login_required
def like_action(question_id, action):
    question = Questions.query.filter_by(id=question_id).first()
    if action == 'like':
        current_user.like_question(question)
        db.session.commit()
    if action == 'unlike':
        current_user.unlike_question(question)
        db.session.commit()
    p = Questions.query.filter_by(id=question_id).first()
    print(len(p.likes))
    return redirect(request.referrer)

@app.route("/like_ans/<int:answer_id>/<action>")
@login_required
def like_action_ans(answer_id, action):
    answer = Answer.query.filter_by(id=answer_id).first()
    if action == 'like':
        current_user.like_answer(answer)
        db.session.commit()
    if action == 'unlike':
        current_user.unlike_answer(answer)
        db.session.commit()
    p = Answer.query.filter_by(id=answer_id).first()
    print(len(p.likes))
    return redirect(request.referrer)

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/extra")
def extra():
    flash('You need to login to ask question','info')
    return redirect('home')

if __name__ == "__main__":
    app.debug = True
    app.run()