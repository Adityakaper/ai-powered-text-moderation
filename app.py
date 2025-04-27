from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mite@localhost/content'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secure random key in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not logged in

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=2, max=50)], render_kw={"placeholder": "Name"})
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo('password', message='Passwords must match.')],
                                     render_kw={"placeholder": "Re-enter Password"})
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email address is already registered. Please choose a different one.')

def moderate_content(text):
    categories = {
        "hate": ["hate", "disgust", "can't stand", "dislike", "detest", "loath"],
        "hate/threatening": ["threat", "attack", "kill", "hurt", "violently", "harm", "destroy"],
        "self-harm": ["self-harm", "suicide", "kill myself", "hurt myself", "suicidal"],
        "sexual": ["explicit", "porn", "sex", "nude", "sexual", "adult content"],
        "sexual/minors": ["minor", "child", "underage", "pedophile"],
        "violence": ["violence", "attack", "hurt", "kill", "assault", "beat"],
        "violence/graphic": ["gore", "blood", "graphic", "gory"]
    }

    scores = {category: 0.0 for category in categories}
    text_lower = text.lower()
    
    # Keyword weights
    primary_weight = 7.23
    secondary_weight = 4.51
    
    for category, keywords in categories.items():
        word_count = len(text_lower.split())
        for keyword in keywords:
            occurrences = text_lower.count(keyword)
            if occurrences > 0:
                # Calculate score based on occurrence frequency
                frequency = occurrences / max(1, word_count)
                base_score = primary_weight * occurrences + secondary_weight * frequency
                scores[category] += round(base_score, 2)

    # Cap the maximum score at 40.0 with decimal precision
    scores = {category: round(min(score, 40.0), 2) for category, score in scores.items()}
    return scores

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred during registration: {str(e)}', 'error')
    return render_template('register.html', form=form)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        content = ""
        if 'file' in request.files and request.files['file'].filename != "":
            file = request.files['file']
            if file.filename.endswith('.txt'):
                content = file.read().decode('utf-8')
            else:
                flash("Only .txt files are supported", 'error')
                return redirect(url_for('index'))
        else:
            content = request.form.get("content", "")

        results = moderate_content(content)
        return render_template('index.html', results=results, content=content)

    return render_template('index.html', results=None, content=None)

@app.route('/moderate', methods=['POST'])
def moderate():
    content = ""
    # Check if a file is uploaded
    if 'file' in request.files and request.files['file'].filename:
        file = request.files['file']
        if file.filename.endswith('.txt'):
            content = file.read().decode('utf-8')  # Read file content
        else:
            return jsonify({"error": "Only .txt files are supported"}), 400
    else:
        # Process text from the form
        content = request.form.get("content", "")

    # Get moderation results
    results = moderate_content(content)
    return jsonify(results)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
