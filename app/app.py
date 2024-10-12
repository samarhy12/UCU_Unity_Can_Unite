from flask import Flask, render_template, url_for, flash, redirect, request, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from itsdangerous.serializer import Serializer
from werkzeug.utils import secure_filename
import random
import os

# Initialize the app and extensions
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'agyareyraphael@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or '10836799San'

db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

if not os.path.exists('uploads'):
    os.makedirs('uploads')

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    emergency_contact_name = db.Column(db.String(100), nullable=False)
    emergency_contact_relationship = db.Column(db.String(50), nullable=False)
    emergency_contact_phone = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    ghana_card = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(60), nullable=False)
    account_number = db.Column(db.String(10), nullable=True, unique=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.full_name}', '{self.email}', '{self.account_number}')"

with app.app_context():
    db.create_all()
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        occupation = request.form.get('occupation')
        institution = request.form.get('institution')
        address = request.form.get('address')
        phone = request.form.get('phone')
        email = request.form.get('email')
        emergency_contact_name = request.form.get('emergency_contact_name')
        emergency_contact_relationship = request.form.get('emergency_contact_relationship')
        emergency_contact_phone = request.form.get('emergency_contact_phone')
        location = request.form.get('location')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        ghana_card_file = request.files.get('ghana_card')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Handle file upload
        if ghana_card_file:
            filename = secure_filename(ghana_card_file.filename)
            file_path = os.path.join('uploads', filename)
            ghana_card_file.save(file_path)  # Save the Ghana card file

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create User instance and save to DB
        user = User(
            full_name=full_name,
            occupation=occupation,
            institution=institution,
            address=address,
            phone=phone,
            email=email,
            emergency_contact_name=emergency_contact_name,
            emergency_contact_relationship=emergency_contact_relationship,
            emergency_contact_phone=emergency_contact_phone,
            location=location,
            ghana_card=filename,
            password_hash=hashed_password
        )

        db.session.add(user)
        db.session.commit()
        flash('Your account application has been submitted for validation.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    users = User.query.filter_by(account_number=None).all()  # Fetch users without account numbers
    return render_template('admin_dashboard.html', users=users)

@app.route('/user_details/<int:user_id>', methods=['GET'])
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_details.html', user=user)

@app.route('/validate_user/<int:user_id>', methods=['POST'])
@login_required
def validate_user(user_id):
    user = User.query.get_or_404(user_id)
    if user:
        user.account_number = str(random.randint(1000000000, 9999999999))
        db.session.commit()

        # Generate token for setting password
        token = user.get_reset_token()

        # Send email with account number and password creation link
        msg = Message('Your FinancePro Account Details',
                      sender='noreply@demo.com',
                      recipients=[user.email])
        msg.body = f"""Dear {user.full_name}, 

Your account has been created, and your account number is: {user.account_number}.
Please set your password by visiting the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request, please ignore this email.
"""
        mail.send(msg)

        flash(f'{user.full_name} has been validated and email sent.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_token', token=token))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()

        flash('Your password has been set. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
