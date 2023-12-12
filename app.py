from flask import Flask, render_template, redirect, url_for, flash,session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
import binascii ,base64
from flask_migrate import Migrate
import secrets


app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)
migrate = Migrate(app,db)

# ...........................................................................................................
# 1st way                               passsword ==> 123456
SECRET_KEY = Fernet.generate_key()
def generate_key():
    return Fernet.generate_key()

def key_to_hex(key):
    return binascii.hexlify(key).decode()

def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data.encode())

def decrypt_data(cipher_text, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(cipher_text).decode()

# ..................................................................
# 2nd way                           password   ==> 1230
# def generate_key():
#     return Fernet.generate_key()

# def key_to_hex(key):
#     return binascii.hexlify(key).decode()

# def encrypt_data(data, key):
#     cipher_suite = Fernet(key)
#     encrypted_data = cipher_suite.encrypt(data.encode())
#     return binascii.hexlify(encrypted_data).decode()

# def decrypt_data(cipher_text, key):
#     cipher_suite = Fernet(key)
#     encrypted_data = binascii.unhexlify(cipher_text)
#     return cipher_suite.decrypt(encrypted_data).decode()

# ...........................................................................................

# 3rd way                              password  ==> 123456




# ..............................................................................................................

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    encrypted_email = db.Column(db.String(120), unique=True, nullable=False)
    encrypted_password = db.Column(db.String(256), nullable=False)
    key = db.Column(db.String(44), nullable=False)  # Store the key as a string

    def __repr__(self):
        return f"User('{self.username}', '{self.encrypted_email}' '{self.encrypted_password}')"

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

@app.route("/", methods=["GET", "POST"])
def home():
    return "Welcome to the home page"

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        
        # Generate Fernet key for the user
        user_key = generate_key()

        # Convert the key to a hexadecimal string for storage
        hex_key = key_to_hex(user_key)
        

        encrypted_email = encrypt_data(form.email.data, user_key)
        print(encrypted_email)
        encrypted_password = encrypt_data(form.password.data, user_key)

        user = User(username=form.username.data, encrypted_email=encrypted_email, encrypted_password=encrypted_password, key=hex_key)

        # Store user data in the database
        db.session.add(user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template("registration.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        # if user and decrypt_data(user.encrypted_password, user.key) == password:    #for 3rd method
        decrypted_data = decrypt_data(user.encrypted_password , binascii.unhexlify(user.key)) 
        if user and decrypted_data == password:      
            print(decrypted_data)
            session['logged_in'] = True
            flash(f"Welcome back, {user.username}! You have been logged in successfully.", 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template("login.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)
