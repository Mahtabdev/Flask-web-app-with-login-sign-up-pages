from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)

# Path to your SQLite database for viewing in the browser
DATABASE_PATH = 'D:/login&signup/instance/mydatabase.db'

# Secret key for session management
app.secret_key = "f673c9b4e819d94aaf5e7d13f8a451cd30963c60bd2fe4b3e77c5d6ad8b4932a"

# SQLAlchemy configuration for SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{DATABASE_PATH}'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure file upload for profile pictures
UPLOAD_FOLDER = os.path.abspath("D:/login&signup/static/uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])
    print(f"Upload folder created at: {app.config['UPLOAD_FOLDER']}")

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Utility function to check if a file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)  # Field for profile picture

# Create all tables if not already created
with app.app_context():
    db.create_all()

# Route for the home page
@app.route("/")
def home():
    return render_template("index.html")

# Route for user registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Validate password length
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered. Please log in.", "error")
            return redirect(url_for("login"))

        # Create new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Route for user login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Verify user
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

# Route for the user dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("You cannot access the dashboard without logging in. Please log in!", "error")
        return redirect(url_for("login"))

    # Retrieve user information from the database
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)

# Route for logging out
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# Route for viewing the SQLite database in the browser
@app.route("/view_database")
def view_database():
    # Connect to the SQLite database
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    # Query the database to retrieve all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    # Fetch data from each table
    data = {}
    for table_name in tables:
        table_name = table_name[0]
        cursor.execute(f"SELECT * FROM {table_name};")
        columns = [description[0] for description in cursor.description]  # Column names
        rows = cursor.fetchall()  # Table rows
        data[table_name] = {"columns": columns, "rows": rows}

    connection.close()
    return render_template("database_view.html", data=data)

# Route for updating user profile
@app.route("/update_profile", methods=["GET", "POST"])
def update_profile():
    if "user_id" not in session:
        flash("You must log in to update your profile.", "error")
        return redirect(url_for("login"))

    # Retrieve user information from the database
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")

        # Update username
        if username:
            user.username = username

        # Update email
        if email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and existing_user.id != user.id:
                flash("Email is already registered to another account.", "error")
                return redirect(url_for("update_profile"))
            user.email = email

        # Handle profile picture upload
        if "profile_pic" in request.files:
            file = request.files["profile_pic"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                user.profile_pic = filename

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("update_profile.html", user=user)

# Main entry point for the Flask application
if __name__ == "__main__":
    app.run(debug=True)
