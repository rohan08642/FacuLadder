from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, timedelta
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
app.config['DEBUG'] = True  # Set to False in production

# Email configuration
app.config['MAIL_ENABLED'] = False  # Set to True when ready to send real emails
app.config['MAIL_SENDER'] = "facultyladder@gmail.com"  # Update with real email
app.config['MAIL_PASSWORD'] = "your-app-password"  # Update with app password
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Context processor to add variables to all templates
@app.context_processor
def inject_now():
    return {
        'now': datetime.now(),
        'config': app.config
    }

# Setup sqlite database
def get_db_connection():
    conn = sqlite3.connect('faculty_advancement.db')
    conn.row_factory = sqlite3.Row
    return conn

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, name, is_admin=False):
        self.id = id
        self.email = email
        self.name = name
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return User(
            id=user['id'],
            email=user['email'],
            name=user['name'],
            is_admin=user['is_admin']
        )
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Initialize the database
def init_db():
    conn = get_db_connection()
    
    # Create user table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # Create security questions table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS security_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT NOT NULL
    )
    ''')
    
    # Check if we need to add default security questions
    questions = conn.execute('SELECT * FROM security_questions').fetchall()
    if not questions:
        default_questions = [
            "What was the name of your first pet?",
            "In what city were you born?",
            "What is your mother's maiden name?",
            "What high school did you attend?",
            "What was the make of your first car?",
            "What was your childhood nickname?",
            "What is the name of your favorite childhood friend?",
            "What is your favorite movie?",
            "What street did you grow up on?"
        ]
        for question in default_questions:
            conn.execute('INSERT INTO security_questions (question) VALUES (?)', (question,))
    
    # Create user security answers table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS user_security (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        answer TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (question_id) REFERENCES security_questions (id)
    )
    ''')
    
    # Create profiles table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        designation TEXT,
        department TEXT,
        join_date TEXT,
        qualification TEXT,
        experience_years INTEGER DEFAULT 0,
        research_papers INTEGER DEFAULT 0,
        fdps_attended INTEGER DEFAULT 0,
        current_stage TEXT DEFAULT 'Assistant Professor',
        profile_picture TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Password reset table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS password_reset (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expiry TIMESTAMP NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # OTP verification table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS otp_verification (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        otp TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        verified INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Promotion requests table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS promotion_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        current_stage TEXT NOT NULL,
        requested_stage TEXT NOT NULL,
        request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'pending',
        admin_feedback TEXT,
        admin_id INTEGER,
        reviewed_date TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (admin_id) REFERENCES users (id)
    )
    ''')
    
    # Check if the profile_picture column exists in the profiles table
    # If not, add it
    try:
        columns = conn.execute('PRAGMA table_info(profiles)').fetchall()
        column_names = [column[1] for column in columns]
        
        if 'profile_picture' not in column_names:
            conn.execute('ALTER TABLE profiles ADD COLUMN profile_picture TEXT')
            conn.commit()
            print("Added profile_picture column to profiles table")
    except Exception as e:
        print(f"Error checking/adding profile_picture column: {e}")
    
    # Create achievements table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS achievements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        achievement_type TEXT NOT NULL,
        description TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_path TEXT,
        status TEXT DEFAULT 'pending',
        admin_remarks TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create notifications table
    conn.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Check if admin user exists
    admin = conn.execute('SELECT * FROM users WHERE email = ?', ('admin@example.com',)).fetchone()
    
    # Create default admin if not exists
    if not admin:
        conn.execute('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
                     ('Admin User', 'admin@example.com', generate_password_hash('admin123'), 1))
    
    # Fix file paths in the database
    fix_file_paths(conn)
    
    conn.commit()
    conn.close()

def fix_file_paths(conn):
    """
    Fix file paths in the database to use only filenames instead of full paths
    """
    try:
        # Fix achievements file paths
        achievements = conn.execute('SELECT id, file_path FROM achievements WHERE file_path IS NOT NULL').fetchall()
        
        for achievement in achievements:
            file_path = achievement['file_path']
            
            # Skip if already fixed or null
            if not file_path or '/' not in file_path and '\\' not in file_path:
                continue
                
            # Extract just the filename from the path
            filename = os.path.basename(file_path)
            
            # Update the record with just the filename
            conn.execute('UPDATE achievements SET file_path = ? WHERE id = ?', (filename, achievement['id']))
        
        # Fix profile pictures paths
        profiles = conn.execute('SELECT id, profile_picture FROM profiles WHERE profile_picture IS NOT NULL').fetchall()
        
        for profile in profiles:
            profile_picture = profile['profile_picture']
            
            # Skip if already fixed or null
            if not profile_picture or '/' not in profile_picture and '\\' not in profile_picture:
                continue
                
            # Extract just the filename from the path
            filename = os.path.basename(profile_picture)
            
            # Update the record with just the filename
            conn.execute('UPDATE profiles SET profile_picture = ? WHERE id = ?', (filename, profile['id']))
            
        conn.commit()
        print("Fixed file paths in database tables")
    except Exception as e:
        print(f"Error fixing file paths: {e}")

# Email configuration
def send_email(recipient, subject, body):
    """
    Send an email to the specified recipient
    Uses SMTP to send email through Gmail
    Falls back to console output in development mode
    """
    try:
        # Always log the email for debugging/development purposes
        print(f"EMAIL DETAILS:")
        print(f"To: {recipient}")
        print(f"Subject: {subject}")
        print(f"Body preview: {body[:100]}...")
        
        # If email sending is disabled, just return success for development
        if not app.config['MAIL_ENABLED']:
            print("Email sending is disabled. To enable, set MAIL_ENABLED to True and configure email settings.")
            return True
        
        # Create message
        message = MIMEMultipart()
        message['From'] = app.config['MAIL_SENDER']
        message['To'] = recipient
        message['Subject'] = subject
        message.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server
        if app.config['MAIL_USE_SSL']:
            server = smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
        
        # Login and send
        server.login(app.config['MAIL_SENDER'], app.config['MAIL_PASSWORD'])
        server.send_message(message)
        server.close()
        
        print(f"Email sent successfully to {recipient}")
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        # If we're in development mode, still return success
        # This way the flow continues even without email configuration
        if not app.config['MAIL_ENABLED']:
            return True
        return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            user_obj = User(
                id=user['id'],
                email=user['email'],
                name=user['name'],
                is_admin=user['is_admin']
            )
            login_user(user_obj)
            
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('faculty_dashboard'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Basic validation
        if not all([name, email, password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            conn.close()
            flash('Email already registered')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                     (name, email, hashed_password))
        
        user_id = cursor.lastrowid
        
        # Create an empty profile for the new user
        cursor.execute('INSERT INTO profiles (user_id) VALUES (?)', (user_id,))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

def generate_otp(length=6):
    """Generate a numeric OTP of specified length"""
    return ''.join(random.choice(string.digits) for _ in range(length))

# Security question password reset routes and email-based password reset (all disabled)
"""
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # Make sure OTP table exists
    ensure_otp_table_exists()
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Get database connection
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate OTP
            otp = generate_otp()
            
            # Make the OTP very visible in logs when in development mode
            if not app.config['MAIL_ENABLED']:
                print("\n" + "="*50)
                print(f"DEVELOPMENT MODE: OTP for {email}")
                print(f"OTP CODE: {otp}")
                print("="*50 + "\n")
            
            # Set OTP expiry time (15 minutes from now)
            expiry = datetime.now() + timedelta(minutes=15)
            
            # Delete any existing OTPs for this user
            conn.execute('DELETE FROM otp_verification WHERE user_id = ?', (user['id'],))
            
            # Store the new OTP in the database
            conn.execute('''
                INSERT INTO otp_verification (user_id, email, otp, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user['id'], email, otp, expiry))
            conn.commit()
            
            # Send OTP email
            subject = "FacuLadder - Password Reset OTP"
            body = f'''
<html>
<body>
    <p>Hello {user['name']},</p>
    <p>You have requested to reset your password for FacuLadder. Please use the following OTP to verify your identity:</p>
    <h2 style="text-align: center; padding: 10px; background-color: #f0f0f0; font-family: monospace;">{otp}</h2>
    <p>This OTP will expire in 15 minutes.</p>
    <p>If you did not request this password reset, please ignore this email.</p>
    <p>Regards,<br>FacuLadder Team</p>
</body>
</html>
'''
            
            email_sent = send_email(email, subject, body)
            
            if email_sent:
                flash('We have sent an OTP to your email address. Please check your inbox.', 'success')
                return redirect(url_for('verify_otp', email=email))
            else:
                flash('Error sending email. Please contact support or try again later.', 'danger')
        else:
            # For security reasons, we don't want to reveal if the email exists in our database
            flash('If your email is registered with us, you will receive an OTP shortly.', 'info')
        
        conn.close()
            
    return render_template('forgot_password.html')

@app.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        
        # Log the entered OTP for debugging
        print(f"User entered OTP: {entered_otp} for email: {email}")
        
        conn = get_db_connection()
        # Get the user ID for this email
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Log the query for debugging
            print(f"Looking for OTP in database for user ID: {user['id']}")
            
            # First fetch all OTPs for this user for debugging
            all_otps = conn.execute('''
                SELECT * FROM otp_verification 
                WHERE user_id = ? AND email = ?
            ''', (user['id'], email)).fetchall()
            
            if all_otps:
                for otp_record in all_otps:
                    print(f"Found OTP record: {dict(otp_record)}")
            else:
                print("No OTP records found for this user")
            
            # Get current time in a format SQLite can understand
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Check if there's a valid OTP for this user
            otp_record = conn.execute('''
                SELECT * FROM otp_verification 
                WHERE user_id = ? AND email = ? AND otp = ? 
                AND expires_at > ? AND verified = 0
            ''', (user['id'], email, entered_otp, current_time)).fetchone()
            
            if otp_record:
                print("Valid OTP found, marking as verified")
                # Mark OTP as verified
                conn.execute('UPDATE otp_verification SET verified = 1 WHERE id = ?', (otp_record['id'],))
                conn.commit()
                conn.close()
                
                # Redirect to reset password page
                return redirect(url_for('reset_password', email=email))
            else:
                print("Invalid OTP - no matching record found with the entered code")
                conn.close()
                flash('Invalid or expired OTP. Please try again.', 'danger')
        else:
            print(f"No user found with email: {email}")
            conn.close()
            flash('Invalid email address.', 'danger')
            return redirect(url_for('forgot_password'))
    
    return render_template('verify_otp.html', email=email)

@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user:
        conn.close()
        flash('Invalid email address.', 'danger')
        return redirect(url_for('forgot_password'))
    
    # Get current time in a format SQLite can understand
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if user has a verified OTP
    verified_otp = conn.execute('''
        SELECT * FROM otp_verification 
        WHERE user_id = ? AND email = ? AND verified = 1 AND expires_at > ?
    ''', (user['id'], email, current_time)).fetchone()
    
    if not verified_otp:
        conn.close()
        flash('Password reset session expired or invalid. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('reset_password', email=email))
        
        # Update password
        hashed_password = generate_password_hash(password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user['id']))
        
        # Clear OTP verification records
        conn.execute('DELETE FROM otp_verification WHERE user_id = ?', (user['id'],))
        conn.commit()
        conn.close()
        
        flash('Your password has been updated successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html', email=email)

@app.route('/resend-otp/<email>')
def resend_otp(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if user:
        # Generate a new OTP
        otp = generate_otp()
        
        # Make the OTP very visible in logs when in development mode
        if not app.config['MAIL_ENABLED']:
            print("\n" + "="*50)
            print(f"DEVELOPMENT MODE: RESENT OTP for {email}")
            print(f"NEW OTP CODE: {otp}")
            print("="*50 + "\n")
        
        # Set OTP expiry time (5 minutes from now)
        expiry = datetime.now() + timedelta(minutes=5)
        
        # Delete any existing OTPs for this user
        conn.execute('DELETE FROM otp_verification WHERE user_id = ?', (user['id'],))
        
        # Store the new OTP in the database
        conn.execute('''
            INSERT INTO otp_verification (user_id, email, otp, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (user['id'], email, otp, expiry))
        conn.commit()
        
        # Create email content
        subject = "New Password Reset OTP - FacuLadder"
        body = f'''
<html>
<body>
    <h2>New Password Reset OTP</h2>
    <p>Hello {user['name']},</p>
    <p>You requested a new OTP for password reset. If you didn't make this request, please ignore this email.</p>
    <p>Your new OTP for password reset is:</p>
    <h1 style="text-align: center; letter-spacing: 5px; font-family: monospace; padding: 10px; background-color: #f0f0f0;">{otp}</h1>
    <p>This OTP will expire in 5 minutes.</p>
    <p>Regards,<br>The FacuLadder Team</p>
</body>
</html>
'''
        
        # Send the email
        email_sent = send_email(email, subject, body)
        
        if email_sent:
            flash('A new OTP has been sent to your email.', 'success')
        else:
            flash('Failed to send new OTP. Please try again or contact support.', 'danger')
    else:
        # For security reasons, don't reveal if the email exists
        flash('If the email is registered with us, you will receive a new OTP shortly.', 'info')
    
    conn.close()
    return redirect(url_for('verify_otp', email=email))

@app.route('/security-reset', methods=['GET', 'POST'])
def security_reset():
    # Step 1: User enters their email
    if request.method == 'POST':
        email = request.form.get('email')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if not user:
            conn.close()
            # For security, don't reveal whether the email exists
            flash('If your email is registered with us, you will proceed to the security question.', 'info')
            return redirect(url_for('security_reset'))
        
        # Redirect to security question page
        conn.close()
        return redirect(url_for('security_question', email=email))
    
    return render_template('security_reset.html')

@app.route('/security-question/<email>', methods=['GET', 'POST'])
def security_question(email):
    # Step 2: System displays security question and user answers it
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user:
        conn.close()
        flash('Invalid email address.', 'danger')
        return redirect(url_for('security_reset'))
    
    # Get user's security question
    user_security = conn.execute('''
        SELECT sq.id, sq.question, us.id as security_id
        FROM security_questions sq
        JOIN user_security us ON sq.id = us.question_id
        WHERE us.user_id = ?
    ''', (user['id'],)).fetchone()
    
    if not user_security:
        conn.close()
        flash('Security question not set for this account. Please contact support.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        answer = request.form.get('answer').lower().strip()
        
        # Get stored answer
        stored_answer = conn.execute('''
            SELECT answer FROM user_security 
            WHERE user_id = ? AND question_id = ?
        ''', (user['id'], user_security['id'])).fetchone()
        
        if not stored_answer or stored_answer['answer'] != answer:
            conn.close()
            flash('Incorrect answer. Please try again.', 'danger')
            return redirect(url_for('security_question', email=email))
        
        # Generate a secure reset token
        token = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(minutes=15)
        
        # Store the token
        conn.execute('''
            DELETE FROM password_reset WHERE user_id = ?
        ''', (user['id'],))
        
        conn.execute('''
            INSERT INTO password_reset (user_id, token, expiry, used)
            VALUES (?, ?, ?, 0)
        ''', (user['id'], token, expiry))
        
        conn.commit()
        conn.close()
        
        # Redirect to set new password page
        return redirect(url_for('security_new_password', email=email, token=token))
    
    conn.close()
    return render_template('security_question.html', email=email, question=user_security['question'])

@app.route('/security-new-password/<email>/<token>', methods=['GET', 'POST'])
def security_new_password(email, token):
    # Step 3: User sets a new password after successful verification
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user:
        conn.close()
        flash('Invalid email address.', 'danger')
        return redirect(url_for('security_reset'))
    
    # Verify token
    # Get current time in a format SQLite can understand
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if user has a verified OTP
    reset_record = conn.execute('''
        SELECT * FROM password_reset 
        WHERE user_id = ? AND token = ? AND used = 0 AND expiry > ?
    ''', (user['id'], token, current_time)).fetchone()
    
    if not reset_record:
        conn.close()
        flash('Invalid or expired reset token. Please try again.', 'danger')
        return redirect(url_for('security_reset'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Both password fields are required.', 'danger')
            return redirect(url_for('security_new_password', email=email, token=token))
        
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('security_new_password', email=email, token=token))
        
        # Update password and mark token as used
        hashed_password = generate_password_hash(password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user['id']))
        conn.execute('UPDATE password_reset SET used = 1 WHERE id = ?', (reset_record['id'],))
        
        conn.commit()
        conn.close()
        
        flash('Your password has been successfully reset. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('security_new_password.html', email=email, token=token)

@app.route('/faculty/security-settings', methods=['GET', 'POST'])
@login_required
def faculty_security_settings():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    # Get current security question
    current_security = conn.execute('''
        SELECT sq.id, sq.question, us.answer 
        FROM user_security us
        JOIN security_questions sq ON us.question_id = sq.id
        WHERE us.user_id = ?
    ''', (current_user.id,)).fetchone()
    
    # Get all security questions
    security_questions = conn.execute('SELECT * FROM security_questions').fetchall()
    
    if request.method == 'POST':
        question_id = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        current_password = request.form.get('current_password')
        
        # Verify current password
        user = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()
        
        if not check_password_hash(user['password'], current_password):
            conn.close()
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('faculty_security_settings'))
        
        if current_security:
            # Update existing security question
            conn.execute('''
                UPDATE user_security
                SET question_id = ?, answer = ?
                WHERE user_id = ?
            ''', (question_id, security_answer.lower().strip(), current_user.id))
        else:
            # Insert new security question
            conn.execute('''
                INSERT INTO user_security (user_id, question_id, answer)
                VALUES (?, ?, ?)
            ''', (current_user.id, question_id, security_answer.lower().strip()))
        
        conn.commit()
        flash('Security question updated successfully.', 'success')
        return redirect(url_for('faculty_security_settings'))
    
    conn.close()
    
    return render_template('faculty_security_settings.html',
                         user=current_user,
                         current_security=current_security,
                         security_questions=security_questions)
"""

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/faculty/dashboard')
@login_required
def faculty_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    # Get user profile
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    
    # Get user achievements
    achievements = conn.execute('''
        SELECT * FROM achievements 
        WHERE user_id = ? 
        ORDER BY upload_date DESC
    ''', (current_user.id,)).fetchall()
    
    # Get unread notifications
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? AND is_read = 0
        ORDER BY created_at DESC
    ''', (current_user.id,)).fetchall()
    
    # Calculate current years of experience for display
    calculated_experience = 0
    if profile and profile['join_date']:
        calculated_experience = calculate_experience_years(profile['join_date'])
        
        # Update the database if the calculated value is different
        if calculated_experience != profile['experience_years']:
            conn.execute('UPDATE profiles SET experience_years = ? WHERE user_id = ?', 
                        (calculated_experience, current_user.id))
            conn.commit()
    
    conn.close()
    
    # Convert achievements to a list of dictionaries and ensure upload_date is a datetime object
    formatted_achievements = format_achievements(achievements)
    
    return render_template('faculty_dashboard.html', 
                          user=current_user,
                          profile=profile,
                          achievements=formatted_achievements,
                          notifications=notifications,
                          calculated_experience=calculated_experience)

@app.route('/faculty/profile', methods=['GET', 'POST'])
@login_required
def faculty_profile():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    
    if request.method == 'POST':
        designation = request.form.get('designation')
        department = request.form.get('department')
        join_date = request.form.get('join_date')
        qualification = request.form.get('qualification')
        research_papers = request.form.get('research_papers')
        fdps_attended = request.form.get('fdps_attended')
        
        # Calculate experience years automatically based on join date
        experience_years = calculate_experience_years(join_date)
        
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE profiles
            SET designation = ?, department = ?, join_date = ?, 
                qualification = ?, experience_years = ?, 
                research_papers = ?, fdps_attended = ?
            WHERE user_id = ?
        ''', (designation, department, join_date, qualification, 
              experience_years, research_papers, fdps_attended, current_user.id))
        
        conn.commit()
        flash('Profile updated successfully')
        
        # Recalculate career stage
        calculate_career_stage(current_user.id)
    
    # Get the updated profile
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    
    # Calculate current years of experience for display
    calculated_experience = 0
    if profile and profile['join_date']:
        calculated_experience = calculate_experience_years(profile['join_date'])
        
        # Update the database if the calculated value is different
        if calculated_experience != profile['experience_years']:
            conn.execute('UPDATE profiles SET experience_years = ? WHERE user_id = ?', 
                         (calculated_experience, current_user.id))
            conn.commit()
    
    conn.close()
    
    return render_template('faculty_profile.html', 
                          user=current_user, 
                          profile=profile, 
                          calculated_experience=calculated_experience)

@app.route('/faculty/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Check if the post request has the file part
    if 'profile_picture' not in request.files:
        flash('No file selected', 'warning')
        return redirect(url_for('faculty_profile'))
    
    file = request.files['profile_picture']
    
    # If the user does not select a file, the browser submits an empty file
    if file.filename == '':
        flash('No file selected', 'warning')
        return redirect(url_for('faculty_profile'))
    
    if file and allowed_file(file.filename):
        # Generate secure filename and save it
        filename = secure_filename(file.filename)
        # Add user_id as prefix to avoid filename collisions
        filename = f"{current_user.id}_profile_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Update profile picture in database (store only filename)
        conn = get_db_connection()
        conn.execute('UPDATE profiles SET profile_picture = ? WHERE user_id = ?', 
                    (filename, current_user.id))
        conn.commit()
        conn.close()
        
        flash('Profile picture uploaded successfully', 'success')
    else:
        flash('Invalid file type. Please upload an image file.', 'danger')
    
    return redirect(url_for('faculty_profile'))

@app.route('/faculty/achievements', methods=['GET', 'POST'])
@login_required
def faculty_achievements():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        achievement_type = request.form.get('achievement_type')
        file = request.files.get('file')
        
        file_path = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to filename to avoid conflicts
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{timestamp}_{filename}"
            
            try:
                # Ensure upload folder exists
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                # Save the file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Store only the filename in the database
                file_path = filename
                print(f"File saved as: {filename}")
            except Exception as e:
                print(f"Error saving file: {e}")
                flash(f"Error saving file: {e}", "danger")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO achievements (user_id, title, description, achievement_type, file_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (current_user.id, title, description, achievement_type, file_path))
        
        conn.commit()
        conn.close()
        
        flash('Achievement submitted for review')
        return redirect(url_for('faculty_achievements'))
    
    conn = get_db_connection()
    achievements = conn.execute('''
        SELECT * FROM achievements 
        WHERE user_id = ? 
        ORDER BY upload_date DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    
    # Convert achievements to a list of dictionaries and ensure upload_date is a datetime object
    formatted_achievements = format_achievements(achievements)
    
    return render_template('faculty_achievements.html', 
                          user=current_user, 
                          achievements=formatted_achievements)

@app.route('/faculty/career-tracker')
@login_required
def career_tracker():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    
    # Calculate current years of experience for display
    calculated_experience = 0
    if profile and profile['join_date']:
        calculated_experience = calculate_experience_years(profile['join_date'])
        
        # Update the database if the calculated value is different
        if calculated_experience != profile['experience_years']:
            conn.execute('UPDATE profiles SET experience_years = ? WHERE user_id = ?', 
                        (calculated_experience, current_user.id))
            conn.commit()
            
            # Get updated profile
            profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    
    # Get career progress
    # Logic to calculate progress towards next level
    progress = calculate_progress(profile)
    
    conn.close()
    
    return render_template('career_tracker.html', 
                          user=current_user, 
                          profile=profile,
                          progress=progress,
                          calculated_experience=calculated_experience)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    
    # Get all faculty members
    faculties = conn.execute('''
        SELECT u.id, u.name, u.email, p.designation, p.department, p.current_stage
        FROM users u
        LEFT JOIN profiles p ON u.id = p.user_id
        WHERE u.is_admin = 0
        ORDER BY u.name
    ''').fetchall()
    
    # Get pending achievements for review
    pending_reviews = conn.execute('''
        SELECT a.id, a.title, a.achievement_type, a.upload_date, u.name
        FROM achievements a
        JOIN users u ON a.user_id = u.id
        WHERE a.status = 'pending'
        ORDER BY a.upload_date
    ''').fetchall()
    
    # Get pending promotion requests
    pending_promotions = conn.execute('''
        SELECT pr.id, pr.current_stage, pr.requested_stage, pr.request_date, u.name
        FROM promotion_requests pr
        JOIN users u ON pr.user_id = u.id
        WHERE pr.status = 'pending'
        ORDER BY pr.request_date
    ''').fetchall()
    
    # Get recent notifications
    notifications = conn.execute('''
        SELECT * FROM notifications
        ORDER BY created_at DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    # Format datetime values for pending_reviews, pending_promotions and notifications
    formatted_pending_reviews = format_achievements(pending_reviews)
    
    formatted_pending_promotions = []
    for promotion in pending_promotions:
        promotion_dict = dict(promotion)
        if promotion_dict['request_date'] and isinstance(promotion_dict['request_date'], str):
            try:
                promotion_dict['request_date'] = datetime.strptime(promotion_dict['request_date'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                promotion_dict['request_date'] = None
        formatted_pending_promotions.append(promotion_dict)
    
    formatted_notifications = []
    for notification in notifications:
        notification_dict = dict(notification)
        # Check if created_at is a string and convert it to datetime if needed
        if notification_dict['created_at'] and isinstance(notification_dict['created_at'], str):
            try:
                notification_dict['created_at'] = datetime.strptime(notification_dict['created_at'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                # If there's an error parsing the date, set it to None
                notification_dict['created_at'] = None
        formatted_notifications.append(notification_dict)
    
    return render_template('admin_dashboard.html', 
                          user=current_user,
                          faculties=faculties,
                          pending_reviews=formatted_pending_reviews,
                          pending_promotions=formatted_pending_promotions,
                          notifications=formatted_notifications)

@app.route('/admin/faculty-list')
@login_required
def admin_faculty_list():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    faculties = conn.execute('''
        SELECT u.id, u.name, u.email, p.designation, p.department, p.current_stage
        FROM users u
        LEFT JOIN profiles p ON u.id = p.user_id
        WHERE u.is_admin = 0
        ORDER BY u.name
    ''').fetchall()
    conn.close()
    
    return render_template('admin_faculty_list.html', 
                          user=current_user,
                          faculties=faculties)

@app.route('/admin/review-achievements')
@login_required
def admin_review_achievements():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    achievements = conn.execute('''
        SELECT a.id, a.title, a.description, a.achievement_type, 
               a.file_path, a.upload_date, a.status, u.name
        FROM achievements a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.status, a.upload_date DESC
    ''').fetchall()
    conn.close()
    
    # Convert achievements to a list of dictionaries and ensure upload_date is a datetime object
    formatted_achievements = format_achievements(achievements)
    
    return render_template('admin_review_achievements.html', 
                          user=current_user,
                          achievements=formatted_achievements)

@app.route('/admin/review/<int:achievement_id>', methods=['GET', 'POST'])
@login_required
def admin_review_achievement(achievement_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        status = request.form.get('status')
        remarks = request.form.get('remarks')
        
        conn.execute('''
            UPDATE achievements
            SET status = ?, admin_remarks = ?
            WHERE id = ?
        ''', (status, remarks, achievement_id))
        
        achievement = conn.execute('SELECT user_id, title FROM achievements WHERE id = ?', (achievement_id,)).fetchone()
        
        try:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS admin_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    achievement_id INTEGER NOT NULL,
                    reviewer_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    remarks TEXT,
                    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (achievement_id) REFERENCES achievements (id),
                    FOREIGN KEY (reviewer_id) REFERENCES users (id)
                )
            ''')
            
            conn.execute('''
                INSERT INTO admin_reviews (achievement_id, reviewer_id, status, remarks)
                VALUES (?, ?, ?, ?)
            ''', (achievement_id, current_user.id, status, remarks))
        except Exception as e:
            print(f"Error creating/using admin_reviews table: {e}")
        
        notification_message = f"Your achievement '{achievement['title']}' has been {status}."
        conn.execute('''
            INSERT INTO notifications (user_id, message)
            VALUES (?, ?)
        ''', (achievement['user_id'], notification_message))
        
        conn.commit()
        
        if status == 'approved':
            update_faculty_metrics(achievement['user_id'], achievement_id)
        
        flash(f'Achievement has been {status}')
        return redirect(url_for('admin_review_achievements'))
    
    achievement = conn.execute('''
        SELECT a.*, u.name, u.email
        FROM achievements a
        JOIN users u ON a.user_id = u.id
        WHERE a.id = ?
    ''', (achievement_id,)).fetchone()
    
    conn.close()
    
    if not achievement:
        flash('Achievement not found')
        return redirect(url_for('admin_review_achievements'))
    
    return render_template('admin_review_achievement.html', 
                          user=current_user,
                          achievement=achievement)

@app.route('/admin/faculty/<int:faculty_id>')
@login_required
def admin_view_faculty(faculty_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    faculty = conn.execute('SELECT * FROM users WHERE id = ?', (faculty_id,)).fetchone()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (faculty_id,)).fetchone()
    achievements = conn.execute('''
        SELECT * FROM achievements 
        WHERE user_id = ? 
        ORDER BY upload_date DESC
    ''', (faculty_id,)).fetchall()
    
    # Calculate current years of experience for display
    calculated_experience = 0
    if profile and profile['join_date']:
        calculated_experience = calculate_experience_years(profile['join_date'])
        
        # Update the database if the calculated value is different
        if calculated_experience != profile['experience_years']:
            conn.execute('UPDATE profiles SET experience_years = ? WHERE user_id = ?', 
                        (calculated_experience, faculty_id))
            conn.commit()
            
            # Get updated profile
            profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (faculty_id,)).fetchone()
    
    conn.close()
    
    if not faculty:
        flash('Faculty not found')
        return redirect(url_for('admin_faculty_list'))
    
    # Convert achievements to a list of dictionaries and ensure upload_date is a datetime object
    formatted_achievements = format_achievements(achievements)
    
    return render_template('admin_view_faculty.html', 
                          user=current_user,
                          faculty=faculty,
                          profile=profile,
                          achievements=formatted_achievements,
                          calculated_experience=calculated_experience)

@app.route('/admin/update-faculty/<int:faculty_id>', methods=['POST'])
@login_required
def admin_update_faculty(faculty_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    current_stage = request.form.get('current_stage')
    
    conn = get_db_connection()
    conn.execute('''
        UPDATE profiles
        SET current_stage = ?
        WHERE user_id = ?
    ''', (current_stage, faculty_id))
    
    # Get faculty name
    faculty = conn.execute('SELECT name FROM users WHERE id = ?', (faculty_id,)).fetchone()
    
    # Add notification
    notification_message = f"Your career stage has been updated to {current_stage} by the admin."
    conn.execute('''
        INSERT INTO notifications (user_id, message)
        VALUES (?, ?)
    ''', (faculty_id, notification_message))
    
    conn.commit()
    conn.close()
    
    flash(f"Updated {faculty['name']}'s career stage to {current_stage}")
    return redirect(url_for('admin_view_faculty', faculty_id=faculty_id))

@app.route('/notifications')
@login_required
def notifications():
    """Route to display all notifications for the current user"""
    # Get current user's role
    cursor = get_db_connection().cursor()
    
    if current_user.is_admin:
        # Admin sees all notifications
        cursor.execute('''
            SELECT * FROM notifications 
            ORDER BY created_at DESC
        ''')
    else:
        # Faculty only sees their own notifications
        cursor.execute('''
            SELECT * FROM notifications 
            WHERE user_id = ? OR user_id IS NULL
            ORDER BY created_at DESC
        ''', (current_user.id,))
    
    notifications = cursor.fetchall()
    
    return render_template('notifications.html', 
                           notifications=notifications,
                           user=current_user)

@app.route('/faculty/report')
@login_required
def faculty_report():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (current_user.id,)).fetchone()
    achievements = conn.execute('''
        SELECT * FROM achievements 
        WHERE user_id = ? AND status = 'approved'
        ORDER BY upload_date DESC
    ''', (current_user.id,)).fetchall()
    
    # Calculate current years of experience for display
    calculated_experience = 0
    if profile and profile['join_date']:
        calculated_experience = calculate_experience_years(profile['join_date'])
        
        # Update the database if the calculated value is different
        if calculated_experience != profile['experience_years']:
            conn.execute('UPDATE profiles SET experience_years = ? WHERE user_id = ?', 
                        (calculated_experience, current_user.id))
            conn.commit()
    
    conn.close()
    
    # Convert achievements to a list of dictionaries and ensure upload_date is a datetime object
    formatted_achievements = format_achievements(achievements)
    
    return render_template('faculty_report.html', 
                          user=current_user,
                          profile=profile,
                          achievements=formatted_achievements,
                          calculated_experience=calculated_experience)

# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Ensure there's no path traversal
    filename = os.path.basename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Route to download files with attachment disposition
@app.route('/download/<filename>')
def download_file(filename):
    # Ensure there's no path traversal
    filename = os.path.basename(filename)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True
    )

# Route to serve profile pictures
@app.route('/uploads/profile/<filename>')
def profile_picture(filename):
    # Ensure there's no path traversal
    filename = os.path.basename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Temporary debug route to list files
@app.route('/debug/files')
def debug_files():
    try:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        html = "<h1>Files in upload folder</h1>"
        html += f"<p>Upload folder path: {app.config['UPLOAD_FOLDER']}</p>"
        html += "<ul>"
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
            file_size = os.path.getsize(file_path)
            html += f"<li>{file} ({file_size} bytes)</li>"
        html += "</ul>"
        return html
    except Exception as e:
        return f"Error: {str(e)}"

# Helper functions
def format_achievements(achievements):
    """Convert achievement date strings to datetime objects"""
    formatted_achievements = []
    for achievement in achievements:
        achievement_dict = dict(achievement)
        if achievement_dict['upload_date'] and isinstance(achievement_dict['upload_date'], str):
            try:
                achievement_dict['upload_date'] = datetime.strptime(achievement_dict['upload_date'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                achievement_dict['upload_date'] = None
        formatted_achievements.append(achievement_dict)
    return formatted_achievements

def calculate_career_stage(user_id):
    conn = get_db_connection()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (user_id,)).fetchone()
    
    current_stage = profile['current_stage']
    experience_years = profile['experience_years']
    research_papers = profile['research_papers']
    fdps_attended = profile['fdps_attended']
    
    eligible_for = current_stage
    
    if (current_stage == 'Assistant Professor' and 
        experience_years >= 5 and research_papers >= 3 and fdps_attended >= 5):
        eligible_for = 'Associate Professor'
    elif (current_stage == 'Associate Professor' and 
          experience_years >= 10 and research_papers >= 10 and fdps_attended >= 10):
        eligible_for = 'Professor'
    
    if eligible_for != current_stage:
        existing_request = conn.execute('''
            SELECT * FROM promotion_requests 
            WHERE user_id = ? AND status = 'pending'
        ''', (user_id,)).fetchone()
        
        if not existing_request:
            conn.execute('''
                INSERT INTO promotion_requests (user_id, current_stage, requested_stage)
                VALUES (?, ?, ?)
            ''', (user_id, current_stage, eligible_for))
            
            notification_message = f"You now meet the criteria for {eligible_for}. Your promotion request has been submitted for admin review."
            conn.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)',
                        (user_id, notification_message))
            
            user = conn.execute('SELECT name FROM users WHERE id = ?', (user_id,)).fetchone()
            admin_notification = f"{user['name']} is eligible for promotion to {eligible_for}. Please review their request."
            
            admins = conn.execute('SELECT id FROM users WHERE is_admin = 1').fetchall()
            for admin in admins:
                conn.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)',
                            (admin['id'], admin_notification))
            
            conn.commit()
    
    conn.close()
    return eligible_for

def calculate_progress(profile):
    requirements = {
        'Assistant Professor': {
            'next_stage': 'Associate Professor',
            'experience_years': 5,
            'research_papers': 3,
            'fdps_attended': 5
        },
        'Associate Professor': {
            'next_stage': 'Professor',
            'experience_years': 10,
            'research_papers': 10,
            'fdps_attended': 10
        },
        'Professor': {
            'next_stage': None,
            'experience_years': None,
            'research_papers': None,
            'fdps_attended': None
        }
    }
    
    current_stage = profile['current_stage']
    
    if current_stage not in requirements or requirements[current_stage]['next_stage'] is None:
        return {
            'next_stage': None,
            'experience_progress': 100,
            'research_progress': 100,
            'fdp_progress': 100,
            'overall_progress': 100
        }
    
    req = requirements[current_stage]
    
    experience_progress = min(100, (profile['experience_years'] / req['experience_years']) * 100)
    research_progress = min(100, (profile['research_papers'] / req['research_papers']) * 100)
    fdp_progress = min(100, (profile['fdps_attended'] / req['fdps_attended']) * 100)
    
    overall_progress = (experience_progress + research_progress + fdp_progress) / 3
    
    return {
        'next_stage': req['next_stage'],
        'experience_progress': round(experience_progress),
        'research_progress': round(research_progress),
        'fdp_progress': round(fdp_progress),
        'overall_progress': round(overall_progress)
    }

def update_faculty_metrics(user_id, achievement_id):
    conn = get_db_connection()
    
    achievement = conn.execute('SELECT achievement_type FROM achievements WHERE id = ?', (achievement_id,)).fetchone()
    
    achievement_type = achievement['achievement_type']
    
    if achievement_type == 'Research Paper':
        conn.execute('UPDATE profiles SET research_papers = research_papers + 1 WHERE user_id = ?', (user_id,))
    elif achievement_type == 'FDP Attended':
        conn.execute('UPDATE profiles SET fdps_attended = fdps_attended + 1 WHERE user_id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    calculate_career_stage(user_id)

def calculate_experience_years(join_date):
    """Calculate years of experience based on join date"""
    if not join_date:
        return 0
    
    try:
        if isinstance(join_date, str):
            join_date = datetime.strptime(join_date, '%Y-%m-%d').date()
        
        today = datetime.now().date()
        years_diff = today.year - join_date.year
        
        if (today.month, today.day) < (join_date.month, join_date.day):
            years_diff -= 1
            
        return max(0, years_diff)
    except Exception as e:
        print(f"Error calculating experience years: {e}")
        return 0

@app.route('/admin/promotion-requests')
@login_required
def admin_promotion_requests():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    promotion_requests = conn.execute('''
        SELECT pr.*, u.name, u.email, p.department, p.designation, p.experience_years, 
               p.research_papers, p.fdps_attended
        FROM promotion_requests pr
        JOIN users u ON pr.user_id = u.id
        JOIN profiles p ON pr.user_id = p.user_id
        ORDER BY pr.status, pr.request_date DESC
    ''').fetchall()
    
    # Format date values
    formatted_requests = []
    for request in promotion_requests:
        request_dict = dict(request)
        # Convert request_date
        if request_dict['request_date'] and isinstance(request_dict['request_date'], str):
            try:
                request_dict['request_date'] = datetime.strptime(request_dict['request_date'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                request_dict['request_date'] = None
        
        # Convert reviewed_date
        if request_dict['reviewed_date'] and isinstance(request_dict['reviewed_date'], str):
            try:
                request_dict['reviewed_date'] = datetime.strptime(request_dict['reviewed_date'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                request_dict['reviewed_date'] = None
                
        formatted_requests.append(request_dict)
    
    conn.close()
    
    return render_template('admin_promotion_requests.html',
                          user=current_user,
                          promotion_requests=formatted_requests)

@app.route('/admin/review-promotion/<int:request_id>', methods=['GET', 'POST'])
@login_required
def admin_review_promotion(request_id):
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('faculty_dashboard'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        status = request.form.get('status')
        feedback = request.form.get('feedback')
        
        promotion_request = conn.execute('''
            SELECT pr.*, u.name, u.id as user_id
            FROM promotion_requests pr
            JOIN users u ON pr.user_id = u.id
            WHERE pr.id = ?
        ''', (request_id,)).fetchone()
        
        if not promotion_request:
            conn.close()
            flash('Promotion request not found')
            return redirect(url_for('admin_promotion_requests'))
        
        conn.execute('''
            UPDATE promotion_requests
            SET status = ?, admin_feedback = ?, admin_id = ?, reviewed_date = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, feedback, current_user.id, request_id))
        
        if status == 'approved':
            conn.execute('''
                UPDATE profiles
                SET current_stage = ?
                WHERE user_id = ?
            ''', (promotion_request['requested_stage'], promotion_request['user_id']))
        
        notification_message = f"Your promotion request to {promotion_request['requested_stage']} has been {status}."
        if feedback:
            notification_message += f" Admin feedback: {feedback}"
        
        conn.execute('''
            INSERT INTO notifications (user_id, message)
            VALUES (?, ?)
        ''', (promotion_request['user_id'], notification_message))
        
        conn.commit()
        conn.close()
        
        flash(f"Promotion request for {promotion_request['name']} has been {status}")
        return redirect(url_for('admin_promotion_requests'))
    
    promotion_request = conn.execute('''
        SELECT pr.*, u.name, u.email, p.department, p.designation, p.experience_years, 
               p.research_papers, p.fdps_attended, p.join_date, p.qualification
        FROM promotion_requests pr
        JOIN users u ON pr.user_id = u.id
        JOIN profiles p ON pr.user_id = p.user_id
        WHERE pr.id = ?
    ''', (request_id,)).fetchone()
    
    if not promotion_request:
        conn.close()
        flash('Promotion request not found')
        return redirect(url_for('admin_promotion_requests'))
    
    if promotion_request and promotion_request['request_date'] and isinstance(promotion_request['request_date'], str):
        try:
            promotion_request_dict = dict(promotion_request)
            promotion_request_dict['request_date'] = datetime.strptime(promotion_request_dict['request_date'], '%Y-%m-%d %H:%M:%S')
            promotion_request = promotion_request_dict
        except ValueError:
            pass
    
    conn.close()
    
    return render_template('admin_review_promotion.html',
                          user=current_user,
                          promotion_request=promotion_request)

# Debug route to show OTP for development purposes
@app.route('/debug/otp/<email>')
def debug_otp(email):
    if app.config['MAIL_ENABLED']:
        # If mail is enabled (production), don't show OTPs
        flash('This feature is only available in development mode.', 'warning')
        return redirect(url_for('verify_otp', email=email))
    
    conn = get_db_connection()
    user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('verify_otp', email=email))
    
    # Get the latest OTP for this user
    otp_record = conn.execute('''
        SELECT * FROM otp_verification 
        WHERE user_id = ? AND email = ? 
        ORDER BY created_at DESC LIMIT 1
    ''', (user['id'], email)).fetchone()
    
    conn.close()
    
    if otp_record:
        flash(f'Current OTP for {email}: {otp_record["otp"]}', 'info')
    else:
        flash('No OTP found for this user.', 'warning')
    
    return redirect(url_for('verify_otp', email=email))

# Function to ensure the OTP verification table exists
def ensure_otp_table_exists():
    conn = get_db_connection()
    
    # Check if the otp_verification table exists
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='otp_verification'").fetchall()
    
    if not tables:
        print("OTP verification table does not exist. Creating it now.")
        conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        conn.commit()
        print("OTP verification table created.")
    
    conn.close()

# Debug route to reset OTP table
@app.route('/debug/reset-otp-table')
def debug_reset_otp_table():
    if app.config['DEBUG'] or not app.config['MAIL_ENABLED']:
        conn = get_db_connection()
        
        # Drop the existing table if it exists
        conn.execute("DROP TABLE IF EXISTS otp_verification")
        
        # Create a new table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        conn.close()
        
        flash('OTP verification table has been reset.', 'success')
        return redirect(url_for('login'))
    else:
        flash('This operation is only available in development mode.', 'warning')
        return redirect(url_for('login'))

# Initialize the database and start the app
if __name__ == '__main__':
    init_db()
    app.run(debug=True) 