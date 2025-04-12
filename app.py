from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    bugs_created = db.relationship('Bug', backref='creator', lazy=True, foreign_keys='Bug.creator_id')
    bugs_assigned = db.relationship('Bug', backref='assignee', lazy=True, foreign_keys='Bug.assignee_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')
    priority = db.Column(db.String(20), default='Medium')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Create tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        else:
            user = User(username=username, email=email, is_admin=False)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    users = User.query.all()
    bugs = Bug.query.all()
    open_bugs = Bug.query.filter_by(status='Open').count()
    in_progress_bugs = Bug.query.filter_by(status='In Progress').count()
    closed_bugs = Bug.query.filter_by(status='Closed').count()
    
    return render_template('admin/admin_dashboard.html', 
                         users=users, 
                         bugs=bugs,
                         open_bugs=open_bugs,
                         in_progress_bugs=in_progress_bugs,
                         closed_bugs=closed_bugs)

@app.route('/admin/user/<int:user_id>')
@login_required
def user_details(user_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    user = User.query.get_or_404(user_id)
    bugs_created = Bug.query.filter_by(creator_id=user.id).all()
    bugs_assigned = Bug.query.filter_by(assignee_id=user.id).all()
    
    return render_template('admin/user_details.html', 
                         user=user, 
                         bugs_created=bugs_created,
                         bugs_assigned=bugs_assigned)

@app.route('/admin/manage_bugs')
@login_required
def manage_bugs():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    bugs = Bug.query.all()
    users = User.query.filter_by(is_admin=False).all()
    
    return render_template('admin/manage_bugs.html', bugs=bugs, users=users)

@app.route('/admin/assign_bug/<int:bug_id>', methods=['POST'])
@login_required
def assign_bug(bug_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    bug = Bug.query.get_or_404(bug_id)
    assignee_id = request.form.get('assignee_id')
    
    if assignee_id:
        bug.assignee_id = assignee_id
        bug.status = 'In Progress'
        db.session.commit()
        flash('Bug assigned successfully!', 'success')
    else:
        flash('Please select a user to assign', 'danger')
    
    return redirect(url_for('manage_bugs'))

@app.route('/admin/update_bug_status/<int:bug_id>', methods=['POST'])
@login_required
def update_bug_status(bug_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    bug = Bug.query.get_or_404(bug_id)
    status = request.form.get('status')
    
    if status:
        bug.status = status
        db.session.commit()
        flash('Bug status updated successfully!', 'success')
    else:
        flash('Please select a status', 'danger')
    
    return redirect(url_for('manage_bugs'))

@app.route('/admin/assigned_bugs')
@login_required
def assigned_bugs():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    bugs = Bug.query.filter(Bug.assignee_id.isnot(None)).all()
    return render_template('admin/assigned_bugs.html', bugs=bugs)

@app.route('/admin/bug_reports')
@login_required
def bug_reports():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    
    # Daily reports
    today = datetime.utcnow().date()
    daily_bugs = Bug.query.filter(db.func.date(Bug.created_at) == today).all()
    
    # Monthly reports
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    monthly_bugs = Bug.query.filter(
        db.func.extract('month', Bug.created_at) == current_month,
        db.func.extract('year', Bug.created_at) == current_year
    ).all()
    
    return render_template('admin/bug_reports.html', 
                         daily_bugs=daily_bugs,
                         monthly_bugs=monthly_bugs)

# User Routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    bugs_created = Bug.query.filter_by(creator_id=current_user.id).all()
    bugs_assigned = Bug.query.filter_by(assignee_id=current_user.id).all()
    
    return render_template('user/user_dashboard.html', 
                         bugs_created=bugs_created,
                         bugs_assigned=bugs_assigned)

@app.route('/user/create_bug', methods=['GET', 'POST'])
@login_required
def create_bug():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form.get('priority', 'Medium')
        
        bug = Bug(
            title=title,
            description=description,
            priority=priority,
            creator_id=current_user.id,
            status='Open'
        )
        
        db.session.add(bug)
        db.session.commit()
        flash('Bug created successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('user/create_bug.html')

@app.route('/user/assigned_bugs')
@login_required
def view_assigned_bugs():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    bugs = Bug.query.filter_by(assignee_id=current_user.id).all()
    return render_template('user/assigned_bugs.html', bugs=bugs)

@app.route('/user/update_bug_status/<int:bug_id>', methods=['POST'])
@login_required
def user_update_bug_status(bug_id):
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    bug = Bug.query.get_or_404(bug_id)
    
    if bug.assignee_id != current_user.id:
        flash('You are not authorized to update this bug', 'danger')
        return redirect(url_for('view_assigned_bugs'))
    
    status = request.form.get('status')
    
    if status:
        bug.status = status
        db.session.commit()
        flash('Bug status updated successfully!', 'success')
    else:
        flash('Please select a status', 'danger')
    
    return redirect(url_for('view_assigned_bugs'))

if __name__ == '__main__':
    app.run(debug=True)