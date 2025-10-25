
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, abort
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DecimalField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.file import FileField, FileAllowed
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key' # Change this to a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Decorator for admin-only routes ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    annonces = db.relationship('Annonce', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('Like', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Annonce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    comments = db.relationship('Comment', backref='annonce', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='annonce', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    annonce_id = db.Column(db.Integer, db.ForeignKey('annonce.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    annonce_id = db.Column(db.Integer, db.ForeignKey('annonce.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AnnonceForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField('Create Annonce')

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')

# --- Routes ---

@app.route('/')
def home():
    latest_annonces = Annonce.query.filter_by(is_approved=True).order_by(Annonce.id.desc()).limit(5).all()
    return render_template('home.html', annonces=latest_annonces)

@app.route('/annonces')
def annonces_list():
    all_annonces = Annonce.query.filter_by(is_approved=True).order_by(Annonce.id.desc()).all()
    comment_form = CommentForm()
    return render_template('annonces.html', annonces=all_annonces, comment_form=comment_form)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = AnnonceForm()
    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            image_file = form.image.data
            image_filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_annonce = Annonce(
            title=form.title.data,
            description=form.description.data,
            price=float(form.price.data),
            image_filename=image_filename,
            author=current_user,
            is_approved=False
        )
        db.session.add(new_annonce)
        db.session.commit()
        flash('Annonce soumise pour approbation.', 'success')
        return redirect(url_for('annonces_list'))
    return render_template('add_annonce.html', form=form)

@app.route('/annonce/<int:annonce_id>/comment', methods=['POST'])
@login_required
def add_comment(annonce_id):
    form = CommentForm()
    annonce = Annonce.query.get_or_404(annonce_id)
    if form.validate_on_submit():
        comment = Comment(text=form.text.data, user_id=current_user.id, annonce_id=annonce.id)
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been added.', 'success')
    return redirect(url_for('annonces_list'))

@app.route('/annonce/<int:annonce_id>/like', methods=['POST'])
@login_required
def like_annonce(annonce_id):
    annonce = Annonce.query.get_or_404(annonce_id)
    like = Like.query.filter_by(user_id=current_user.id, annonce_id=annonce.id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('You unliked the annonce.', 'success')
    else:
        like = Like(user_id=current_user.id, annonce_id=annonce.id)
        db.session.add(like)
        db.session.commit()
        flash('You liked the annonce.', 'success')
    return redirect(url_for('annonces_list'))

@app.route('/annonce/delete/<int:annonce_id>', methods=['POST'])
@login_required
def delete_annonce(annonce_id):
    annonce = Annonce.query.get_or_404(annonce_id)
    if annonce.author != current_user and not current_user.is_admin:
        abort(403)
        
    if annonce.image_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], annonce.image_filename))
        except OSError:
            flash('Error deleting image file.', 'danger')
            
    db.session.delete(annonce)
    db.session.commit()
    flash('Annonce supprimée avec succès.', 'success')
    return redirect(request.referrer or url_for('annonces_list'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('annonces_list'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# --- Admin Routes ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    approved_annonces = Annonce.query.filter_by(is_approved=True).all()
    pending_annonces = Annonce.query.filter_by(is_approved=False).all()
    return render_template('admin_dashboard.html', users=users, approved_annonces=approved_annonces, pending_annonces=pending_annonces)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.is_admin:
        flash('Cannot delete an admin user.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Delete user's annonces first
    Annonce.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'User {user_to_delete.email} and their annonces have been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/annonce/approve/<int:annonce_id>', methods=['POST'])
@admin_required
def approve_annonce(annonce_id):
    annonce = Annonce.query.get_or_404(annonce_id)
    annonce.is_approved = True
    db.session.commit()
    flash('Annonce approuvée.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/annonce/deny/<int:annonce_id>', methods=['POST'])
@admin_required
def deny_annonce(annonce_id):
    annonce = Annonce.query.get_or_404(annonce_id)
    db.session.delete(annonce)
    db.session.commit()
    flash('Annonce refusée et supprimée.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)