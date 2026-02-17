from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import secrets
import qrcode
import io
import hmac
import hashlib
import json
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dust_collection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WEBHOOK_SECRET'] = os.environ.get('WEBHOOK_SECRET', secrets.token_hex(32))

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# ==================== MODELS ====================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), nullable=False, default='donor')
    is_active = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    donations = db.relationship('Donation', backref='donor', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    target_amount = db.Column(db.Float, default=0.0)
    collected_amount = db.Column(db.Float, default=0.0)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    qr_token = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    donations = db.relationship('Donation', backref='campaign', lazy=True)

    def generate_qr_token(self):
        self.qr_token = secrets.token_urlsafe(32)

class Donation(db.Model):
    __tablename__ = 'donations'
    id = db.Column(db.Integer, primary_key=True)
    reference_id = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50))
    is_anonymous = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    transaction_id = db.Column(db.String(100))
    receipt_id = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DustLocation(db.Model):
    __tablename__ = 'dust_locations'
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(20), default='reported')
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PaymentRequest(db.Model):
    __tablename__ = 'payment_requests'
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donations.id'), nullable=False)
    provider = db.Column(db.String(50))
    request_data = db.Column(db.Text)
    response_data = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    donation = db.relationship('Donation', backref='payment_requests')

# ==================== LOGIN MANAGER ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== DECORATORS ====================

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login_page'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== HELPER FUNCTIONS ====================

def get_request_data():
    """Helper function to get request data regardless of content type"""
    if request.is_json:
        return request.get_json()
    elif request.form:
        return request.form.to_dict()
    elif request.data:
        try:
            return json.loads(request.data.decode('utf-8'))
        except:
            return {}
    return {}

# ==================== HTML PAGE ROUTES ====================

@app.route('/')
def home():
    campaigns = Campaign.query.filter_by(is_active=True).all()
    return render_template('home.html', campaigns=campaigns)

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'worker':
        return redirect(url_for('worker_dashboard'))
    else:
        return redirect(url_for('donor_dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    total_donations = db.session.query(db.func.sum(Donation.amount)).filter_by(status='success').scalar() or 0
    total_campaigns = Campaign.query.count()
    active_campaigns = Campaign.query.filter_by(is_active=True).count()
    total_users = User.query.count()
    pending_donations = Donation.query.filter_by(status='pending').all()
    
    return render_template('admin_dashboard.html',
                         total_donations=total_donations,
                         total_campaigns=total_campaigns,
                         active_campaigns=active_campaigns,
                         total_users=total_users,
                         pending_donations=pending_donations)

@app.route('/worker/dashboard')
@login_required
@role_required('worker')
def worker_dashboard():
    locations = DustLocation.query.filter_by(assigned_to=current_user.id).all()
    total_assigned = len(locations)
    completed = sum(1 for loc in locations if loc.status == 'completed')
    in_progress = sum(1 for loc in locations if loc.status == 'in_progress')
    
    return render_template('worker_dashboard.html',
                         locations=locations,
                         total_assigned=total_assigned,
                         completed=completed,
                         in_progress=in_progress)

@app.route('/donor/dashboard')
@login_required
@role_required('donor')
def donor_dashboard():
    donations = Donation.query.filter_by(user_id=current_user.id).all()
    total_donated = sum(d.amount for d in donations if d.status == 'success')
    
    return render_template('donor_dashboard.html',
                         donations=donations,
                         total_donated=total_donated)

@app.route('/campaigns')
def campaigns_page():
    campaigns = Campaign.query.filter_by(is_active=True).all()
    return render_template('campaigns.html', campaigns=campaigns)

@app.route('/campaigns/<int:campaign_id>')
def campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('campaign_detail.html', campaign=campaign)

@app.route('/donate/<int:campaign_id>')
def donate_page(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('donate.html', campaign=campaign)

@app.route('/admin/campaigns')
@login_required
@role_required('admin')
def admin_campaigns():
    campaigns = Campaign.query.all()
    return render_template('admin_campaigns.html', campaigns=campaigns)

@app.route('/admin/campaigns/new')
@login_required
@role_required('admin')
def new_campaign_page():
    return render_template('new_campaign.html')

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/donations')
@login_required
@role_required('admin')
def admin_donations():
    donations = Donation.query.all()
    return render_template('admin_donations.html', donations=donations)

@app.route('/admin/locations')
@login_required
@role_required('admin')
def admin_locations():
    locations = DustLocation.query.all()
    workers = User.query.filter_by(role='worker').all()
    return render_template('admin_locations.html', locations=locations, workers=workers)

@app.route('/locations')
@login_required
def locations_page():
    locations = DustLocation.query.all()
    return render_template('locations.html', locations=locations)

@app.route('/locations/report')
@login_required
def report_location_page():
    return render_template('report_location.html')

@app.route('/messages')
@login_required
def messages_page():
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('messages.html', messages=messages)

@app.route('/profile')
@login_required
def profile_page():
    donations = Donation.query.filter_by(user_id=current_user.id).all()
    total_donated = sum(d.amount for d in donations if d.status == 'success')
    return render_template('profile.html', donations=donations, total_donated=total_donated)

# ==================== AUTHENTICATION API ROUTES ====================

@app.route('/api/register', methods=['POST'])
def register():
    data = get_request_data()
    
    if not data.get('username') or not data.get('email') or not data.get('password'):
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Missing required fields'}), 400
        flash('Missing required fields', 'danger')
        return redirect(url_for('register_page'))
    
    if User.query.filter_by(username=data['username']).first():
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Username already exists'}), 400
        flash('Username already exists', 'danger')
        return redirect(url_for('register_page'))
    
    if User.query.filter_by(email=data['email']).first():
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Email already exists'}), 400
        flash('Email already exists', 'danger')
        return redirect(url_for('register_page'))
    
    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data.get('full_name', ''),
        phone=data.get('phone', ''),
        role=data.get('role', 'donor')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'message': 'User registered successfully'}), 201
    
    flash('Registration successful! Please log in.', 'success')
    return redirect(url_for('login_page'))

@app.route('/api/login', methods=['POST'])
def login():
    data = get_request_data()
    
    if not data.get('username') or not data.get('password'):
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Missing credentials'}), 400
        flash('Please provide username and password', 'danger')
        return redirect(url_for('login_page'))
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Invalid credentials'}), 401
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login_page'))
    
    if not user.is_active:
        if request.content_type and 'application/json' in request.content_type:
            return jsonify({'error': 'Account is deactivated'}), 403
        flash('Your account has been deactivated', 'danger')
        return redirect(url_for('login_page'))
    
    login_user(user, remember=data.get('remember', False))
    
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }), 200
    
    flash(f'Welcome back, {user.full_name or user.username}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'message': 'Logout successful'}), 200
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# ==================== USER MANAGEMENT API ROUTES ====================

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
@role_required('admin')
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'role': user.role,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat()
    })

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@role_required('admin')
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = get_request_data()
    
    if 'email' in data and data['email'] != user.email:
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    
    if 'full_name' in data:
        user.full_name = data['full_name']
    if 'phone' in data:
        user.phone = data['phone']
    if 'role' in data:
        user.role = data['role']
    if 'is_active' in data:
        user.is_active = bool(data['is_active'])
    
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@role_required('admin')
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

# ==================== CAMPAIGN API ROUTES ====================

@app.route('/api/campaigns', methods=['GET'])
def get_campaigns():
    campaigns = Campaign.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'description': c.description,
        'target_amount': c.target_amount,
        'collected_amount': c.collected_amount,
        'start_date': c.start_date.isoformat(),
        'end_date': c.end_date.isoformat(),
        'is_active': c.is_active,
        'created_at': c.created_at.isoformat()
    } for c in campaigns])

@app.route('/api/campaigns', methods=['POST'])
@login_required
@role_required('admin')
def create_campaign():
    data = get_request_data()
    
    required_fields = ['name', 'target_amount', 'start_date', 'end_date']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    try:
        campaign = Campaign(
            name=data['name'],
            description=data.get('description', ''),
            target_amount=float(data['target_amount']),
            start_date=datetime.fromisoformat(data['start_date'].replace('Z', '+00:00')),
            end_date=datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
        )
        campaign.generate_qr_token()
        
        db.session.add(campaign)
        db.session.commit()
        
        return jsonify({
            'message': 'Campaign created successfully',
            'campaign_id': campaign.id,
            'qr_token': campaign.qr_token
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/campaigns/<int:campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return jsonify({
        'id': campaign.id,
        'name': campaign.name,
        'description': campaign.description,
        'target_amount': campaign.target_amount,
        'collected_amount': campaign.collected_amount,
        'start_date': campaign.start_date.isoformat(),
        'end_date': campaign.end_date.isoformat(),
        'is_active': campaign.is_active,
        'created_at': campaign.created_at.isoformat()
    })

@app.route('/api/campaigns/<int:campaign_id>', methods=['PUT'])
@login_required
@role_required('admin')
def update_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    data = get_request_data()
    
    if 'name' in data:
        campaign.name = data['name']
    if 'description' in data:
        campaign.description = data['description']
    if 'target_amount' in data:
        campaign.target_amount = float(data['target_amount'])
    if 'is_active' in data:
        campaign.is_active = bool(data['is_active'])
    
    db.session.commit()
    
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'message': 'Campaign updated successfully'}), 200
    
    flash('Campaign updated successfully!', 'success')
    return redirect(url_for('admin_campaigns'))

@app.route('/api/campaigns/<int:campaign_id>/qr', methods=['GET'])
def get_campaign_qr(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    
    if not campaign.qr_token:
        campaign.generate_qr_token()
        db.session.commit()
    
    qr_url = f"{request.host_url}donate/{campaign.id}?qr={campaign.qr_token}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

@app.route('/api/campaigns/<int:campaign_id>/donations', methods=['GET'])
def get_campaign_donations(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    donations = Donation.query.filter_by(campaign_id=campaign_id, status='success').all()
    
    return jsonify([{
        'id': d.id,
        'reference_id': d.reference_id,
        'amount': d.amount,
        'is_anonymous': d.is_anonymous,
        'donor_name': 'Anonymous' if d.is_anonymous else (d.donor.full_name if d.donor else 'Guest'),
        'created_at': d.created_at.isoformat()
    } for d in donations])

# ==================== DONATION API ROUTES ====================

@app.route('/api/donations', methods=['GET'])
@login_required
@role_required('admin')
def get_all_donations():
    donations = Donation.query.all()
    return jsonify([{
        'id': d.id,
        'reference_id': d.reference_id,
        'campaign_id': d.campaign_id,
        'campaign_name': d.campaign.name,
        'amount': d.amount,
        'donor_name': 'Anonymous' if d.is_anonymous else (d.donor.full_name if d.donor else 'Guest'),
        'status': d.status,
        'payment_method': d.payment_method,
        'created_at': d.created_at.isoformat()
    } for d in donations])

@app.route('/api/donations', methods=['POST'])
def create_donation():
    data = get_request_data()
    
    if 'campaign_id' not in data or 'amount' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    campaign = Campaign.query.get_or_404(data['campaign_id'])
    
    if not campaign.is_active:
        return jsonify({'error': 'Campaign is not active'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400
    
    donation = Donation(
        reference_id=f"DON-{secrets.token_hex(8).upper()}",
        campaign_id=data['campaign_id'],
        amount=amount,
        payment_method=data.get('payment_method', 'mobile_money'),
        is_anonymous=data.get('is_anonymous', False)
    )
    
    if current_user.is_authenticated and not donation.is_anonymous:
        donation.user_id = current_user.id
    
    # In a real application, you would integrate with a payment gateway here
    # For demo purposes, we auto-approve
    donation.status = 'success'
    donation.receipt_id = f"RCP-{secrets.token_hex(8).upper()}"
    donation.transaction_id = f"TXN-{secrets.token_hex(12).upper()}"
    
    campaign.collected_amount += donation.amount
    
    db.session.add(donation)
    db.session.commit()
    
    return jsonify({
        'message': 'Donation successful',
        'donation_id': donation.id,
        'reference_id': donation.reference_id,
        'receipt_id': donation.receipt_id,
        'transaction_id': donation.transaction_id,
        'amount': donation.amount
    }), 201

@app.route('/api/donations/<int:donation_id>', methods=['GET'])
@login_required
def get_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    
    # Check permissions
    if current_user.role != 'admin' and donation.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'id': donation.id,
        'reference_id': donation.reference_id,
        'campaign_id': donation.campaign_id,
        'campaign_name': donation.campaign.name,
        'amount': donation.amount,
        'status': donation.status,
        'payment_method': donation.payment_method,
        'is_anonymous': donation.is_anonymous,
        'receipt_id': donation.receipt_id,
        'transaction_id': donation.transaction_id,
        'created_at': donation.created_at.isoformat()
    })

@app.route('/api/donations/<int:donation_id>/approve', methods=['POST'])
@login_required
@role_required('admin')
def approve_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    
    if donation.status == 'success':
        return jsonify({'error': 'Donation already approved'}), 400
    
    donation.status = 'success'
    donation.receipt_id = f"RCP-{secrets.token_hex(8).upper()}"
    
    campaign = Campaign.query.get(donation.campaign_id)
    campaign.collected_amount += donation.amount
    
    db.session.commit()
    
    return jsonify({'message': 'Donation approved successfully'}), 200

@app.route('/api/donations/<int:donation_id>/reject', methods=['POST'])
@login_required
@role_required('admin')
def reject_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    
    if donation.status != 'pending':
        return jsonify({'error': 'Only pending donations can be rejected'}), 400
    
    donation.status = 'rejected'
    
    db.session.commit()
    
    return jsonify({'message': 'Donation rejected'}), 200

# ==================== DUST LOCATION API ROUTES ====================

@app.route('/api/dust-locations', methods=['GET'])
def get_dust_locations():
    locations = DustLocation.query.all()
    return jsonify([{
        'id': loc.id,
        'latitude': loc.latitude,
        'longitude': loc.longitude,
        'address': loc.address,
        'description': loc.description,
        'severity': loc.severity,
        'status': loc.status,
        'reported_by': loc.reported_by,
        'reporter_name': User.query.get(loc.reported_by).full_name if loc.reported_by else None,
        'assigned_to': loc.assigned_to,
        'assigned_name': User.query.get(loc.assigned_to).full_name if loc.assigned_to else None,
        'created_at': loc.created_at.isoformat(),
        'completed_at': loc.completed_at.isoformat() if loc.completed_at else None
    } for loc in locations])

@app.route('/api/dust-locations', methods=['POST'])
@login_required
def report_dust_location():
    data = get_request_data()
    
    required_fields = ['latitude', 'longitude']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    try:
        location = DustLocation(
            latitude=float(data['latitude']),
            longitude=float(data['longitude']),
            address=data.get('address', ''),
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            reported_by=current_user.id
        )
        
        db.session.add(location)
        db.session.commit()
        
        return jsonify({
            'message': 'Dust location reported successfully',
            'location_id': location.id
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/dust-locations/<int:location_id>', methods=['GET'])
@login_required
def get_dust_location(location_id):
    location = DustLocation.query.get_or_404(location_id)
    
    # Check permissions: admin, reporter, or assigned worker
    if (current_user.role != 'admin' and 
        location.reported_by != current_user.id and 
        location.assigned_to != current_user.id):
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'id': location.id,
        'latitude': location.latitude,
        'longitude': location.longitude,
        'address': location.address,
        'description': location.description,
        'severity': location.severity,
        'status': location.status,
        'reported_by': location.reported_by,
        'assigned_to': location.assigned_to,
        'image_url': location.image_url,
        'created_at': location.created_at.isoformat(),
        'completed_at': location.completed_at.isoformat() if location.completed_at else None
    })

@app.route('/api/dust-locations/<int:location_id>/assign', methods=['POST'])
@login_required
@role_required('admin')
def assign_dust_location(location_id):
    location = DustLocation.query.get_or_404(location_id)
    data = get_request_data()
    
    if 'worker_id' not in data:
        return jsonify({'error': 'Missing worker_id'}), 400
    
    worker = User.query.get_or_404(data['worker_id'])
    if worker.role != 'worker':
        return jsonify({'error': 'User is not a worker'}), 400
    
    location.assigned_to = worker.id
    location.status = 'assigned'
    
    db.session.commit()
    
    return jsonify({
        'message': 'Location assigned successfully',
        'worker_name': worker.full_name
    }), 200

@app.route('/api/dust-locations/<int:location_id>/update-status', methods=['POST'])
@login_required
def update_location_status(location_id):
    location = DustLocation.query.get_or_404(location_id)
    data = get_request_data()
    
    # Check permissions: admin or assigned worker
    if (current_user.role != 'admin' and 
        location.assigned_to != current_user.id):
        return jsonify({'error': 'Access denied'}), 403
    
    if 'status' not in data:
        return jsonify({'error': 'Missing status'}), 400
    
    valid_statuses = ['reported', 'assigned', 'in_progress', 'completed', 'cancelled']
    if data['status'] not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
    
    location.status = data['status']
    
    if data['status'] == 'completed':
        location.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({'message': 'Location status updated successfully'}), 200

# ==================== MESSAGE API ROUTES ====================

@app.route('/api/messages', methods=['GET'])
@login_required
def get_messages():
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.created_at.desc()).all()
    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': msg.sender.full_name if msg.sender else 'Unknown',
        'subject': msg.subject,
        'content': msg.content,
        'is_read': msg.is_read,
        'created_at': msg.created_at.isoformat()
    } for msg in messages])

@app.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    data = get_request_data()
    
    if 'receiver_id' not in data or 'content' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    receiver = User.query.get(data['receiver_id'])
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=data['receiver_id'],
        subject=data.get('subject', ''),
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({
        'message': 'Message sent successfully',
        'message_id': message.id
    }), 201

@app.route('/api/messages/<int:message_id>/read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.receiver_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    message.is_read = True
    db.session.commit()
    
    return jsonify({'message': 'Message marked as read'}), 200

@app.route('/api/users/search', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])
    
    users = User.query.filter(
        (User.username.ilike(f'%{query}%')) |
        (User.full_name.ilike(f'%{query}%')) |
        (User.email.ilike(f'%{query}%'))
    ).limit(10).all()
    
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'full_name': user.full_name,
        'email': user.email,
        'role': user.role
    } for user in users])

# ==================== STATISTICS API ROUTES ====================

@app.route('/api/statistics', methods=['GET'])
@login_required
@role_required('admin')
def get_statistics():
    total_donations = db.session.query(db.func.sum(Donation.amount)).filter_by(status='success').scalar() or 0
    total_campaigns = Campaign.query.count()
    active_campaigns = Campaign.query.filter_by(is_active=True).count()
    total_users = User.query.count()
    total_locations = DustLocation.query.count()
    completed_locations = DustLocation.query.filter_by(status='completed').count()
    
    # Recent donations
    recent_donations = Donation.query.filter_by(status='success').order_by(Donation.created_at.desc()).limit(5).all()
    
    # Campaign progress
    campaigns = Campaign.query.all()
    campaign_progress = [{
        'id': c.id,
        'name': c.name,
        'target': c.target_amount,
        'collected': c.collected_amount,
        'progress': (c.collected_amount / c.target_amount * 100) if c.target_amount > 0 else 0
    } for c in campaigns]
    
    return jsonify({
        'total_donations': total_donations,
        'total_campaigns': total_campaigns,
        'active_campaigns': active_campaigns,
        'total_users': total_users,
        'total_locations': total_locations,
        'completed_locations': completed_locations,
        'recent_donations': [{
            'id': d.id,
            'amount': d.amount,
            'campaign_name': d.campaign.name,
            'donor': 'Anonymous' if d.is_anonymous else (d.donor.full_name if d.donor else 'Guest'),
            'created_at': d.created_at.isoformat()
        } for d in recent_donations],
        'campaign_progress': campaign_progress
    })

# ==================== RECEIPT ROUTES ====================

@app.route('/receipts/<string:receipt_id>')
def get_receipt(receipt_id):
    donation = Donation.query.filter_by(receipt_id=receipt_id).first_or_404()
    return render_template('receipt.html', donation=donation)

@app.route('/api/receipts/<string:receipt_id>', methods=['GET'])
def get_receipt_data(receipt_id):
    donation = Donation.query.filter_by(receipt_id=receipt_id).first_or_404()
    
    return jsonify({
        'receipt_id': donation.receipt_id,
        'reference_id': donation.reference_id,
        'transaction_id': donation.transaction_id,
        'amount': donation.amount,
        'campaign_name': donation.campaign.name,
        'donor_name': 'Anonymous' if donation.is_anonymous else (donation.donor.full_name if donation.donor else 'Guest'),
        'donor_email': None if donation.is_anonymous else (donation.donor.email if donation.donor else None),
        'payment_method': donation.payment_method,
        'status': donation.status,
        'created_at': donation.created_at.isoformat(),
        'is_anonymous': donation.is_anonymous
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'error': 'Bad request'}), 400
    flash('Bad request', 'danger')
    return redirect(url_for('home'))

@app.errorhandler(403)
def forbidden(error):
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'error': 'Access forbidden'}), 403
    flash('You do not have permission to access this page.', 'danger')
    return redirect(url_for('home'))

@app.errorhandler(401)
def unauthorized(error):
    if request.content_type and 'application/json' in request.content_type:
        return jsonify({'error': 'Authentication required'}), 401
    flash('Please log in to access this page.', 'warning')
    return redirect(url_for('login_page'))


def init_db():
    """Create tables and seed initial data."""
    db.create_all()

    # Check if admin already exists to avoid duplicate seeding
    if User.query.filter_by(username='admin').first() is not None:
        return  # Data already seeded

    # Create default users
    admin = User(
        username='admin',
        email='admin@dustcollection.com',
        full_name='System Administrator',
        role='admin',
        is_active=True
    )
    admin.set_password('admin123')
    db.session.add(admin)

    worker = User(
        username='worker1',
        email='worker1@dustcollection.com',
        full_name='John Worker',
        role='worker',
        is_active=True
    )
    worker.set_password('worker123')
    db.session.add(worker)

    donor = User(
        username='donor1',
        email='donor1@dustcollection.com',
        full_name='Jane Donor',
        role='donor',
        is_active=True
    )
    donor.set_password('donor123')
    db.session.add(donor)

    # Flush to assign IDs (but not commit yet, so we can rollback if something fails)
    db.session.flush()

    # Create sample campaigns
    campaign = Campaign(
        name='Clean Streets 2026',
        description='Help us keep our streets clean and dust-free. This campaign aims to collect donations for dust collection equipment and worker salaries.',
        target_amount=10000.00,
        collected_amount=0.00,
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=30),
        is_active=True
    )
    campaign.generate_qr_token()
    db.session.add(campaign)

    campaign2 = Campaign(
        name='School Cleanup Initiative',
        description='Providing dust-free environments for schools in rural areas. Every donation helps us equip schools with proper dust management systems.',
        target_amount=5000.00,
        collected_amount=0.00,
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=45),
        is_active=True
    )
    campaign2.generate_qr_token()
    db.session.add(campaign2)

    # Create sample dust locations
    location1 = DustLocation(
        latitude=40.7128,
        longitude=-74.0060,
        address='123 Main St, New York, NY',
        description='Heavy dust accumulation near construction site',
        severity='high',
        status='reported',
        reported_by=donor.id   # Now donor.id is available after flush
    )
    db.session.add(location1)

    location2 = DustLocation(
        latitude=34.0522,
        longitude=-118.2437,
        address='456 Oak Ave, Los Angeles, CA',
        description='Dust from nearby demolition project',
        severity='medium',
        status='assigned',
        reported_by=donor.id,
        assigned_to=worker.id
    )
    db.session.add(location2)

    # Commit everything
    db.session.commit()

# Run initialization inside application context
with app.app_context():
    init_db()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)