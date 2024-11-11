from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from datetime import datetime, timedelta
import ssl
import socket
import OpenSSL
import schedule
import threading
import time
import requests
import csv
import io
import os
import logging
import ipaddress
import validators
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

# Constants from environment variables
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', 15))
WARNING_THRESHOLD = int(os.getenv('WARNING_THRESHOLD', 30))
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'password')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=443)
    expiration_date = db.Column(db.DateTime)
    last_checked = db.Column(db.DateTime)
    last_notified = db.Column(db.DateTime)
    issuer = db.Column(db.String(255))
    enabled = db.Column(db.Boolean, default=True)

    @property
    def days_left(self):
        if self.expiration_date:
            delta = self.expiration_date - datetime.now()
            return max(delta.days, 0)  # Ensure days_left is never negative
        return float('inf')  # Return a large number if there is no expiration date

class User(UserMixin):
    def __init__(self, username):
        self.id = username

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_bot_token = db.Column(db.String(255), nullable=True)
    telegram_chat_id = db.Column(db.String(255), nullable=True)
    alert_threshold = db.Column(db.Integer, default=15)
    warning_threshold = db.Column(db.Integer, default=40)
    admin_password_hash = db.Column(db.String(255), nullable=True)

@login_manager.user_loader
def load_user(username):
    if username == ADMIN_USERNAME:
        return User(username)
    return None

def is_valid_domain(domain):
    """
    Comprehensive domain validation
    """
    try:
        # Basic domain syntax validation
        if not validators.domain(domain):
            return False
        
        # Attempt to resolve domain
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.error):
        return False
    except Exception:
        return False

def send_telegram_notification(message):
    system_settings = SystemSettings.query.first()
    if system_settings and system_settings.telegram_bot_token and system_settings.telegram_chat_id:
        try:
            url = f"https://api.telegram.org/bot{system_settings.telegram_bot_token}/sendMessage"
            data = {
                "chat_id": system_settings.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            requests.post(url, data=data)
        except Exception as e:
            logging.error(f"Error sending Telegram notification: {e}")

def check_certificate(site):
    try:
        # Domain validation
        if not is_valid_domain(site.domain):
            site.status = "Invalid Domain"
            site.last_checked = datetime.now()
            site.expiration_date = None
            site.issuer = "Invalid Domain"
            db.session.commit()
            logging.error(f"Invalid domain: {site.domain}")
            return

        context = ssl.create_default_context()
        with socket.create_connection((site.domain, site.port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=site.domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                
                expiration_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                issuer = dict(x509.get_issuer().get_components())
                issuer_name = issuer.get(b'O', b'Unknown').decode('utf-8')

                site.expiration_date = expiration_date
                site.last_checked = datetime.now()
                site.issuer = issuer_name
                
                days_left = (expiration_date - datetime.now()).days
                
                system_settings = SystemSettings.query.first()
                if days_left <= system_settings.alert_threshold and (
                    not site.last_notified or 
                    datetime.now() - site.last_notified > timedelta(days=1)
                ):
                    message = f" 🚨 ALERT: SSL Certificate for {site.domain} expires in {days_left} days!"
                    send_telegram_notification(message)
                    site.last_notified = datetime.now()
                elif days_left <= system_settings.warning_threshold and (
                    not site.last_notified or 
                    datetime.now() - site.last_notified > timedelta(days=7)
                ):
                    message = f"⚠️ WARNING: SSL Certificate for {site.domain} expires in {days_left} days."
                    send_telegram_notification(message)
                    site.last_notified = datetime.now()
                
                db.session.commit()
    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error for {site.domain}: {ssl_error}")
    except socket.gaierror as addr_error:
        logging.error(f"Address error for {site.domain}: {addr_error}")
    except Exception as e:
        logging.error(f"Error checking certificate for {site.domain}: {e}")
        
def check_certificates():
    with app.app_context():
        sites = Site.query.filter_by(enabled=True).all()
        for site in sites:
            check_certificate(site)

def run_schedule():
    while True:
        schedule.run_pending()
        time.sleep(1)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        system_settings = SystemSettings.query.first()
        
        if username == ADMIN_USERNAME and (
            (not system_settings.admin_password_hash) or 
            check_password_hash(system_settings.admin_password_hash, password)
        ):
            user = User(username)
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    sites = Site.query.all()
    return render_template('index.html', sites=sites)

@app.route('/add_site', methods=['POST'])
@login_required
def add_site():
    try:
        data = request.get_json() or request.form
        domain = data.get('domain')
        port = int(data.get('port', 443))

        if not domain:
            return jsonify({'success': False, 'message': 'Domain is required'})

        existing_site = Site.query.filter_by(domain=domain, port=port).first()
        if existing_site:
            return jsonify({'success': False, 'message': 'Site already exists'})

        site = Site(domain=domain, port=port, enabled=True)
        db.session.add(site)
        db.session.commit()

        check_certificate(site)

        return jsonify({
            'success': True,
            'message': 'Site added successfully',
            'site': {
                'id': site.id,
                'domain': site.domain,
                'port': site.port,
                'expiration_date': site.expiration_date.isoformat() if site.expiration_date else None,
                'days_left': site.days_left,
                'last_checked': site.last_checked.isoformat() if site.last_checked else None,
                'issuer': site.issuer,
                'enabled': site.enabled
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/edit_site/<int:id>', methods=['POST'])
@login_required
def edit_site(id):
    try:
        site = Site.query.get_or_404(id)
        data = request.get_json() or request.form
        
        site.domain = data.get('domain', site.domain)
        site.port = int(data.get('port', site.port))
        site.enabled = data.get('enabled', site.enabled)
        
        db.session.commit()
        check_certificate(site)
        
        return jsonify({
            'success': True,
            'message': 'Site updated successfully',
            'site': {
                'id': site.id,
                'domain': site.domain,
                'port': site.port,
                'expiration_date': site.expiration_date.isoformat() if site.expiration_date else None,
                'days_left': site.days_left,
                'last_checked': site.last_checked.isoformat() if site.last_checked else None,
                'issuer': site.issuer,
                'enabled': site.enabled
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_site/<int:id>', methods=['POST'])
@login_required
def delete_site(id):
    try:
        site = Site.query.get_or_404(id)
        db.session.delete(site)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Site deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/export_csv')
@login_required
def export_csv():
    try:
        sites = Site.query.all()
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Domain', 'Port', 'Expiration Date', 'Days Left', 
                        'Last Checked', 'Issuer', 'Enabled'])
        
        # Write data
        for site in sites:
            writer.writerow([
                site.domain,
                site.port,
                site.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if site.expiration_date else 'N/A',
                site.days_left,
                site.last_checked.strftime('%Y-%m-%d %H:%M:%S') if site.last_checked else 'N/A',
                site.issuer,
                'Yes' if site.enabled else 'No'
            ])
        
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            attachment_filename='ssl_certificates.csv'
        )
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/check_now', methods=['POST'])
@login_required
def manual_check():
    try:
        check_certificates()
        return jsonify({'success': True, 'message': 'Certificate check completed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/get_sites')
@login_required
def get_sites():
    try:
        sites = Site.query.all()
        return jsonify([{
            'id': site.id,
            'domain': site.domain,
            'port': site.port,
            'expiration_date': site.expiration_date.isoformat() if site.expiration_date else None,
            'days_left': site.days_left,
            'last_checked': site.last_checked.isoformat() if site.last_checked else None,
            'issuer': site.issuer,
            'enabled': site.enabled
        } for site in sites])
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/toggle_site/<int:id>', methods=['POST'])
@login_required
def toggle_site(id):
    try:
        site = Site.query.get_or_404(id)
        site.enabled = not site.enabled
        db.session.commit()
        return jsonify({
            'success': True,
            'message': f'Site {"enabled" if site.enabled else "disabled"} successfully',
            'enabled': site.enabled
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Get or create system settings
            system_settings = SystemSettings.query.first()
            if not system_settings:
                system_settings = SystemSettings()
                db.session.add(system_settings)
            
            # Update Telegram settings
            if data.get('telegram_bot_token'):
                system_settings.telegram_bot_token = data['telegram_bot_token']
            if data.get('telegram_chat_id'):
                system_settings.telegram_chat_id = data['telegram_chat_id']
            
            # Update thresholds with explicit type conversion and validation
            try:
                # Alert Threshold
                if data.get('alert_threshold'):
                    alert_threshold = int(data['alert_threshold'])
                    if alert_threshold > 0:
                        system_settings.alert_threshold = alert_threshold
                    else:
                        return jsonify({
                            'success': False, 
                            'message': 'Alert threshold must be a positive number'
                        })

                # Warning Threshold
                if data.get('warning_threshold'):
                    warning_threshold = int(data['warning_threshold'])
                    if warning_threshold > 0:
                        system_settings.warning_threshold = warning_threshold
                    else:
                        return jsonify({
                            'success': False, 
                            'message': 'Warning threshold must be a positive number'
                        })
            except ValueError:
                return jsonify({
                    'success': False, 
                    'message': 'Thresholds must be valid numbers'
                })
            
            # Change password
            if data.get('current_password') and data.get('new_password'):
                # Verify current password or set first password
                if (not system_settings.admin_password_hash or 
                    check_password_hash(system_settings.admin_password_hash, data['current_password'])):
                    system_settings.admin_password_hash = generate_password_hash(data['new_password'])
                else:
                    return jsonify({'success': False, 'message': 'Current password is incorrect'})
            
            db.session.commit()
            
            # Update global variables
            global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ALERT_THRESHOLD, WARNING_THRESHOLD
            TELEGRAM_BOT_TOKEN = system_settings.telegram_bot_token or TELEGRAM_BOT_TOKEN
            TELEGRAM_CHAT_ID = system_settings.telegram_chat_id or TELEGRAM_CHAT_ID
            ALERT_THRESHOLD = system_settings.alert_threshold or ALERT_THRESHOLD
            WARNING_THRESHOLD = system_settings.warning_threshold or WARNING_THRESHOLD
            
            return jsonify({
                'success': True, 
                'message': 'Settings updated successfully',
                'settings': {
                    'telegram_bot_token': system_settings.telegram_bot_token,
                    'telegram_chat_id': system_settings.telegram_chat_id,
                    'alert_threshold': system_settings.alert_threshold,
                    'warning_threshold': system_settings.warning_threshold
                }
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    # GET request
    system_settings = SystemSettings.query.first()
    if not system_settings:
        system_settings = SystemSettings(
            alert_threshold=ALERT_THRESHOLD,
            warning_threshold=WARNING_THRESHOLD
        )
        db.session.add(system_settings)
        db.session.commit()
    
    return render_template('settings.html', settings={
        'telegram_bot_token': system_settings.telegram_bot_token or '',
        'telegram_chat_id': system_settings.telegram_chat_id or '',
        'alert_threshold': system_settings.alert_threshold,
        'warning_threshold': system_settings.warning_threshold
    })
# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Ensure a system settings record exists
        system_settings = SystemSettings.query.first()
        if not system_settings:
            system_settings = SystemSettings(
                telegram_bot_token=TELEGRAM_BOT_TOKEN,
                telegram_chat_id=TELEGRAM_CHAT_ID,
                alert_threshold=ALERT_THRESHOLD,
                warning_threshold=WARNING_THRESHOLD
            )
            db.session.add(system_settings)
            db.session.commit()
    
    # Schedule daily certificate check
    schedule.every().day.at("00:00").do(check_certificates)
    
    # Run the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_schedule)
    scheduler_thread.daemon = True  # This ensures the thread will die when the main program exits
    scheduler_thread.start()
    
    # Run initial certificate check
    check_certificates()
    
    # Start the Flask application
    app.run(host='0.0.0.0', port=8080, debug=True)
