from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from database import db, Admin, Nomination, AllowedIP
from datetime import datetime, timedelta
from functools import wraps
import os
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import traceback
from werkzeug.security import generate_password_hash, check_password_hash
import csv
from io import StringIO
import shutil
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))  # Güvenli ve gizli anahtar
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Rate Limiter tanımlanıyor
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Admin kullanıcı adı ve şifre ortam değişkenlerinden alınıyor
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']

db.init_app(app)

def create_tables():
    with app.app_context():
        db.create_all()

# Admin girişi gerekli decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin kullanıcısını oluştur
def create_admin():
    with app.app_context():
        # Veritabanı tablolarını oluştur (eğer yoksa)
        db.create_all()
        
        # Admin kullanıcısı var mı kontrol et
        admin_username = os.environ['ADMIN_USERNAME']
        admin_password = os.environ['ADMIN_PASSWORD']
        admin = Admin.query.filter_by(username=admin_username).first()
        if not admin:
            # Admin kullanıcısını oluştur
            admin = Admin(username=admin_username)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()

def standardize_twitter_handle(handle):
    """Twitter handle'ı standardize eder."""
    if not handle:
        return handle
    # Başındaki boşlukları temizle
    handle = handle.strip()
    # Sadece başlangıçtaki @@ kontrolü
    if handle.startswith('@@'):
        handle = '@' + handle[2:]
    # Eğer @ ile başlamıyorsa ekle
    if not handle.startswith('@'):
        handle = '@' + handle
    return handle

@app.route('/')
def home():
    return app.send_static_file('index.html')

@app.route('/faq')
def faq():
    return app.send_static_file('faq.html')

@app.route('/nominate-page')
def nominate_page():
    return app.send_static_file('nominate.html')

def check_category_limit(ip_address, category):
    """Bir IP'nin belirli bir kategoride daha önce oy kullanıp kullanmadığını kontrol eder."""
    existing_nomination = Nomination.query.filter_by(
        ip_address=ip_address,
        category=category
    ).first()
    return existing_nomination is None

@app.route('/api/nominate', methods=['POST'])
@limiter.limit("10 per minute")
def nominate():
    try:
        data = request.json
        print("Received data:", data)
        
        # IP adresini al
        ip_address = request.remote_addr
        print(f"Request from IP: {ip_address}")
        
        # Kategori limiti kontrolü
        if not check_category_limit(ip_address, data['category']):
            category_messages = {
                'SELFIE SORCERERS': '🚀 Looks like you\'ve already nominated your favorite selfie sorcerer!',
                'HYPE HITCHHIKERS': '👥 One hype hitchhiker nomination per person - that\'s the spirit!',
                'AISHWASHERS': '💡 Your AI washer nomination is already in the stars!',
                'MEME MINERS': '😂 Your meme miner vote is already spreading joy!',
                'BAIT LORDS': '🎣 Your bait lord nomination is already in the trap!',
                'DM DIPLOMATS': '🤫 Your DM diplomat vote is already in the shadows!',
                'GMONAD BULLIES': '💪 Your GYMONAD bully nomination is already flexing!',
                'VIRTUE VAMPIRES': '🧛 Your virtue vampire vote is already sucking engagement!'
            }
            default_message = 'Whoa there! 🐎 You\'ve already cast your vote in this category. One vote per category keeps the awards fair!'
            
            return jsonify({
                'success': False, 
                'message': category_messages.get(data['category'], default_message)
            }), 403
        
        # Standardize Twitter handles
        twitter_handle = standardize_twitter_handle(data.get('twitter_handle', ''))
        candidate = standardize_twitter_handle(data.get('candidate', ''))
        
        # Required fields check
        required_fields = ['category', 'twitter_url', 'monad_address']
        missing_fields = []
        for field in required_fields:
            if field not in data or not data[field]:
                missing_fields.append(field)
        
        if missing_fields:
            field_messages = {
                'category': 'Which category are you voting for? 🎯',
                'twitter_url': 'Don\'t forget to share the Twitter post! 🐦',
                'monad_address': 'We need your Monad address to verify your vote! 🔐'
            }
            messages = [field_messages.get(field, field) for field in missing_fields]
            return jsonify({
                'success': False, 
                'message': f'Almost there! Just fill in these missing details: {", ".join(messages)} 📝'
            }), 400
        
        if not twitter_handle or not candidate:
            if not twitter_handle and not candidate:
                return jsonify({
                    'success': False, 
                    'message': 'Hey! Don\'t forget to tell us who you\'re voting for and your Twitter handle! 🐦'
                }), 400
            elif not twitter_handle:
                return jsonify({
                    'success': False, 
                    'message': 'We need your Twitter handle to verify your vote! 🐦'
                }), 400
            else:
                return jsonify({
                    'success': False, 
                    'message': 'Who are you voting for? Don\'t forget to mention them! 🎯'
                }), 400
        
        # Twitter URL formatı kontrolü
        if not (data['twitter_url'].startswith('https://twitter.com/') or data['twitter_url'].startswith('https://x.com/')):
            return jsonify({
                'success': False,
                'message': 'That doesn\'t look like a Twitter (X) post! Make sure you\'re sharing a valid X link 🐦'
            }), 400
        
        # Monad adresi formatı kontrolü
        if not data['monad_address'].startswith('0x') or len(data['monad_address']) != 42:
            if not data['monad_address'].startswith('0x'):
                return jsonify({
                    'success': False,
                    'message': 'Your Monad address should start with 0x! 🔍'
                }), 400
            elif len(data['monad_address']) != 42:
                return jsonify({
                    'success': False,
                    'message': 'Your Monad address should be 42 characters long! 🔍'
                }), 400
        
        nomination = Nomination(
            category=data['category'],
            twitter_handle=twitter_handle,
            candidate=candidate,
            reason=data.get('reason'),
            twitter_url=data['twitter_url'],
            monad_address=data['monad_address'],
            ip_address=ip_address
        )
        
        db.session.add(nomination)
        db.session.commit()
        print("Nomination successfully saved:", nomination.id)
        
        # Başarılı mesajları kategoriye göre özelleştir
        success_messages = {
            'SELFIE SORCERERS': '🎉 Your selfie sorcerer nomination is in! Let\'s celebrate the selfie masters! 🚀',
            'HYPE HITCHHIKERS': '🎉 Your hype hitchhiker vote is recorded! Together we grow! 👥',
            'AISHWASHERS': '🎉 Your AI washer nomination is saved! Innovation never stops! 💡',
            'MEME MINERS': '🎉 Your meme miner vote is in! Keep the laughs coming! 😂',
            'BAIT LORDS': '🎉 Your bait lord nomination is saved! The trap is set! 🎣',
            'DM DIPLOMATS': '🎉 Your DM diplomat vote is recorded! Moving in silence! 🤫',
            'GMONAD BULLIES': '🎉 Your GYMONAD bully nomination is in! Flexing hard! 💪',
            'VIRTUE VAMPIRES': '🎉 Your virtue vampire vote is saved! Drama incoming! 🧛'
        }
        
        return jsonify({
            'success': True,
            'message': success_messages.get(data['category'], '🎉 Amazing! Your vote is in! Thanks for being part of the Monad Awards! 🏆')
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        db.session.rollback()
        print("Error occurred:", str(e))
        return jsonify({
            'success': False, 
            'message': 'Oops! Something\'s not quite right. Give it another try in a moment! ��'
        }), 400

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_id'] = 1
            session.permanent = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error='Invalid username or password')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/admin/api/nominations')
@admin_required
def admin_nominations():
    try:
        nominations = Nomination.query.order_by(Nomination.created_at.desc()).all()
        return jsonify([{
            'id': nom.id,
            'category': nom.category,
            'name': nom.candidate,
            'twitter': nom.twitter_handle,
            'reason': nom.reason,
            'created_at': nom.created_at.isoformat() if nom.created_at else None
        } for nom in nominations])
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")  # Hata loglaması
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/statistics')
@admin_required
def admin_statistics():
    try:
        # Toplam adaylık sayısı
        total = Nomination.query.count()
        
        # Kategori bazında toplam adaylık sayıları
        category_totals = db.session.query(
            Nomination.category,
            db.func.count(Nomination.id).label('total')
        ).group_by(Nomination.category).all()
        
        by_category = {cat: total for cat, total in category_totals}
        
        # Her kategorinin en çok oy alan ilk 3 adayı
        top_candidates = {}
        for category, total_votes in by_category.items():
            # Adayları standardize edilmiş isimlerle grupla
            candidates = db.session.query(
                db.func.replace(Nomination.candidate, '@@', '@').label('candidate'),
                db.func.count(Nomination.id).label('vote_count')
            ).filter(
                Nomination.category == category
            ).group_by(
                db.func.replace(Nomination.candidate, '@@', '@')
            ).order_by(
                db.func.count(Nomination.id).desc()
            ).limit(3).all()
            
            top_candidates[category] = [{
                'candidate': standardize_twitter_handle(candidate),
                'votes': count,
                'percentage': round((count / total_votes) * 100, 2),
                'rank': idx + 1
            } for idx, (candidate, count) in enumerate(candidates)]
        
        return jsonify({
            'total': total,
            'by_category': by_category,
            'top_candidates': top_candidates
        })
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")
        return jsonify({'error': str(e)}), 500

def create_backup():
    """Veritabanı yedeği oluşturur."""
    backup_dir = 'backups'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f'{backup_dir}/site_{timestamp}.db'
    
    # Veritabanı dosyasını yedekle
    shutil.copy2('instance/site.db', backup_file)
    
    # Eski yedekleri temizle (son 7 gün hariç)
    cleanup_old_backups(backup_dir)
    
    return backup_file

def cleanup_old_backups(backup_dir, days=7):
    """Belirtilen günden eski yedekleri temizler."""
    cutoff_date = datetime.now() - timedelta(days=days)
    
    for filename in os.listdir(backup_dir):
        if filename.startswith('site_') and filename.endswith('.db'):
            filepath = os.path.join(backup_dir, filename)
            file_date = datetime.fromtimestamp(os.path.getctime(filepath))
            
            if file_date < cutoff_date:
                os.remove(filepath)

@app.route('/admin/api/export/csv')
@admin_required
def export_nominations_csv():
    try:
        # Nominations verilerini al
        nominations = Nomination.query.order_by(Nomination.created_at.desc()).all()
        
        # CSV oluştur
        si = StringIO()
        cw = csv.writer(si)
        
        # Başlıkları yaz
        cw.writerow(['ID', 'Category', 'Twitter Handle', 'Candidate', 'Reason', 
                    'Twitter URL', 'Monad Address', 'Created At'])
        
        # Verileri yaz
        for nom in nominations:
            cw.writerow([
                nom.id,
                nom.category,
                nom.twitter_handle,
                nom.candidate,
                nom.reason,
                nom.twitter_url,
                nom.monad_address,
                nom.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # CSV dosyasını oluştur
        output = si.getvalue()
        si.close()
        
        # Dosya adını oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'nomination_export_{timestamp}.csv'
        
        return Response(
            output,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'text/csv',
            }
        )
    except Exception as e:
        print(f"Export error: {str(e)}")
        return jsonify({'error': 'Export failed'}), 500

# Otomatik yedekleme için scheduler
def schedule_backup():
    """Her gün gece yarısı yedek alır."""
    while True:
        now = datetime.now()
        next_run = now.replace(hour=0, minute=0, second=0) + timedelta(days=1)
        time.sleep((next_run - now).total_seconds())
        create_backup()

# Yedekleme işlemini başlat
backup_thread = threading.Thread(target=schedule_backup, daemon=True)
backup_thread.start()

# Admin paneli için yeni endpoint'ler
@app.route('/admin/api/allowed-ips', methods=['GET'])
@admin_required
def get_allowed_ips():
    try:
        allowed_ips = AllowedIP.query.all()
        return jsonify([{
            'id': ip.id,
            'ip_address': ip.ip_address,
            'description': ip.description,
            'created_at': ip.created_at.isoformat(),
            'expires_at': ip.expires_at.isoformat() if ip.expires_at else None
        } for ip in allowed_ips])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/allowed-ips', methods=['POST'])
@admin_required
def add_allowed_ip():
    try:
        data = request.json
        ip_address = data.get('ip_address')
        description = data.get('description', '')
        expires_at = None
        
        if data.get('expires_at'):
            expires_at = datetime.fromisoformat(data['expires_at'])
        
        allowed_ip = AllowedIP(
            ip_address=ip_address,
            description=description,
            expires_at=expires_at
        )
        
        db.session.add(allowed_ip)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/allowed-ips/<int:ip_id>', methods=['DELETE'])
@admin_required
def delete_allowed_ip(ip_id):
    try:
        allowed_ip = AllowedIP.query.get_or_404(ip_id)
        db.session.delete(allowed_ip)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        create_admin()
    app.run(debug=True) 