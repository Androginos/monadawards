from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from database import db, Admin, Nomination
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
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
# Default şifre: Gk123456 (ortam değişkeni tanımlı değilse kullanılır)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Gk123456')

db.init_app(app)

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
        admin_username = os.environ.get('ADMIN_USERNAME', 'AdminKutsal')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'Gk..123456')
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

@app.route('/api/nominate', methods=['POST'])
def nominate():
    try:
        data = request.json
        print("Received data:", data)
        
        # Standardize Twitter handles
        twitter_handle = standardize_twitter_handle(data.get('twitter_handle', ''))
        candidate = standardize_twitter_handle(data.get('candidate', ''))
        
        # Required fields check
        required_fields = ['category', 'twitter_url', 'monad_address']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'{field} field is required'}), 400
        
        if not twitter_handle or not candidate:
            return jsonify({'success': False, 'message': 'Twitter handle and candidate fields are required'}), 400
        
        nomination = Nomination(
            category=data['category'],
            twitter_handle=twitter_handle,
            candidate=candidate,
            reason=data.get('reason'),
            twitter_url=data['twitter_url'],
            monad_address=data['monad_address']
        )
        
        db.session.add(nomination)
        db.session.commit()
        print("Nomination successfully saved:", nomination.id)
        
        return jsonify({'success': True})
    except Exception as e:
        import traceback; traceback.print_exc()
        db.session.rollback()
        print("Error occurred:", str(e))
        return jsonify({'success': False, 'message': str(e)}), 400

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

if __name__ == '__main__':
    with app.app_context():
        create_admin()
    app.run(debug=True) 