from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response, abort, send_from_directory, flash
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
import requests
from collections import defaultdict, Counter
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))  # Güvenli ve gizli anahtar
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = True  # Sadece HTTPS üzerinden
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript erişimini engelle
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF koruması

# CSRF koruması
csrf = CSRFProtect(app)

# CSRF token'ı template'lere ekle
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:; connect-src 'self' https:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Rate Limiter tanımlanıyor
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Admin kullanıcı adı ve şifre ortam değişkenlerinden alınıyor
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')  # Varsayılan değer
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin')  # Varsayılan değer

# Discord OAuth bilgileri
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '1373612267869835275')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '63U1ks7tkW7fq9QNTXiAIMM8SA2JqcX5')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', 'https://www.monadawards.xyz/discord/callback')

GUILD_ID = '1036357772826120242'
FULL_ACCESS_ROLE_ID = '1072682201658970112'

db.init_app(app)

def create_tables():
    with app.app_context():
        try:
            print("Veritabanı tabloları oluşturuluyor...")  # Debug log
            db.create_all()
            print("Veritabanı tabloları oluşturuldu.")  # Debug log
            
            # Localhost IP'sini ekle
            local_ip = AllowedIP.query.filter_by(ip_address='127.0.0.1').first()
            if not local_ip:
                local_ip = AllowedIP(
                    ip_address='127.0.0.1',
                    description='Local Development IP'
                )
                db.session.add(local_ip)
                db.session.commit()
                print("Localhost IP'si eklendi.")
            
            # İzin verilen IP'leri kontrol et
            allowed_ips = AllowedIP.query.all()
            print(f"Mevcut izin verilen IP'ler: {[ip.ip_address for ip in allowed_ips]}")  # Debug log
            
            # Test verisi ekle
            test_nomination = Nomination(
                category='Test Kategori',
                candidate='Test Aday',
                reason='Test Sebep',
                ip_address='127.0.0.1',
                twitter_handle='@test',
                twitter_url='https://twitter.com/test',
                monad_address='0x123...',
                discord_display_name='Test User'
            )
            db.session.add(test_nomination)
            db.session.commit()
            print("Test verisi eklendi.")
        except Exception as e:
            print(f"Veritabanı işlemlerinde hata: {str(e)}")
            db.session.rollback()

def create_admin():
    admin = Admin.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        new_admin = Admin(username=ADMIN_USERNAME)
        new_admin.set_password(ADMIN_PASSWORD)
        db.session.add(new_admin)
        db.session.commit()
    else:
        # Şifreyi environment'tan gelenle güncelle
        admin.set_password(ADMIN_PASSWORD)
        db.session.commit()

# HTTPS zorunluluğu
@app.before_request
def force_https():
    # Sadece production ortamında HTTPS zorunluluğu
    if os.environ.get('FLASK_ENV') == 'production':
        if not request.is_secure and not request.headers.get('X-Forwarded-Proto', 'http') == 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

# Admin route'larını gizle
ADMIN_ROUTE_PREFIX = 'superpanel-m0nad-2025'

# Admin girişi gerekli decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def is_ip_allowed(ip):
    """IP adresinin izin verilen listede olup olmadığını kontrol eder"""
    try:
        # IP adresini temizle
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        
        # X-Forwarded-For header'ını kontrol et
        forwarded_ip = request.headers.get('X-Forwarded-For')
        if forwarded_ip:
            forwarded_ip = forwarded_ip.split(',')[0].strip()
            print(f"X-Forwarded-For IP: {forwarded_ip}")  # Debug log
        
        print(f"Gelen IP adresi: {ip}")  # Debug log
        
        # Tüm izin verilen IP'leri al
        allowed_ips = [ip.ip_address for ip in AllowedIP.query.all()]
        print(f"İzin verilen IP'ler: {allowed_ips}")  # Debug log
        
        # Direkt IP kontrolü
        if ip in allowed_ips or (forwarded_ip and forwarded_ip in allowed_ips):
            print("IP direkt eşleşme bulundu")  # Debug log
            return True
            
        # IP range kontrolü
        for allowed_ip in allowed_ips:
            if '*' in allowed_ip:
                # IP range formatı: 83.7.138.*
                base_ip = allowed_ip.rsplit('.', 1)[0]  # 83.7.138
                if ip.startswith(base_ip + '.') or (forwarded_ip and forwarded_ip.startswith(base_ip + '.')):
                    print(f"IP range eşleşmesi bulundu: {allowed_ip}")  # Debug log
                    return True
        
        print("IP eşleşmesi bulunamadı")  # Debug log
        return False
    except Exception as e:
        print(f"IP kontrolünde hata: {str(e)}")  # Hata logu
        return False

# Admin IP kontrolü
def check_admin_ip():
    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip_address and ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        print(f"Gelen IP adresi: {ip_address}")  # Debug log
        
        allowed_ip = AllowedIP.query.filter(
            AllowedIP.ip_address == ip_address,
            (AllowedIP.expires_at.is_(None) | (AllowedIP.expires_at > datetime.utcnow()))
        ).first()
        
        print(f"İzin verilen IP'ler: {[ip.ip_address for ip in AllowedIP.query.all()]}")  # Debug log
        print(f"IP kontrolü sonucu: {allowed_ip is not None}")  # Debug log
        
        return allowed_ip is not None
    except Exception as e:
        print(f"IP kontrolünde hata: {str(e)}")  # Hata logu
        return False

@app.before_request
def limit_admin_access():
    if request.path.startswith(f"/{ADMIN_ROUTE_PREFIX}"):
        try:
            if not is_ip_allowed(request.remote_addr):
                print(f"Erişim reddedildi - IP: {request.remote_addr}")  # Debug log
                abort(403, description="Bu IP adresinden erişim izniniz yok.")
        except Exception as e:
            print(f"Admin erişim kontrolünde hata: {str(e)}")  # Hata logu
            abort(500, description="Sunucu hatası oluştu.")

def update_allowed_ip(ip_address):
    """Giriş yapan kullanıcının IP'sini otomatik olarak günceller"""
    try:
        # IP zaten var mı kontrol et
        existing_ip = AllowedIP.query.filter_by(ip_address=ip_address).first()
        if not existing_ip:
            # Yeni IP'yi ekle
            new_ip = AllowedIP(ip_address=ip_address)
            db.session.add(new_ip)
            db.session.commit()
            print(f"Yeni IP eklendi: {ip_address}")
    except Exception as e:
        print(f"IP güncelleme hatası: {e}")
        db.session.rollback()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Giriş başarılı, IP'yi güncelle
            client_ip = request.remote_addr
            update_allowed_ip(client_ip)
            
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre!', 'error')
    
    return render_template('admin_login.html')

@app.route(f'/{ADMIN_ROUTE_PREFIX}/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))

@app.route(f'/{ADMIN_ROUTE_PREFIX}')
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/nominations')
@admin_required
def admin_nominations():
    try:
        nominations = Nomination.query.order_by(Nomination.created_at.desc()).all()
        return jsonify([
            {
                'category': nom.category,
                'candidate': nom.candidate,
                'discord_display_name': nom.discord_display_name,
                'discord_id': nom.discord_id,
                'twitter_url': nom.twitter_url,
                'created_at': nom.created_at.isoformat() if nom.created_at else None,
                'reason': nom.reason,
                'monad_address': nom.monad_address,
                'ip_address': nom.ip_address
            }
            for nom in nominations
        ])
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")  # Hata loglaması
        return jsonify({'error': str(e)}), 500

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/statistics')
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
        
        by_category = {cat: count for cat, count in category_totals}
        
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
                'candidate': candidate,
                'votes': count,
                'percentage': round((count / total_votes) * 100, 2) if total_votes else 0,
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

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/export/csv')
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

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/allowed-ips', methods=['GET'])
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

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/allowed-ips', methods=['POST'])
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

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/allowed-ips/<int:ip_id>', methods=['DELETE'])
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

@app.route('/discord/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        return "No code provided", 400
    # Discord'dan access token al
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'scope': 'identify guilds guilds.members.read'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
    if not token_response.ok:
        return 'Token could not be obtained', 400
    tokens = token_response.json()
    access_token = tokens['access_token']
    # Kullanıcı bilgisi çek
    user_response = requests.get(
        'https://discord.com/api/users/@me',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    if not user_response.ok:
        return 'User info could not be obtained', 400
    user_info = user_response.json()
    # Sunucu üyeliği kontrolü kaldırıldı
    # Session'a kaydet
    session['discord_user'] = {
        'id': user_info['id'],
        'avatar': user_info.get('avatar', None),
        'display_name': user_info.get('global_name', None)
    }
    session['discord_access_token'] = access_token
    return redirect(url_for('home'))

@app.route('/discord/disconnect')
def discord_disconnect():
    session.pop('discord_user', None)
    session.pop('discord_access_token', None)
    return redirect(url_for('home'))

@app.route('/api/discord-user')
def api_discord_user():
    user = session.get('discord_user')
    if not user:
        return '', 404
    return jsonify({
        'id': user['id'],
        'avatar': user['avatar'],
        'display_name': user['display_name']
    })

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/top-voters')
@admin_required
def admin_top_voters():
    # Her kategori için ilk 3 adayı bul
    top_candidates = {}
    category_votes = defaultdict(list)
    all_nominations = Nomination.query.all()
    for nom in all_nominations:
        category_votes[nom.category].append(nom.candidate)
    for category, votes in category_votes.items():
        counter = Counter(votes)
        top3 = [c for c, _ in counter.most_common(3)]
        top_candidates[category] = top3
    # Her kullanıcının oylarını ve puanlarını hesapla (display name bazlı)
    user_scores = {}
    for nom in all_nominations:
        user_name = nom.discord_display_name
        if not user_name:
            continue
        if user_name not in user_scores:
            user_scores[user_name] = {
                'discord_display_name': user_name,
                'total_score': 0,
                'num_first': 0,
                'num_second': 0,
                'num_third': 0
            }
        # Bu kullanıcının bu kategorideki adayının sırası nedir?
        top3 = top_candidates.get(nom.category, [])
        try:
            rank = top3.index(nom.candidate)
        except ValueError:
            rank = -1
        if rank == 0:
            user_scores[user_name]['total_score'] += 3
            user_scores[user_name]['num_first'] += 1
        elif rank == 1:
            user_scores[user_name]['total_score'] += 2
            user_scores[user_name]['num_second'] += 1
        elif rank == 2:
            user_scores[user_name]['total_score'] += 1
            user_scores[user_name]['num_third'] += 1
    # En çok puan alan ilk 3 kullanıcıyı sırala
    top_voters = sorted(user_scores.values(), key=lambda x: (-x['total_score'], -x['num_first'], -x['num_second'], -x['num_third']))[:3]
    return jsonify(top_voters)

@app.route(f'/{ADMIN_ROUTE_PREFIX}/api/clear-database', methods=['POST'])
@csrf.exempt
@admin_required
def clear_database():
    # Ekstra IP kontrolü
    if not is_ip_allowed(request.remote_addr):
        return jsonify({'success': False, 'message': 'Bu IP adresinden silme yetkiniz yok!'}), 403
    try:
        db.session.query(Nomination).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': 'All nominations have been deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# FAQ route
@app.route('/faq')
def faq():
    return send_from_directory('static', 'faq.html')

# Ana route
@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

@app.route('/api/nominate', methods=['POST'])
@csrf.exempt
def api_nominate():
    data = request.get_json()
    category = data.get('category')
    candidate = data.get('candidate')
    reason = data.get('reason')
    twitter_url = data.get('twitter_url')
    monad_address = data.get('monad_address')
    discord_display_name = data.get('discord_username')
    discord_id = data.get('discord_id')  # Discord ID'yi al
    twitter_handle = data.get('twitter_handle', '')  # Twitter handle'ı al
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Aynı IP ve kategori için daha önce oy verilmiş mi kontrol et
    existing = Nomination.query.filter_by(ip_address=ip_address, category=category).first()
    if existing:
        return jsonify({'message': 'You have already voted in this category!'}), 400

    nomination = Nomination(
        category=category,
        candidate=candidate,
        reason=reason,
        twitter_url=twitter_url,
        monad_address=monad_address,
        discord_display_name=discord_display_name,
        discord_id=discord_id,  # Discord ID'yi kaydet
        twitter_handle=twitter_handle,  # Twitter handle'ı kaydet
        ip_address=ip_address
    )
    db.session.add(nomination)
    db.session.commit()
    return jsonify({'message': 'Your nomination has been submitted successfully!'}), 200

if __name__ == '__main__':
    with app.app_context():
        create_tables()  # Önce tabloları oluştur
        create_admin()   # Sonra admin kullanıcısını oluştur
    app.run(debug=True, use_reloader=True, host='127.0.0.1', port=5000) 