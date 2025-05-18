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
import requests
from collections import defaultdict, Counter

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

GUILD_ID = '1036357772826120242'
FULL_ACCESS_ROLE_ID = '1072682201658970112'

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
    # Discord bağlantı kontrolü
    discord_user = session.get('discord_user')
    if not discord_user:
        return jsonify({'success': False, 'message': 'You must connect your Discord account to vote.'}), 403
    access_token = session.get('discord_access_token')
    if not access_token:
        return jsonify({'success': False, 'message': 'You must connect your Discord account to vote.'}), 403
    # Kullanıcı Monad sunucusunda mı kontrol et
    guilds_response = requests.get(
        'https://discord.com/api/users/@me/guilds',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    if guilds_response.status_code != 200:
        return jsonify({'success': False, 'message': 'Could not verify your Discord server membership.'}), 403
    guilds = guilds_response.json()
    in_monad = any(g['id'] == GUILD_ID for g in guilds)
    if not in_monad:
        return jsonify({'success': False, 'message': 'You must be a member of the Monad Discord server to vote.'}), 403
    try:
        data = request.json
        print("Received data:", data)
        
        # IP adresini al
        ip_address = request.remote_addr
        print(f"Request from IP: {ip_address}")
        
        # Discord ile kategori bazlı oy kontrolü
        existing_discord_nom = Nomination.query.filter_by(
            category=data['category'],
            discord_id=discord_user['id']
        ).first()
        if existing_discord_nom:
            return jsonify({'success': False, 'message': 'You have already voted in this category with your Discord account.'}), 403
        
        # Kategori limiti kontrolü
        if not check_category_limit(ip_address, data['category']):
            category_messages = {
                'SELFIE SORCERERS': '🚀 Looks like you\'ve already nominated your favorite selfie sorcerer!',
                'HYPE HITCHHIKERS': '👥 One hype hitchhiker nomination per person - that\'s the spirit!',
                'AISHWASHERS': '💡 Your AI washer nomination is already in the stars!',
                'MEME MINERS': '😂 Your meme miner vote is already spreading joy!',
                'BAIT LORDS': '🎣 Your bait lord nomination is already in the trap!',
                'DM DIPLOMATS': '🤫 Your DM diplomat vote is already in the shadows!',
                'GYMONAD BULLIES': '💪 Your GYMONAD bully nomination is already flexing!',
                'VIRTUE VAMPIRES': '🧛 Your virtue vampire vote is already sucking engagement!'
            }
            default_message = 'Whoa there! 🐎 You\'ve already cast your vote in this category. One vote per category keeps the awards fair!'
            
            return jsonify({
                'success': False, 
                'message': category_messages.get(data['category'], default_message)
            }), 403
        
        # Required fields check
        required_fields = ['category', 'monad_address']
        missing_fields = []
        for field in required_fields:
            if field not in data or not data[field]:
                missing_fields.append(field)
        if missing_fields:
            field_messages = {
                'category': 'Which category are you voting for? 🎯',
                'monad_address': 'We need your Monad address to verify your vote! 🔐'
            }
            messages = [field_messages.get(field, field) for field in missing_fields]
            return jsonify({
                'success': False, 
                'message': f'Almost there! Just fill in these missing details: {", ".join(messages)} 📝'
            }), 400
        # Monad adresi formatı kontrolü
        monad_address = data['monad_address'].strip()
        if not monad_address.startswith('0x') or len(monad_address) != 42:
            if not monad_address.startswith('0x'):
                return jsonify({
                    'success': False,
                    'message': 'Your Monad address should start with 0x! 🔍'
                }), 400
            elif len(monad_address) != 42:
                return jsonify({
                    'success': False,
                    'message': 'Your Monad address should be 42 characters long! 🔍'
                }), 400
        nomination = Nomination(
            category=data['category'],
            twitter_handle='',  # Artık kullanılmıyor
            candidate=data.get('candidate', ''),
            reason=data.get('reason'),
            twitter_url=data.get('twitter_url', ''),
            monad_address=monad_address,
            ip_address=ip_address,
            discord_id=discord_user['id'],
            discord_display_name=discord_user.get('display_name', '')
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
            'GYMONAD BULLIES': '🎉 Your GYMONAD bully nomination is in! Flexing hard! 💪',
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
        return jsonify([
            {
                'category': nom.category,
                'candidate': nom.candidate,
                'discord_display_name': nom.discord_display_name,
                'discord_id': nom.discord_id,
                'twitter_url': nom.twitter_url,
                'created_at': nom.created_at.isoformat() if nom.created_at else None,
                'reason': nom.reason,
                'ip_address': nom.ip_address
            }
            for nom in nominations
        ])
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

@app.route('/discord/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        return "No code provided", 400
    # Discord'dan access token al
    data = {
        'client_id': '1373612267869835275',
        'client_secret': '63U1ks7tkW7fq9QNTXiAIMM8SA2JqcX5',
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': 'https://monadawards.onrender.com/discord/callback',
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

@app.route('/admin/api/top-voters')
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
    # Her kullanıcının oylarını ve puanlarını hesapla
    user_scores = {}
    for nom in all_nominations:
        user_id = nom.discord_id
        user_name = nom.discord_display_name
        if not user_id:
            continue
        if user_id not in user_scores:
            user_scores[user_id] = {
                'discord_display_name': user_name,
                'discord_id': user_id,
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
            user_scores[user_id]['total_score'] += 3
            user_scores[user_id]['num_first'] += 1
        elif rank == 1:
            user_scores[user_id]['total_score'] += 2
            user_scores[user_id]['num_second'] += 1
        elif rank == 2:
            user_scores[user_id]['total_score'] += 1
            user_scores[user_id]['num_third'] += 1
    # En çok puan alan ilk 3 kullanıcıyı sırala
    top_voters = sorted(user_scores.values(), key=lambda x: (-x['total_score'], -x['num_first'], -x['num_second'], -x['num_third']))[:3]
    return jsonify(top_voters)

@app.route('/admin/api/clear-database', methods=['POST'])
@admin_required
def clear_database():
    try:
        db.session.query(Nomination).delete()
        db.session.commit()
        return jsonify({'success': True, 'message': 'All nominations have been deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    with app.app_context():
        create_admin()
    app.run(debug=True) 