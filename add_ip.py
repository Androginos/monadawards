import os
os.environ['ADMIN_USERNAME'] = 'admin'  # Geçici olarak
os.environ['ADMIN_PASSWORD'] = 'admin'  # Geçici olarak

from app import app, db, AllowedIP
from datetime import datetime

def add_allowed_ip():
    with app.app_context():
        # Önce tüm IP'leri temizle
        AllowedIP.query.delete()
        db.session.commit()
        
        # Yeni IP'yi ekle
        ip = AllowedIP(
            ip_address='83.7.157.113',
            description='Admin IP',
            created_at=datetime.utcnow()
        )
        db.session.add(ip)
        db.session.commit()
        print("IP adresi başarıyla eklendi!")

if __name__ == '__main__':
    add_allowed_ip() 