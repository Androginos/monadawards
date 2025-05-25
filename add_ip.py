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
        
        # Mevcut IP'yi ekle
        ip = AllowedIP(
            ip_address='83.7.138.122',
            description='Admin IP',
            created_at=datetime.utcnow()
        )
        db.session.add(ip)
        
        # IP range ekle (83.7.138.*)
        ip_range = AllowedIP(
            ip_address='83.7.138.*',
            description='Admin IP Range',
            created_at=datetime.utcnow()
        )
        db.session.add(ip_range)
        
        db.session.commit()
        print("IP ve IP range başarıyla eklendi!")

def add_current_ip():
    try:
        # Yeni IP'yi ekle
        new_ip = AllowedIP(ip_address='83.7.138.122')
        db.session.add(new_ip)
        db.session.commit()
        print("IP başarıyla eklendi!")
    except Exception as e:
        print(f"Hata oluştu: {e}")
        db.session.rollback()

if __name__ == '__main__':
    add_allowed_ip()
    add_current_ip() 