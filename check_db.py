from app import app, db, Nomination, Admin
from datetime import datetime

def check_database():
    with app.app_context():
        # Tabloları oluştur
        db.create_all()
        
        # Nominations tablosunu kontrol et
        nominations = Nomination.query.all()
        print("\n=== Nominations Tablosu ===")
        print(f"Toplam kayıt sayısı: {len(nominations)}")
        if nominations:
            print("\nSon 5 kayıt:")
            for nom in nominations[-5:]:
                print(f"ID: {nom.id}")
                print(f"Kategori: {nom.category}")
                print(f"Aday: {nom.candidate}")
                print(f"Twitter: {nom.twitter_handle}")
                print(f"Oluşturulma: {nom.created_at}")
                print("-" * 30)
        
        # Admin tablosunu kontrol et
        admins = Admin.query.all()
        print("\n=== Admin Tablosu ===")
        print(f"Toplam admin sayısı: {len(admins)}")
        if admins:
            print("\nAdmin kullanıcıları:")
            for admin in admins:
                print(f"ID: {admin.id}")
                print(f"Kullanıcı adı: {admin.username}")
                print("-" * 30)

if __name__ == "__main__":
    check_database() 