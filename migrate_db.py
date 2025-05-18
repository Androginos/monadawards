from app import app, db, create_tables
from database import Nomination, AllowedIP
import sqlite3
import os
import time
import shutil

def migrate_database():
    with app.app_context():
        # Eski veritabanı yedeği al
        if os.path.exists('site.db'):
            backup_path = f'site.db.backup.{int(time.time())}'
            shutil.copy2('site.db', backup_path)
            print(f"Veritabanı yedeği oluşturuldu: {backup_path}")

        # Önce yeni tabloları oluştur
        print("Yeni tablolar oluşturuluyor...")
        create_tables()

        # Eski verileri yeni yapıya taşı
        try:
            # Eski veritabanına bağlan
            old_conn = sqlite3.connect('site.db')
            old_cursor = old_conn.cursor()

            # Eski tabloları kontrol et
            old_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nomination'")
            if not old_cursor.fetchone():
                print("Eski nomination tablosu bulunamadı. Yeni bir veritabanı oluşturuluyor...")
                return True

            # Eski nomination verilerini al
            old_cursor.execute('SELECT * FROM nomination')
            old_nominations = old_cursor.fetchall()

            if not old_nominations:
                print("Eski veritabanında kayıt bulunamadı.")
                return True

            print(f"{len(old_nominations)} adet kayıt taşınıyor...")

            # Yeni yapıya taşı
            for nom in old_nominations:
                new_nomination = Nomination(
                    id=nom[0],
                    category=nom[1],
                    twitter_handle=nom[2],
                    candidate=nom[3],
                    reason=nom[4],
                    twitter_url=nom[5],
                    monad_address=nom[6],
                    ip_address='0.0.0.0',  # Varsayılan IP
                    created_at=nom[7]
                )
                db.session.add(new_nomination)

            db.session.commit()
            print("Veriler başarıyla taşındı.")

        except Exception as e:
            print(f"Hata oluştu: {str(e)}")
            db.session.rollback()
            print("Veritabanı yedeğinden geri yükleme yapılabilir.")
            return False

        finally:
            old_conn.close()

        return True

if __name__ == '__main__':
    if migrate_database():
        print("Migration başarıyla tamamlandı.")
    else:
        print("Migration sırasında hata oluştu.")

with app.app_context():
    try:
        db.engine.execute('ALTER TABLE nomination ADD COLUMN discord_id VARCHAR(50)')
    except Exception as e:
        print('discord_id zaten var:', e)
    try:
        db.engine.execute('ALTER TABLE nomination ADD COLUMN discord_display_name VARCHAR(100)')
    except Exception as e:
        print('discord_display_name zaten var:', e)
    print('Migration tamamlandı.') 