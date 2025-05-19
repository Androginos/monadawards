import csv
from datetime import datetime
from app import app, db, Nomination

import sys
print("Python version:", sys.version)

CSV_PATH = "import_nominations.csv"

with app.app_context():
    print("Tüm eski adaylıklar siliniyor...")
    Nomination.query.delete()
    db.session.commit()
    print("Tüm eski adaylıklar silindi.")

    with open(CSV_PATH, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for i, row in enumerate(reader, 1):
            try:
                print(f"{i}. satır ekleniyor: {row}")
                nomination = Nomination(
                    category=row['Category'],
                    candidate=row['Candidate'],
                    discord_display_name=row['Voter Discord Name'],
                    discord_id=str(row['Voter Discord ID']),
                    twitter_url=row['X URL'],
                    created_at=datetime.strptime(row['Date'], "%d.%m.%Y %H:%M:%S"),
                    reason=row['Reason'],
                    monad_address=row['Monad Address'],
                    ip_address=row['IP'],
                    twitter_handle=''  # Eski alan, boş bırakıyoruz
                )
                db.session.add(nomination)
            except Exception as e:
                print(f"HATA! {i}. satırda sorun: {e}")
        db.session.commit()
    print("CSV'den tüm adaylıklar başarıyla eklendi.")