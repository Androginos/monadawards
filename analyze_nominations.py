from app import app, db
from database import Nomination
from sqlalchemy import func
from collections import Counter

def analyze_nominations():
    with app.app_context():
        # 1. Kategori bazında oy sayıları
        print("\n1. Kategori Bazında Oy Sayıları:")
        print("-" * 50)
        category_votes = db.session.query(
            Nomination.category,
            func.count(Nomination.id).label('vote_count')
        ).group_by(Nomination.category).all()
        
        for category, count in category_votes:
            print(f"{category}: {count} oy")

        # 2. Her kategoride en çok aday gösterilen ilk 3 isim
        print("\n2. Kategori Bazında En Çok Aday Gösterilen İlk 3 İsim:")
        print("-" * 50)
        
        categories = db.session.query(Nomination.category).distinct().all()
        for category in categories:
            category = category[0]
            print(f"\n{category}:")
            
            # Bu kategorideki adayları say
            candidates = db.session.query(
                Nomination.candidate,
                func.count(Nomination.id).label('nomination_count')
            ).filter(
                Nomination.category == category
            ).group_by(
                Nomination.candidate
            ).order_by(
                func.count(Nomination.id).desc()
            ).limit(3).all()
            
            for candidate, count in candidates:
                print(f"  - {candidate}: {count} adaylık")

        # 3. En aktif aday gösteren Twitter hesapları (İlk 5)
        print("\n3. En Aktif Aday Gösteren Twitter Hesapları (İlk 5):")
        print("-" * 50)
        active_nominators = db.session.query(
            Nomination.twitter_handle,
            func.count(Nomination.id).label('nomination_count')
        ).group_by(
            Nomination.twitter_handle
        ).order_by(
            func.count(Nomination.id).desc()
        ).limit(5).all()
        
        for handle, count in active_nominators:
            print(f"{handle}: {count} adaylık")

        # 4. Son 24 saatteki adaylıklar
        print("\n4. Son 24 Saatteki Adaylıklar:")
        print("-" * 50)
        from datetime import datetime, timedelta
        recent_nominations = Nomination.query.filter(
            Nomination.created_at >= datetime.utcnow() - timedelta(days=1)
        ).all()
        
        if recent_nominations:
            for nom in recent_nominations:
                print(f"\nKategori: {nom.category}")
                print(f"Aday: {nom.candidate}")
                print(f"Aday Gösteren: {nom.twitter_handle}")
                print(f"Tarih: {nom.created_at}")
                print("-" * 30)
        else:
            print("Son 24 saatte adaylık bulunmuyor.")

if __name__ == "__main__":
    analyze_nominations() 