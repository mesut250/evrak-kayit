from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import os
import pandas as pd
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import uuid
import shutil
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import text
from flask_paginate import Pagination, get_page_args

# Flask uygulamasını başlat
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')  # Kayıtlar için klasör
app.config['ARSIV_UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploadsarsiv')  # Arşiv için ayrı klasör
app.config['BACKUP_FOLDER'] = os.path.join(os.getcwd(), 'backups')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Klasörlerin varlığını kontrol et ve yoksa oluştur
for folder in [app.config['UPLOAD_FOLDER'], app.config['ARSIV_UPLOAD_FOLDER'], app.config['BACKUP_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Veritabanı ve login manager’ı başlat
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modeller
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    permissions = db.Column(db.JSON, default={"can_edit": True, "can_delete": False})
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, permission):
        return self.permissions.get(permission, False) if self.role != 'admin' else True

    def is_online(self):
        return (datetime.utcnow() - self.last_active).total_seconds() < 300

class Evrak(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kayit_no = db.Column(db.String(50), unique=True, nullable=False)
    dosya_no = db.Column(db.String(20), unique=True, nullable=False)
    gelen_ebys_no = db.Column(db.String(50))
    gelen_yer = db.Column(db.String(100))
    islem_tarihi = db.Column(db.Date)
    adi_soyadi = db.Column(db.String(100))
    tc_kimlik = db.Column(db.String(11))
    soru_numara = db.Column(db.String(50))
    ceraim_no = db.Column(db.String(50))
    ceraim_verme_tarihi = db.Column(db.Date)
    ncmec_rapor = db.Column(db.String(50))
    aciklama = db.Column(db.Text)
    dosya_durumu = db.Column(db.String(50))
    buro_sayisi = db.Column(db.Integer)
    klasor = db.Column(db.String(100))
    zimmetlenen_personel = db.Column(db.String(100))
    zimmet_tarihi = db.Column(db.Date)
    gonderilen_ebys_no = db.Column(db.String(50))
    dosya_yolu = db.Column(db.String(200))

class Arsiv(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sira_no = db.Column(db.Integer)
    gelen_ebys_no = db.Column(db.String(50))
    gelen_yer = db.Column(db.String(100))
    islem_tarihi = db.Column(db.Date)
    adi_soyadi = db.Column(db.String(100))
    tc_kimlik = db.Column(db.String(11))
    soru_numara = db.Column(db.String(50))
    ceraim_no = db.Column(db.String(50))
    ceraim_verme_tarihi = db.Column(db.Date)
    ncmec_rapor = db.Column(db.String(50))
    aciklama = db.Column(db.Text)
    dosya_durumu = db.Column(db.String(50))
    buro_sayisi = db.Column(db.Integer)
    klasor = db.Column(db.String(100))
    zimmetlenen_personel = db.Column(db.String(100))
    zimmet_tarihi = db.Column(db.Date)
    gonderilen_ebys_no = db.Column(db.String(50))
    kategori = db.Column(db.String(50), default="2025 Öncesi")

class DosyaNoCounter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.Integer, unique=True, nullable=False)
    last_number = db.Column(db.Integer, nullable=False, default=0)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)  # Log’u oluşturan kullanıcı
    action = db.Column(db.String(200), nullable=False)   # Yapılan işlem
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Yardımcı Fonksiyonlar
def run_migration():
    with app.app_context():
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        if 'dosya_no_counter' not in existing_tables:
            db.session.execute(text("""
                CREATE TABLE dosya_no_counter (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    year INTEGER NOT NULL UNIQUE,
                    last_number INTEGER NOT NULL DEFAULT 0
                )
            """))
        if 'arsiv' not in existing_tables:
            db.session.execute(text("""
                CREATE TABLE arsiv (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sira_no INTEGER,
                    gelen_ebys_no VARCHAR(50),
                    gelen_yer VARCHAR(100),
                    islem_tarihi DATE,
                    adi_soyadi VARCHAR(100),
                    tc_kimlik VARCHAR(11),
                    soru_numara VARCHAR(50),
                    ceraim_no VARCHAR(50),
                    ceraim_verme_tarihi DATE,
                    ncmec_rapor VARCHAR(50),
                    aciklama TEXT,
                    dosya_durumu VARCHAR(50),
                    buro_sayisi INTEGER,
                    klasor VARCHAR(100),
                    zimmetlenen_personel VARCHAR(100),
                    zimmet_tarihi DATE,
                    gonderilen_ebys_no VARCHAR(50),
                    kategori VARCHAR(50) DEFAULT '2025 Öncesi'
                )
            """))
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def update_last_active():
    if current_user.is_authenticated:
        current_user.last_active = datetime.utcnow()
        db.session.commit()

def log_action(action):
    if current_user.is_authenticated:
        new_log = Log(username=current_user.username, action=action)
        db.session.add(new_log)
        db.session.commit()

@app.route('/')
def index():
    return redirect(url_for('home'))       

@app.route('/home')
@login_required
def home():
    evrak_sayisi = Evrak.query.count()
    kullanici_sayisi = User.query.count()
    acik_dosya_sayisi = Evrak.query.filter_by(dosya_durumu='Açık').count()
    kapali_dosya_sayisi = Evrak.query.filter_by(dosya_durumu='Kapalı').count()
    users = User.query.all()
    return render_template('home.html', is_admin=current_user.role == 'admin', 
                         evrak_sayisi=evrak_sayisi, kullanici_sayisi=kullanici_sayisi,
                         acik_dosya_sayisi=acik_dosya_sayisi, kapali_dosya_sayisi=kapali_dosya_sayisi,
                         users=users)

@app.route('/settings')
@login_required
def settings():
    if current_user.role != 'admin':
        flash('Bu sayfaya yalnızca adminler erişebilir!', 'danger')
        return redirect(url_for('home'))
    backups = [f for f in os.listdir(app.config['BACKUP_FOLDER']) if f.endswith('.xlsx')]
    return render_template('settings.html', backups=backups)

@app.route('/backup_records', methods=['GET', 'POST'])
@login_required
def backup_records():
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('home'))
    
    try:
        if request.method == 'POST':
            records = Evrak.query.all()
            data = [{k: getattr(r, k) if getattr(r, k) is not None else '-' for k in Evrak.__table__.columns.keys()} for r in records]
            df = pd.DataFrame(data)
            backup_path = os.path.join(app.config['BACKUP_FOLDER'], f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx')
            df.to_excel(backup_path, index=False)
            log_action(f"Yedek oluşturuldu: {os.path.basename(backup_path)}")
            flash(f'Kayıt listesi başarıyla yedeklendi! Yedek dosyası: {os.path.basename(backup_path)}', 'success')
            return redirect(url_for('settings'))
        else:
            backups = [f for f in os.listdir(app.config['BACKUP_FOLDER']) if f.endswith('.xlsx')]
            return render_template('settings.html', backups=backups)
    except Exception as e:
        flash(f'Yedekleme sırasında hata oluştu: {str(e)}', 'danger')
        log_action(f"Yedekleme hatası: {str(e)}")
        return redirect(url_for('settings'))

# Güncellenmiş: Dışarıdan dosya yükleme rotası (hiçbir sütun zorunlu değil)
@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('settings'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        target_table = request.form.get('target_table', 'evrak')  # Varsayılan: Evrak (kayıtlar)

        if not file or not file.filename:
            flash('Lütfen bir dosya seçin!', 'danger')
            return redirect(url_for('settings'))
        
        try:
            # Desteklenen dosya türlerini kontrol et
            if file.filename.endswith('.xlsx'):
                df = pd.read_excel(file)
            elif file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                flash('Yalnızca .xlsx veya .csv formatında dosyalar kabul edilir!', 'danger')
                return redirect(url_for('settings'))
            
            # Tüm sütunlar opsiyonel, eksik sütunlar için varsayılan değerler atanacak
            if target_table == 'evrak':
                table_name = 'Evrak'
                model = Evrak
                all_columns = {'kayit_no', 'dosya_no', 'gelen_ebys_no', 'gelen_yer', 'islem_tarihi', 'adi_soyadi', 
                              'tc_kimlik', 'soru_numara', 'ceraim_no', 'ceraim_verme_tarihi', 'ncmec_rapor', 
                              'aciklama', 'dosya_durumu', 'buro_sayisi', 'klasor', 'zimmetlenen_personel', 
                              'zimmet_tarihi', 'gonderilen_ebys_no'}
            else:  # target_table == 'arsiv'
                table_name = 'Arşiv'
                model = Arsiv
                all_columns = {'sira_no', 'gelen_ebys_no', 'gelen_yer', 'islem_tarihi', 'adi_soyadi', 
                              'tc_kimlik', 'soru_numara', 'ceraim_no', 'ceraim_verme_tarihi', 'ncmec_rapor', 
                              'aciklama', 'dosya_durumu', 'buro_sayisi', 'klasor', 'zimmetlenen_personel', 
                              'zimmet_tarihi', 'gonderilen_ebys_no'}

            # Eksik sütunlar için varsayılan değerler ata
            for col in all_columns:
                if col not in df.columns:
                    df[col] = None

            # Verileri işleme ve ilgili tabloya ekleme
            successful_records = 0
            for index, row in df.iterrows():
                try:
                    if target_table == 'evrak':
                        islem_tarihi = pd.to_datetime(row.get('islem_tarihi', None), errors='coerce')
                        islem_tarihi = islem_tarihi.date() if pd.notna(islem_tarihi) else None

                        ceraim_verme_tarihi = pd.to_datetime(row.get('ceraim_verme_tarihi', None), errors='coerce')
                        ceraim_verme_tarihi = ceraim_verme_tarihi.date() if pd.notna(ceraim_verme_tarihi) else None

                        zimmet_tarihi = pd.to_datetime(row.get('zimmet_tarihi', None), errors='coerce')
                        zimmet_tarihi = zimmet_tarihi.date() if pd.notna(zimmet_tarihi) else None

                        try:
                            buro_sayisi = int(row.get('buro_sayisi', 0)) if pd.notna(row.get('buro_sayisi')) else None
                        except (ValueError, TypeError):
                            buro_sayisi = None

                        # kayit_no ve dosya_no opsiyonel, eğer yoksa otomatik oluştur
                        kayit_no = row.get('kayit_no')
                        if not kayit_no or pd.isna(kayit_no):
                            kayit_no = f"EVRAK-{uuid.uuid4().hex[:8]}"

                        dosya_no = row.get('dosya_no')
                        if not dosya_no or pd.isna(dosya_no):
                            year = islem_tarihi.year if islem_tarihi else datetime.now().year
                            counter = DosyaNoCounter.query.filter_by(year=year).first()
                            if not counter:
                                counter = DosyaNoCounter(year=year, last_number=0)
                                db.session.add(counter)
                            counter.last_number += 1
                            dosya_no = f"{year}/{counter.last_number}"

                        new_record = Evrak(
                            kayit_no=kayit_no,
                            dosya_no=dosya_no,
                            gelen_ebys_no=str(row.get('gelen_ebys_no', '')).strip() if pd.notna(row.get('gelen_ebys_no')) else None,
                            gelen_yer=str(row.get('gelen_yer', '')).strip() if pd.notna(row.get('gelen_yer')) else None,
                            islem_tarihi=islem_tarihi,
                            adi_soyadi=str(row.get('adi_soyadi', '')).strip() if pd.notna(row.get('adi_soyadi')) else None,
                            tc_kimlik=str(row.get('tc_kimlik', '')).strip() if pd.notna(row.get('tc_kimlik')) else None,
                            soru_numara=str(row.get('soru_numara', '')).strip() if pd.notna(row.get('soru_numara')) else None,
                            ceraim_no=str(row.get('ceraim_no', '')).strip() if pd.notna(row.get('ceraim_no')) else None,
                            ceraim_verme_tarihi=ceraim_verme_tarihi,
                            ncmec_rapor=str(row.get('ncmec_rapor', '')).strip() if pd.notna(row.get('ncmec_rapor')) else None,
                            aciklama=str(row.get('aciklama', '')).strip() if pd.notna(row.get('aciklama')) else None,
                            dosya_durumu=str(row.get('dosya_durumu', '')).strip() if pd.notna(row.get('dosya_durumu')) else None,
                            buro_sayisi=buro_sayisi,
                            klasor=str(row.get('klasor', '')).strip() if pd.notna(row.get('klasor')) else None,
                            zimmetlenen_personel=str(row.get('zimmetlenen_personel', '')).strip() if pd.notna(row.get('zimmetlenen_personel')) else None,
                            zimmet_tarihi=zimmet_tarihi,
                            gonderilen_ebys_no=str(row.get('gonderilen_ebys_no', '')).strip() if pd.notna(row.get('gonderilen_ebys_no')) else None,
                            dosya_yolu=None
                        )
                    else:  # Arsiv tablosu
                        islem_tarihi = pd.to_datetime(row.get('islem_tarihi', None), errors='coerce')
                        islem_tarihi = islem_tarihi.date() if pd.notna(islem_tarihi) else None

                        ceraim_verme_tarihi = pd.to_datetime(row.get('ceraim_verme_tarihi', None), errors='coerce')
                        ceraim_verme_tarihi = ceraim_verme_tarihi.date() if pd.notna(ceraim_verme_tarihi) else None

                        zimmet_tarihi = pd.to_datetime(row.get('zimmet_tarihi', None), errors='coerce')
                        zimmet_tarihi = zimmet_tarihi.date() if pd.notna(zimmet_tarihi) else None

                        try:
                            buro_sayisi = int(row.get('buro_sayisi', 0)) if pd.notna(row.get('buro_sayisi')) else None
                        except (ValueError, TypeError):
                            buro_sayisi = None

                        try:
                            sira_no = int(row.get('sira_no', 0)) if pd.notna(row.get('sira_no')) else None
                        except (ValueError, TypeError):
                            sira_no = None

                        new_record = Arsiv(
                            sira_no=sira_no,
                            gelen_ebys_no=str(row.get('gelen_ebys_no', '')).strip() if pd.notna(row.get('gelen_ebys_no')) else None,
                            gelen_yer=str(row.get('gelen_yer', '')).strip() if pd.notna(row.get('gelen_yer')) else None,
                            islem_tarihi=islem_tarihi,
                            adi_soyadi=str(row.get('adi_soyadi', '')).strip() if pd.notna(row.get('adi_soyadi')) else None,
                            tc_kimlik=str(row.get('tc_kimlik', '')).strip() if pd.notna(row.get('tc_kimlik')) else None,
                            soru_numara=str(row.get('soru_numara', '')).strip() if pd.notna(row.get('soru_numara')) else None,
                            ceraim_no=str(row.get('ceraim_no', '')).strip() if pd.notna(row.get('ceraim_no')) else None,
                            ceraim_verme_tarihi=ceraim_verme_tarihi,
                            ncmec_rapor=str(row.get('ncmec_rapor', '')).strip() if pd.notna(row.get('ncmec_rapor')) else None,
                            aciklama=str(row.get('aciklama', '')).strip() if pd.notna(row.get('aciklama')) else None,
                            dosya_durumu=str(row.get('dosya_durumu', '')).strip() if pd.notna(row.get('dosya_durumu')) else None,
                            buro_sayisi=buro_sayisi,
                            klasor=str(row.get('klasor', '')).strip() if pd.notna(row.get('klasor')) else None,
                            zimmetlenen_personel=str(row.get('zimmetlenen_personel', '')).strip() if pd.notna(row.get('zimmetlenen_personel')) else None,
                            zimmet_tarihi=zimmet_tarihi,
                            gonderilen_ebys_no=str(row.get('gonderilen_ebys_no', '')).strip() if pd.notna(row.get('gonderilen_ebys_no')) else None,
                            kategori="2025 Öncesi"
                        )

                    db.session.add(new_record)
                    successful_records += 1
                except Exception as e:
                    flash(f'Satır {index + 1} için hata oluştu: {str(e)}', 'warning')
                    continue
            
            db.session.commit()
            log_action(f"Dışarıdan dosya yüklendi: {file.filename} ({table_name} tablosuna)")
            flash(f'Dosya başarıyla {table_name} tablosuna yüklendi! Toplam {successful_records} kayıt eklendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Dosya yüklenirken hata oluştu: {str(e)}', 'danger')
            log_action(f"Dosya yükleme hatası: {str(e)}")
        return redirect(url_for('settings'))
    
    return redirect(url_for('settings'))  # GET isteği için settings’e yönlendir

@app.route('/download_backup/<filename>')
@login_required
def download_backup(filename):
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('home'))
    log_action(f"Yedek dosyası indirildi: {filename}")
    return send_from_directory(app.config['BACKUP_FOLDER'], filename, as_attachment=True)

@app.route('/restore_backup/<filename>', methods=['POST'])
@login_required
def restore_backup(filename):
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('settings'))
    try:
        backup_path = os.path.join(app.config['BACKUP_FOLDER'], filename)
        if not os.path.exists(backup_path):
            flash(f'Yedek dosyası bulunamadı: {filename}', 'danger')
            return redirect(url_for('settings'))

        # Mevcut veritabanını temizle
        db.session.execute(text('DELETE FROM evrak'))
        db.session.commit()

        # Excel dosyasını oku
        df = pd.read_excel(backup_path)
        if df.empty:
            flash('Yedek dosyası boş!', 'danger')
            return redirect(url_for('settings'))

        # Excel sütun isimlerini temizle, boşlukları kaldır ve küçük harfe çevir
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

        for index, row in df.iterrows():
            islem_tarihi = pd.to_datetime(row.get('islem_tarihi', None), errors='coerce')
            islem_tarihi = islem_tarihi.date() if pd.notna(islem_tarihi) else None

            ceraim_verme_tarihi = pd.to_datetime(row.get('ceraim_verme_tarihi', None), errors='coerce')
            ceraim_verme_tarihi = ceraim_verme_tarihi.date() if pd.notna(ceraim_verme_tarihi) else None

            zimmet_tarihi = pd.to_datetime(row.get('zimmet_tarihi', None), errors='coerce')
            zimmet_tarihi = zimmet_tarihi.date() if pd.notna(zimmet_tarihi) else None

            try:
                buro_sayisi = int(row.get('buro_sayisi', 0)) if pd.notna(row.get('buro_sayisi')) else None
            except (ValueError, TypeError):
                buro_sayisi = None

            year = islem_tarihi.year if islem_tarihi else datetime.now().year
            counter = DosyaNoCounter.query.filter_by(year=year).first()
            if not counter:
                counter = DosyaNoCounter(year=year, last_number=0)
                db.session.add(counter)
            counter.last_number += 1
            dosya_no = f"{year}/{counter.last_number}"

            new_record = Evrak(
                kayit_no=row.get('kayit_no', f"EVRAK-{uuid.uuid4().hex[:8]}"),
                dosya_no=dosya_no,
                gelen_ebys_no=str(row.get('gelen_ebys_no', '')).strip() if pd.notna(row.get('gelen_ebys_no')) else None,
                gelen_yer=str(row.get('gelen_yer', '')).strip() if pd.notna(row.get('gelen_yer')) else None,
                islem_tarihi=islem_tarihi,
                adi_soyadi=str(row.get('adi_soyadi', '')).strip() if pd.notna(row.get('adi_soyadi')) else None,
                tc_kimlik=str(row.get('tc_kimlik', '')).strip() if pd.notna(row.get('tc_kimlik')) else None,
                soru_numara=str(row.get('soru_numara', '')).strip() if pd.notna(row.get('soru_numara')) else None,
                ceraim_no=str(row.get('ceraim_no', '')).strip() if pd.notna(row.get('ceraim_no')) else None,
                ceraim_verme_tarihi=ceraim_verme_tarihi,
                ncmec_rapor=str(row.get('ncmec_rapor', '')).strip() if pd.notna(row.get('ncmec_rapor')) else None,
                aciklama=str(row.get('aciklama', '')).strip() if pd.notna(row.get('aciklama')) else None,
                dosya_durumu=str(row.get('dosya_durumu', '')).strip() if pd.notna(row.get('dosya_durumu')) else None,
                buro_sayisi=buro_sayisi,
                klasor=str(row.get('klasor', '')).strip() if pd.notna(row.get('klasor')) else None,
                zimmetlenen_personel=str(row.get('zimmetlenen_personel', '')).strip() if pd.notna(row.get('zimmetlenen_personel')) else None,
                zimmet_tarihi=zimmet_tarihi,
                gonderilen_ebys_no=str(row.get('gonderilen_ebys_no', '')).strip() if pd.notna(row.get('gonderilen_ebys_no')) else None,
                dosya_yolu=None
            )
            db.session.add(new_record)

        db.session.commit()
        log_action(f"Yedek geri yüklendi: {filename}")
        flash(f'Yedek başarıyla geri yüklendi: {filename}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Yedek geri yüklenirken hata oluştu: {str(e)}', 'danger')
        log_action(f"Yedek geri yükleme hatası: {str(e)}")
    return redirect(url_for('settings'))

@app.route('/archive_backup/<filename>', methods=['POST'])
@login_required
def archive_backup(filename):
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('settings'))
    try:
        backup_path = os.path.join(app.config['BACKUP_FOLDER'], filename)
        if not os.path.exists(backup_path):
            flash(f'Yedek dosyası bulunamadı: {filename}', 'danger')
            return redirect(url_for('settings'))

        # Excel dosyasını oku
        df = pd.read_excel(backup_path)
        if df.empty:
            flash('Yedek dosyası boş!', 'danger')
            return redirect(url_for('settings'))

        # Excel sütun isimlerini temizle, boşlukları kaldır ve küçük harfe çevir
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

        for index, row in df.iterrows():
            islem_tarihi = pd.to_datetime(row.get('islem_tarihi', None), errors='coerce')
            islem_tarihi = islem_tarihi.date() if pd.notna(islem_tarihi) else None

            ceraim_verme_tarihi = pd.to_datetime(row.get('ceraim_verme_tarihi', None), errors='coerce')
            ceraim_verme_tarihi = ceraim_verme_tarihi.date() if pd.notna(ceraim_verme_tarihi) else None

            zimmet_tarihi = pd.to_datetime(row.get('zimmet_tarihi', None), errors='coerce')
            zimmet_tarihi = zimmet_tarihi.date() if pd.notna(zimmet_tarihi) else None

            try:
                buro_sayisi = int(row.get('buro_sayisi', 0)) if pd.notna(row.get('buro_sayisi')) else None
            except (ValueError, TypeError):
                buro_sayisi = None

            try:
                sira_no = int(row.get('sira_no', 0)) if pd.notna(row.get('sira_no')) else None
            except (ValueError, TypeError):
                sira_no = None

            new_record = Arsiv(
                sira_no=sira_no,
                gelen_ebys_no=str(row.get('gelen_ebys_no', '')).strip() if pd.notna(row.get('gelen_ebys_no')) else None,
                gelen_yer=str(row.get('gelen_yer', '')).strip() if pd.notna(row.get('gelen_yer')) else None,
                islem_tarihi=islem_tarihi,
                adi_soyadi=str(row.get('adi_soyadi', '')).strip() if pd.notna(row.get('adi_soyadi')) else None,
                tc_kimlik=str(row.get('tc_kimlik', '')).strip() if pd.notna(row.get('tc_kimlik')) else None,
                soru_numara=str(row.get('soru_numara', '')).strip() if pd.notna(row.get('soru_numara')) else None,
                ceraim_no=str(row.get('ceraim_no', '')).strip() if pd.notna(row.get('ceraim_no')) else None,
                ceraim_verme_tarihi=ceraim_verme_tarihi,
                ncmec_rapor=str(row.get('ncmec_rapor', '')).strip() if pd.notna(row.get('ncmec_rapor')) else None,
                aciklama=str(row.get('aciklama', '')).strip() if pd.notna(row.get('aciklama')) else None,
                dosya_durumu=str(row.get('dosya_durumu', '')).strip() if pd.notna(row.get('dosya_durumu')) else None,
                buro_sayisi=buro_sayisi,
                klasor=str(row.get('klasor', '')).strip() if pd.notna(row.get('klasor')) else None,
                zimmetlenen_personel=str(row.get('zimmetlenen_personel', '')).strip() if pd.notna(row.get('zimmetlenen_personel')) else None,
                zimmet_tarihi=zimmet_tarihi,
                gonderilen_ebys_no=str(row.get('gonderilen_ebys_no', '')).strip() if pd.notna(row.get('gonderilen_ebys_no')) else None,
                kategori="2025 Öncesi"
            )
            db.session.add(new_record)

        db.session.commit()
        log_action(f"Yedek arşive yüklendi: {filename}")
        flash(f'Yedek başarıyla arşive yüklendi: {filename}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Yedek arşive yüklenirken hata oluştu: {str(e)}', 'danger')
        log_action(f"Yedek arşive yükleme hatası: {str(e)}")
    return redirect(url_for('settings'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Kullanıcı adı ve şifre gerekli!', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_action(f"Kullanıcı giriş yaptı: {username}")
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    log_action(f"Kullanıcı çıkış yaptı: {username}")
    flash('Başarıyla çıkış yaptınız!', 'info')
    return redirect(url_for('login'))

@app.route('/kayit_form', methods=['GET', 'POST'])
@login_required
def kayit_form():
    if not current_user.can('can_edit') and current_user.role != 'admin':
        flash('Bu işlemi yapma yetkiniz yok!', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        try:
            gelen_ebys_no = request.form.get('gelenEbysNo')
            gelen_yer = request.form.get('gelenYer')
            islem_tarihi_str = request.form.get('islemTarihi')
            adi_soyadi = request.form.get('adiSoyadi')
            tc_kimlik = request.form.get('tcKimlik')
            soru_numara = request.form.get('soruNumara')
            ceraim_no = request.form.get('ceraimNo')
            ceraim_verme_tarihi_str = request.form.get('ceraimVermeTarihi')
            ncmec_rapor = request.form.get('ncmecRapor')
            aciklama = request.form.get('aciklama')
            dosya_durumu = request.form.get('dosyaDurumu')
            buro_sayisi = int(request.form.get('buroSayisi', 0)) if request.form.get('buroSayisi') else None
            klasor = request.form.get('klasor')
            zimmetlenen_personel = request.form.get('zimmetlenenPersonel')
            zimmet_tarihi_str = request.form.get('zimmetTarihi')
            gonderilen_ebys_no = request.form.get('gonderilenEbysNo')
            dosya = request.files.get('dosya')

            islem_tarihi = datetime.strptime(islem_tarihi_str, '%Y-%m-%d').date() if islem_tarihi_str else None
            ceraim_verme_tarihi = datetime.strptime(ceraim_verme_tarihi_str, '%Y-%m-%d').date() if ceraim_verme_tarihi_str else None
            zimmet_tarihi = datetime.strptime(zimmet_tarihi_str, '%Y-%m-%d').date() if zimmet_tarihi_str else None

            kayit_no = f"EVRAK-{uuid.uuid4().hex[:8]}"
            year = islem_tarihi.year if islem_tarihi else datetime.now().year
            counter = DosyaNoCounter.query.filter_by(year=year).first()
            if not counter:
                counter = DosyaNoCounter(year=year, last_number=0)
                db.session.add(counter)
            counter.last_number += 1
            dosya_no = f"{year}/{counter.last_number}"

            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], dosya_no.replace('/', '_'))
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

            dosya_yolu = None
            if dosya and dosya.filename:
                dosya_adi = f"{dosya_no.replace('/', '_')}_{dosya.filename}"
                dosya_yolu = os.path.join(folder_path, dosya_adi)
                dosya.save(dosya_yolu)
                relative_dosya_yolu = os.path.relpath(dosya_yolu, app.config['UPLOAD_FOLDER']).replace('\\', '/')
                dosya_yolu = f"uploads/{relative_dosya_yolu}"

            new_record = Evrak(
                kayit_no=kayit_no,
                dosya_no=dosya_no,
                gelen_ebys_no=gelen_ebys_no,
                gelen_yer=gelen_yer,
                islem_tarihi=islem_tarihi,
                adi_soyadi=adi_soyadi,
                tc_kimlik=tc_kimlik,
                soru_numara=soru_numara,
                ceraim_no=ceraim_no,
                ceraim_verme_tarihi=ceraim_verme_tarihi,
                ncmec_rapor=ncmec_rapor,
                aciklama=aciklama,
                dosya_durumu=dosya_durumu,
                buro_sayisi=buro_sayisi,
                klasor=klasor,
                zimmetlenen_personel=zimmetlenen_personel,
                zimmet_tarihi=zimmet_tarihi,
                gonderilen_ebys_no=gonderilen_ebys_no,
                dosya_yolu=dosya_yolu
            )
            db.session.add(new_record)
            db.session.commit()
            log_action(f"Yeni evrak kaydedildi: {kayit_no}")
            flash(f'EVRAKINIZ KAYDEDİLDİ. EVRAK NO: {kayit_no}', 'success')
            return render_template('kayit_form.html', show_success=True, kayit_no=kayit_no)
        except Exception as e:
            db.session.rollback()
            flash(f"Kayıt eklenirken hata oluştu: {str(e)}", 'danger')
            log_action(f"Kayıt ekleme hatası: {str(e)}")
            return redirect(url_for('kayit_form'))
    return render_template('kayit_form.html')

@app.route('/list_records', methods=['GET'])
@login_required
def list_records():
    search_query = request.args.get('search', '').strip()
    filters = {
        'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
        'dosya_durumu': request.args.get('dosya_durumu', '')
    }

    query = Evrak.query
    for key, value in filters.items():
        if value:
            query = query.filter(getattr(Evrak, key) == value)
    if search_query:
        query = query.filter(
            db.or_(
                Evrak.kayit_no.ilike(f'%{search_query}%'),
                Evrak.dosya_no.ilike(f'%{search_query}%'),
                Evrak.gelen_ebys_no.ilike(f'%{search_query}%'),
                Evrak.gelen_yer.ilike(f'%{search_query}%'),
                Evrak.adi_soyadi.ilike(f'%{search_query}%'),
                Evrak.tc_kimlik.ilike(f'%{search_query}%'),
                Evrak.soru_numara.ilike(f'%{search_query}%'),
                Evrak.ceraim_no.ilike(f'%{search_query}%'),
                Evrak.ncmec_rapor.ilike(f'%{search_query}%'),
                Evrak.aciklama.ilike(f'%{search_query}%'),
                Evrak.buro_sayisi.ilike(f'%{search_query}%'),
                Evrak.klasor.ilike(f'%{search_query}%'),
                Evrak.zimmetlenen_personel.ilike(f'%{search_query}%'),
                Evrak.gonderilen_ebys_no.ilike(f'%{search_query}%')
            )
        )

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 20
    total = query.count()
    records = query.order_by(Evrak.id.desc()).offset(offset).limit(per_page).all()
    
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    filter_options = {
        'zimmetlenen_personel': sorted(set([r.zimmetlenen_personel for r in Evrak.query.all() if r.zimmetlenen_personel])),
        'dosya_durumu': sorted(set([r.dosya_durumu for r in Evrak.query.all() if r.dosya_durumu]))
    }
    return render_template('list.html', records=records, upload_folder=app.config['UPLOAD_FOLDER'],
                          filter_options=filter_options, selected_filters=filters, search_query=search_query,
                          page=page, per_page=per_page, pagination=pagination)

@app.route('/search_records', methods=['GET'])
@login_required
def search_records():
    search_query = request.args.get('q', '').strip().lower()  # Arama sorgusunu küçük harfe çevir
    filters = {
        'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
        'dosya_durumu': request.args.get('dosya_durumu', '')
    }

    query = Evrak.query
    for key, value in filters.items():
        if value:
            query = query.filter(getattr(Evrak, key) == value)
    if search_query:
        query = query.filter(
            db.or_(
                Evrak.kayit_no.ilike(f'%{search_query}%'),
                Evrak.dosya_no.ilike(f'%{search_query}%'),
                Evrak.gelen_ebys_no.ilike(f'%{search_query}%'),
                Evrak.gelen_yer.ilike(f'%{search_query}%'),
                Evrak.adi_soyadi.ilike(f'%{search_query}%'),
                Evrak.tc_kimlik.ilike(f'%{search_query}%'),
                Evrak.soru_numara.ilike(f'%{search_query}%'),
                Evrak.ceraim_no.ilike(f'%{search_query}%'),
                Evrak.ncmec_rapor.ilike(f'%{search_query}%'),
                Evrak.aciklama.ilike(f'%{search_query}%'),
                Evrak.buro_sayisi.ilike(f'%{search_query}%'),
                Evrak.klasor.ilike(f'%{search_query}%'),
                Evrak.zimmetlenen_personel.ilike(f'%{search_query}%'),
                Evrak.gonderilen_ebys_no.ilike(f'%{search_query}%')
            )
        )

    records = query.order_by(Evrak.id.desc()).limit(20).all()
    records_data = [{
        'id': record.id,
        'kayit_no': record.kayit_no,
        'dosya_no': record.dosya_no,
        'gelen_ebys_no': record.gelen_ebys_no or '-',
        'gelen_yer': record.gelen_yer or '-',
        'islem_tarihi': record.islem_tarihi.strftime('%d.%m.%Y') if record.islem_tarihi else '-',
        'adi_soyadi': record.adi_soyadi or '-',
        'tc_kimlik': record.tc_kimlik or '-',
        'soru_numara': record.soru_numara or '-',
        'ceraim_no': record.ceraim_no or '-',
        'ceraim_verme_tarihi': record.ceraim_verme_tarihi.strftime('%d.%m.%Y') if record.ceraim_verme_tarihi else '-',
        'ncmec_rapor': record.ncmec_rapor or '-',
        'aciklama': record.aciklama or '-',
        'dosya_durumu': record.dosya_durumu or '-',
        'buro_sayisi': record.buro_sayisi if record.buro_sayisi is not None else '-',
        'klasor': record.klasor or '-',
        'zimmetlenen_personel': record.zimmetlenen_personel or '-',
        'zimmet_tarihi': record.zimmet_tarihi.strftime('%d.%m.%Y') if record.zimmet_tarihi else '-',
        'gonderilen_ebys_no': record.gonderilen_ebys_no or '-',
        'dosya_yolu': record.dosya_yolu or None
    } for record in records]

    return jsonify(records_data)

@app.route('/arsiv', methods=['GET'])
@login_required
def arsiv():
    search_query = request.args.get('search', '').strip()
    filters = {
        'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
        'dosya_durumu': request.args.get('dosya_durumu', '')
    }

    query = Arsiv.query.filter_by(kategori="2025 Öncesi")
    for key, value in filters.items():
        if value:
            query = query.filter(getattr(Arsiv, key) == value)
    if search_query:
        query = query.filter(
            db.or_(
                Arsiv.gelen_ebys_no.ilike(f'%{search_query}%'),
                Arsiv.gelen_yer.ilike(f'%{search_query}%'),
                Arsiv.adi_soyadi.ilike(f'%{search_query}%'),
                Arsiv.tc_kimlik.ilike(f'%{search_query}%'),
                Arsiv.soru_numara.ilike(f'%{search_query}%'),
                Arsiv.ceraim_no.ilike(f'%{search_query}%'),
                Arsiv.ncmec_rapor.ilike(f'%{search_query}%'),
                Arsiv.aciklama.ilike(f'%{search_query}%'),
                Arsiv.buro_sayisi.ilike(f'%{search_query}%'),
                Arsiv.klasor.ilike(f'%{search_query}%'),
                Arsiv.zimmetlenen_personel.ilike(f'%{search_query}%'),
                Arsiv.gonderilen_ebys_no.ilike(f'%{search_query}%')
            )
        )

    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 20
    total = query.count()
    records = query.order_by(Arsiv.id.desc()).offset(offset).limit(per_page).all()
    
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    filter_options = {
        'zimmetlenen_personel': sorted(set([r.zimmetlenen_personel for r in Arsiv.query.all() if r.zimmetlenen_personel])),
        'dosya_durumu': sorted(set([r.dosya_durumu for r in Arsiv.query.all() if r.dosya_durumu]))
    }
    
    return render_template('arsiv.html', records=records, filter_options=filter_options, 
                          selected_filters=filters, search_query=search_query,
                          page=page, per_page=per_page, pagination=pagination)

@app.route('/search_arsiv', methods=['GET'])
@login_required
def search_arsiv():
    search_query = request.args.get('q', '').strip().lower()  # Arama sorgusunu küçük harfe çevir
    filters = {
        'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
        'dosya_durumu': request.args.get('dosya_durumu', '')
    }

    query = Arsiv.query.filter_by(kategori="2025 Öncesi")
    for key, value in filters.items():
        if value:
            query = query.filter(getattr(Arsiv, key) == value)
    if search_query:
        query = query.filter(
            db.or_(
                Arsiv.gelen_ebys_no.ilike(f'%{search_query}%'),
                Arsiv.gelen_yer.ilike(f'%{search_query}%'),
                Arsiv.adi_soyadi.ilike(f'%{search_query}%'),
                Arsiv.tc_kimlik.ilike(f'%{search_query}%'),
                Arsiv.soru_numara.ilike(f'%{search_query}%'),
                Arsiv.ceraim_no.ilike(f'%{search_query}%'),
                Arsiv.ncmec_rapor.ilike(f'%{search_query}%'),
                Arsiv.aciklama.ilike(f'%{search_query}%'),
                Arsiv.buro_sayisi.ilike(f'%{search_query}%'),
                Arsiv.klasor.ilike(f'%{search_query}%'),
                Arsiv.zimmetlenen_personel.ilike(f'%{search_query}%'),
                Arsiv.gonderilen_ebys_no.ilike(f'%{search_query}%')
            )
        )

    records = query.order_by(Arsiv.id.desc()).limit(20).all()
    records_data = [{
        'sira_no': record.sira_no if record.sira_no is not None else '-',
        'gelen_ebys_no': record.gelen_ebys_no or '-',
        'gelen_yer': record.gelen_yer or '-',
        'islem_tarihi': record.islem_tarihi.strftime('%d.%m.%Y') if record.islem_tarihi else '-',
        'adi_soyadi': record.adi_soyadi or '-',
        'tc_kimlik': record.tc_kimlik or '-',
        'soru_numara': record.soru_numara or '-',
        'ceraim_no': record.ceraim_no or '-',
        'ceraim_verme_tarihi': record.ceraim_verme_tarihi.strftime('%d.%m.%Y') if record.ceraim_verme_tarihi else '-',
        'ncmec_rapor': record.ncmec_rapor or '-',
        'aciklama': record.aciklama or '-',
        'dosya_durumu': record.dosya_durumu or '-',
        'buro_sayisi': record.buro_sayisi if record.buro_sayisi is not None else '-',
        'klasor': record.klasor or '-',
        'zimmetlenen_personel': record.zimmetlenen_personel or '-',
        'zimmet_tarihi': record.zimmet_tarihi.strftime('%d.%m.%Y') if record.zimmet_tarihi else '-',
        'gonderilen_ebys_no': record.gonderilen_ebys_no or '-'
    } for record in records]

    return jsonify(records_data)

@app.route('/delete_record/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    if not current_user.can('can_delete') and current_user.role != 'admin':
        flash('Bu işlemi yapma yetkiniz yok!', 'danger')
        return redirect(url_for('list_records'))
    try:
        record = Evrak.query.get_or_404(record_id)
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], record.dosya_no.replace('/', '_'))
        kayit_no = record.kayit_no
        
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
        
        db.session.delete(record)
        db.session.commit()
        log_action(f"Evrak silindi: {kayit_no}")
        flash(f'KAYIT SİLİNDİ. EVRAK NO: {kayit_no}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Kayıt silinirken hata oluştu: {str(e)}', 'danger')
        log_action(f"Evrak silme hatası: {str(e)}")
    return redirect(url_for('list_records'))

@app.route('/edit_record/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    if not current_user.can('can_edit') and current_user.role != 'admin':
        flash('Bu işlemi yapma yetkiniz yok!', 'danger')
        return redirect(url_for('list_records'))
    record = Evrak.query.get_or_404(record_id)
    if request.method == 'POST':
        try:
            record.gelen_ebys_no = request.form.get('gelenEbysNo')
            record.gelen_yer = request.form.get('gelenYer')
            islem_tarihi_str = request.form.get('islemTarihi')
            record.adi_soyadi = request.form.get('adiSoyadi')
            record.tc_kimlik = request.form.get('tcKimlik')
            record.soru_numara = request.form.get('soruNumara')
            record.ceraim_no = request.form.get('ceraimNo')
            ceraim_verme_tarihi_str = request.form.get('ceraimVermeTarihi')
            record.ncmec_rapor = request.form.get('ncmecRapor')
            record.aciklama = request.form.get('aciklama')
            record.dosya_durumu = request.form.get('dosyaDurumu')
            record.buro_sayisi = int(request.form.get('buroSayisi', 0)) if request.form.get('buroSayisi') else None
            record.klasor = request.form.get('klasor')
            record.zimmetlenen_personel = request.form.get('zimmetlenenPersonel')
            zimmet_tarihi_str = request.form.get('zimmetTarihi')
            record.gonderilen_ebys_no = request.form.get('gonderilenEbysNo')
            dosya = request.files.get('dosya')

            record.islem_tarihi = datetime.strptime(islem_tarihi_str, '%Y-%m-%d').date() if islem_tarihi_str else None
            record.ceraim_verme_tarihi = datetime.strptime(ceraim_verme_tarihi_str, '%Y-%m-%d').date() if ceraim_verme_tarihi_str else None
            record.zimmet_tarihi = datetime.strptime(zimmet_tarihi_str, '%Y-%m-%d').date() if zimmet_tarihi_str else None

            if dosya and dosya.filename:
                folder_path = os.path.join(app.config['UPLOAD_FOLDER'], record.dosya_no.replace('/', '_'))
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                dosya_adi = f"{record.dosya_no.replace('/', '_')}_{dosya.filename}"
                dosya_yolu = os.path.join(folder_path, dosya_adi)
                dosya.save(dosya_yolu)
                relative_dosya_yolu = os.path.relpath(dosya_yolu, app.config['UPLOAD_FOLDER']).replace('\\', '/')
                record.dosya_yolu = f"uploads/{relative_dosya_yolu}"

            db.session.commit()
            log_action(f"Evrak güncellendi: {record.kayit_no}")
            flash(f'KAYIT GÜNCELLENDİ. EVRAK NO: {record.kayit_no}', 'success')
            return render_template('edit_record.html', record=record, show_update_success=True, kayit_no=record.kayit_no)
        except Exception as e:
            db.session.rollback()
            flash(f"Kayıt güncellenirken hata oluştu: {str(e)}", 'danger')
            log_action(f"Evrak güncelleme hatası: {str(e)}")
            return redirect(url_for('edit_record', record_id=record_id))
    return render_template('edit_record.html', record=record)

@app.route('/edit_arsiv_record/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_arsiv_record(record_id):
    if not current_user.can('can_edit') and current_user.role != 'admin':
        flash('Bu işlemi yapma yetkiniz yok!', 'danger')
        return redirect(url_for('arsiv'))
    record = Arsiv.query.get_or_404(record_id)
    if request.method == 'POST':
        try:
            record.gelen_ebys_no = request.form.get('gelenEbysNo')
            record.gelen_yer = request.form.get('gelenYer')
            islem_tarihi_str = request.form.get('islemTarihi')
            record.adi_soyadi = request.form.get('adiSoyadi')
            record.tc_kimlik = request.form.get('tcKimlik')
            record.soru_numara = request.form.get('soruNumara')
            record.ceraim_no = request.form.get('ceraimNo')
            ceraim_verme_tarihi_str = request.form.get('ceraimVermeTarihi')
            record.ncmec_rapor = request.form.get('ncmecRapor')
            record.aciklama = request.form.get('aciklama')
            record.dosya_durumu = request.form.get('dosyaDurumu')
            record.buro_sayisi = int(request.form.get('buroSayisi', 0)) if request.form.get('buroSayisi') else None
            record.klasor = request.form.get('klasor')
            record.zimmetlenen_personel = request.form.get('zimmetlenenPersonel')
            zimmet_tarihi_str = request.form.get('zimmetTarihi')
            record.gonderilen_ebys_no = request.form.get('gonderilenEbysNo')
            dosya = request.files.get('dosya')

            record.islem_tarihi = datetime.strptime(islem_tarihi_str, '%Y-%m-%d').date() if islem_tarihi_str else None
            record.ceraim_verme_tarihi = datetime.strptime(ceraim_verme_tarihi_str, '%Y-%m-%d').date() if ceraim_verme_tarihi_str else None
            record.zimmet_tarihi = datetime.strptime(zimmet_tarihi_str, '%Y-%m-%d').date() if zimmet_tarihi_str else None

            if dosya and dosya.filename:
                folder_path = os.path.join(app.config['ARSIV_UPLOAD_FOLDER'], f"arsiv_{record.id}")
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                dosya_adi = f"arsiv_{record.id}_{dosya.filename}"
                dosya_yolu = os.path.join(folder_path, dosya_adi)
                dosya.save(dosya_yolu)
                relative_dosya_yolu = os.path.relpath(dosya_yolu, app.config['ARSIV_UPLOAD_FOLDER']).replace('\\', '/')
                record.dosya_yolu = f"uploadsarsiv/{relative_dosya_yolu}"

            db.session.commit()
            log_action(f"Arşiv kaydı güncellendi: Sira No {record.sira_no}")
            flash(f'KAYIT GÜNCELLENDİ. SIRA NO: {record.sira_no}', 'success')
            return redirect(url_for('arsiv'))
        except Exception as e:
            db.session.rollback()
            flash(f"Kayıt güncellenirken hata oluştu: {str(e)}", 'danger')
            log_action(f"Arşiv kaydı güncelleme hatası: {str(e)}")
            return redirect(url_for('edit_arsiv_record', record_id=record_id))
    
    # filter_options ekleniyor
    filter_options = {
        'zimmetlenen_personel': sorted(set([r.zimmetlenen_personel for r in Arsiv.query.all() if r.zimmetlenen_personel])),
        'dosya_durumu': sorted(set([r.dosya_durumu for r in Arsiv.query.all() if r.dosya_durumu]))
    }
    
    return render_template('edit_arsiv_record.html', record=record, filter_options=filter_options)

@app.route('/delete_arsiv_record/<int:record_id>', methods=['POST'])
@login_required
def delete_arsiv_record(record_id):
    if not current_user.can('can_delete') and current_user.role != 'admin':
        flash('Bu işlemi yapma yetkiniz yok!', 'danger')
        return redirect(url_for('arsiv'))
    try:
        record = Arsiv.query.get_or_404(record_id)
        folder_path = os.path.join(app.config['ARSIV_UPLOAD_FOLDER'], f"arsiv_{record.id}")
        sira_no = record.sira_no or '-'
        
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
        
        db.session.delete(record)
        db.session.commit()
        log_action(f"Arşiv kaydı silindi: Sira No {sira_no}")
        flash(f'KAYIT SİLİNDİ. SIRA NO: {sira_no}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Kayıt silinirken hata oluştu: {str(e)}', 'danger')
        log_action(f"Arşiv kaydı silme hatası: {str(e)}")
    return redirect(url_for('arsiv'))

@app.route('/export_excel', methods=['GET', 'POST'])
@login_required
def export_excel():
    if request.method == 'POST':
        selected_columns = request.form.getlist('columns')
        if not selected_columns:
            flash('Lütfen en az bir sütun seçin!', 'warning')
            return redirect(url_for('list_records'))
        
        search_query = request.args.get('search', '').strip()
        filters = {
            'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
            'dosya_durumu': request.args.get('dosya_durumu', '')
        }

        query = Evrak.query
        for key, value in filters.items():
            if value:
                query = query.filter(getattr(Evrak, key) == value)
        if search_query:
            query = query.filter(
                db.or_(
                    Evrak.kayit_no.ilike(f'%{search_query}%'),
                    Evrak.dosya_no.ilike(f'%{search_query}%'),
                    Evrak.gelen_ebys_no.ilike(f'%{search_query}%'),
                    Evrak.gelen_yer.ilike(f'%{search_query}%'),
                    Evrak.adi_soyadi.ilike(f'%{search_query}%'),
                    Evrak.tc_kimlik.ilike(f'%{search_query}%'),
                    Evrak.soru_numara.ilike(f'%{search_query}%'),
                    Evrak.ceraim_no.ilike(f'%{search_query}%'),
                    Evrak.ncmec_rapor.ilike(f'%{search_query}%'),
                    Evrak.aciklama.ilike(f'%{search_query}%'),
                    Evrak.buro_sayisi.ilike(f'%{search_query}%'),
                    Evrak.klasor.ilike(f'%{search_query}%'),
                    Evrak.zimmetlenen_personel.ilike(f'%{search_query}%'),
                    Evrak.gonderilen_ebys_no.ilike(f'%{search_query}%')
                )
            )

        records = query.all()
        if not records:
            flash('Seçilen filtrelerle kayıt bulunamadı!', 'warning')
            return redirect(url_for('list_records'))

        data = []
        for record in records:
            row = {}
            for col in selected_columns:
                value = getattr(record, col, None)
                if value is None:
                    row[col] = '-'
                elif isinstance(value, date):
                    row[col] = value.strftime('%d.%m.%Y')
                else:
                    row[col] = str(value)
            data.append(row)

        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Kayitlar')
        output.seek(0)
        log_action("Evrak listesi Excel olarak dışa aktarıldı")
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                         as_attachment=True, download_name='kayitlar.xlsx')
    return render_template('export_columns.html', columns=Evrak.__table__.columns.keys(), export_type='excel')

@app.route('/export_pdf', methods=['GET', 'POST'])
@login_required
def export_pdf():
    if request.method == 'POST':
        selected_columns = request.form.getlist('columns')
        if not selected_columns:
            flash('Lütfen en az bir sütun seçin!', 'warning')
            return redirect(url_for('list_records'))
        
        search_query = request.args.get('search', '').strip()
        filters = {
            'zimmetlenen_personel': request.args.get('zimmetlenen_personel', ''),
            'dosya_durumu': request.args.get('dosya_durumu', '')
        }

        query = Evrak.query
        for key, value in filters.items():
            if value:
                query = query.filter(getattr(Evrak, key) == value)
        if search_query:
            query = query.filter(
                db.or_(
                    Evrak.kayit_no.ilike(f'%{search_query}%'),
                    Evrak.dosya_no.ilike(f'%{search_query}%'),
                    Evrak.gelen_ebys_no.ilike(f'%{search_query}%'),
                    Evrak.gelen_yer.ilike(f'%{search_query}%'),
                    Evrak.adi_soyadi.ilike(f'%{search_query}%'),
                    Evrak.tc_kimlik.ilike(f'%{search_query}%'),
                    Evrak.soru_numara.ilike(f'%{search_query}%'),
                    Evrak.ceraim_no.ilike(f'%{search_query}%'),
                    Evrak.ncmec_rapor.ilike(f'%{search_query}%'),
                    Evrak.aciklama.ilike(f'%{search_query}%'),
                    Evrak.buro_sayisi.ilike(f'%{search_query}%'),
                    Evrak.klasor.ilike(f'%{search_query}%'),
                    Evrak.zimmetlenen_personel.ilike(f'%{search_query}%'),
                    Evrak.gonderilen_ebys_no.ilike(f'%{search_query}%')
                )
            )

        records = query.all()
        if not records:
            flash('Seçilen filtrelerle kayıt bulunamadı!', 'warning')
            return redirect(url_for('list_records'))

        output = BytesIO()
        c = canvas.Canvas(output, pagesize=letter)
        width, height = letter
        y = height - 50
        c.drawString(50, y, f"Evrak Kayıtları - {datetime.now().strftime('%Y-%m-%d')}")
        y -= 30

        for record in records:
            for col in selected_columns:
                value = getattr(record, col, None)
                if value is None:
                    display_value = '-'
                elif isinstance(value, date):
                    display_value = value.strftime('%d.%m.%Y')
                else:
                    display_value = str(value)
                c.drawString(50, y, f"{col}: {display_value}")
                y -= 20
            y -= 20
            if y < 50:
                c.showPage()
                y = height - 50
        c.save()
        output.seek(0)
        log_action("Evrak listesi PDF olarak dışa aktarıldı")
        return send_file(output, mimetype='application/pdf', as_attachment=True, download_name='kayitlar.pdf')
    return render_template('export_columns.html', columns=Evrak.__table__.columns.keys(), export_type='pdf')

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Bu sayfaya yalnızca adminler erişebilir!', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Bu sayfaya yalnızca adminler erişebilir!', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        can_edit = 'can_edit' in request.form
        can_delete = 'can_delete' in request.form
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten alınmış!', 'danger')
            return redirect(url_for('add_user'))
        new_user = User(username=username, role=role, permissions={"can_edit": can_edit, "can_delete": can_delete})
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        log_action(f"Yeni kullanıcı eklendi: {username}")
        flash(f'{username} adlı kullanıcı başarıyla eklendi!', 'success')
        return redirect(url_for('admin_users'))
    return render_template('add_user.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Bu sayfaya yalnızca adminler erişebilir!', 'danger')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.role = request.form.get('role')
        user.permissions = {"can_edit": 'can_edit' in request.form, "can_delete": 'can_delete' in request.form}
        db.session.commit()
        log_action(f"Kullanıcı güncellendi: {user.username}")
        flash(f'{user.username} adlı kullanıcının bilgileri güncellendi!', 'success')
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Admin kullanıcısını silemezsiniz!', 'warning')
        return redirect(url_for('admin_users'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action(f"Kullanıcı silindi: {username}")
    flash(f'{username} adlı kullanıcı silindi!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/reset_database', methods=['POST'])
@login_required
def reset_database():
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('settings'))
    try:
        db.drop_all()
        db.create_all()
        
        # Kayıtlar ve arşiv için tüm klasörleri sil
        uploads_folder = app.config['UPLOAD_FOLDER']
        arsiv_uploads_folder = app.config['ARSIV_UPLOAD_FOLDER']
        if os.path.exists(uploads_folder):
            shutil.rmtree(uploads_folder, ignore_errors=True)
        if os.path.exists(arsiv_uploads_folder):
            shutil.rmtree(arsiv_uploads_folder, ignore_errors=True)
        os.makedirs(uploads_folder)
        os.makedirs(arsiv_uploads_folder)
        
        log_action("Veritabanı sıfırlandı")
        flash('Veritabanı sıfırlandı ve uploads/uploadsarsiv klasörleri temizlendi!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Veritabanı sıfırlanırken hata oluştu: {str(e)}', 'danger')
        log_action(f"Veritabanı sıfırlama hatası: {str(e)}")
    return redirect(url_for('settings'))

@app.route('/change_admin_password', methods=['POST'])
@login_required
def change_admin_password():
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('settings'))
    new_password = request.form.get('new_password')
    if new_password:
        current_user.set_password(new_password)
        db.session.commit()
        log_action("Admin şifresi değiştirildi")
        flash('Şifre başarıyla değiştirildi!', 'success')
    else:
        flash('Yeni şifre giriniz!', 'danger')
    return redirect(url_for('settings'))

@app.route('/change_user_password/<int:user_id>', methods=['POST'])
@login_required
def change_user_password(user_id):
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        log_action(f"Kullanıcı şifresi değiştirildi: {user.username}")
        flash(f'{user.username} kullanıcısının şifresi değiştirildi!', 'success')
    else:
        flash('Yeni şifre giriniz!', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/logs')
@login_required
def logs():
    if current_user.role != 'admin':
        flash('Bu sayfaya yalnızca adminler erişebilir!', 'danger')
        return redirect(url_for('home'))
    logs = Log.query.order_by(Log.timestamp.desc()).all()  # Tarihe göre azalan sıralama
    return render_template('logs.html', logs=logs)

@app.route('/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    if current_user.role != 'admin':
        flash('Bu işlemi yalnızca adminler yapabilir!', 'danger')
        return redirect(url_for('home'))
    try:
        Log.query.delete()
        db.session.commit()
        log_action("Tüm loglar silindi")
        flash('Tüm log kayıtları başarıyla silindi!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Logları silerken hata oluştu: {str(e)}', 'danger')
        log_action(f"Log silme hatası: {str(e)}")
    return redirect(url_for('logs'))

def scheduled_backup():
    with app.app_context():
        backup_records()

scheduler = BackgroundScheduler()
scheduler.add_job(func=scheduled_backup, trigger="interval", hours=24)
scheduler.start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        run_migration()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)