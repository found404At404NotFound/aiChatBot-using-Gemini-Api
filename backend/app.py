import secrets
import os
from EmailOtp import sendOTP 
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime
from google import genai
from flask import Flask, request, redirect, render_template, session, flash, jsonify
from werkzeug.security import generate_password_hash as gph, check_password_hash as cph
import pymysql
from dotenv import load_dotenv 
from datetime import timedelta, datetime

pymysql.install_as_MySQLdb()
load_dotenv()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.secret_key = os.getenv('SECRET_KEY')
client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

app.permanent_session_lifetime = timedelta(days=8) 
origin = ['http://127.0.0.1:5501','https://progress-schools-mediterranean-heart.trycloudflare.com']
CORS(app, resources={r"/*": {"origins": origin}}, supports_credentials=True)
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'  
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(30), nullable=False)
    gender = db.Column(db.String(1), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'gender': self.gender
        }

class PendingUser(db.Model):
    __tablename__ = 'pending_user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(30), nullable=False)
    gender = db.Column(db.String(1), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    otp = db.Column(db.Integer, nullable=True)
    otpcorrect = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now())

class Otp(db.Model):
    __tablename__ = 'otp'
    email = db.Column(db.String(50), primary_key=True)
    otp = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())

"""===================================================================="""

@app.route('/',methods=['GET', 'POST'])
def root():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])

def register():
    if request.method == 'POST':
        email = request.json.get('email')
        name = request.json.get('name')
        gender ='M' if str(request.json.get('gender')).lower() == 'male' else 'F'
        password = request.json.get('password')

        user_record= User.query.filter_by(email=email).first()
        if user_record:
            return jsonify({'error': 'Email already exists'}), 400
        else:
            otp= sendOTP(email)
            
            puser=PendingUser.query.filter_by(email=email).first()
            if puser:
                db.session.delete(puser)
                db.session.commit()
            puser = PendingUser(email=email, name=name, gender=gender, password=gph(password), otp=otp)
            db.session.add(puser)
            print(f'OTP sent to {email}')
            print('pending user added to database :', puser)
            db.session.commit()


            return jsonify({'message': 'User given perms to verify successfully'}), 200
    return jsonify({'message': 'Send POST request with email, name, gender and password to register'}), 200    
    

@app.route('/register/verify', methods=['POST','GET'])
def verify():
    if request.method == 'POST':
        otpEntered = request.json.get('otp')
        email = request.json.get('email')

        puser = PendingUser.query.filter_by(email=email).first()
        if not puser:
            return jsonify({'error': 'User not found'}), 404
        
        if int(otpEntered) == int(puser.otp):
            puser.otpcorrect = 1
            db.session.commit()
            user = User(email=puser.email, name=puser.name, gender=puser.gender, password=puser.password)
            db.session.add(user)
            db.session.delete(puser)
            db.session.commit()

            return jsonify({'message': 'User verified successfully'}), 200
            
        return jsonify({'error': 'Invalid OTP'}), 400
    return jsonify({'message': 'Send POST request with otp and email to verify'}), 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        if session.get('user_id'):
            return redirect('/home')
        user = User.query.filter_by(email=email).first()
        if user and cph(user.password, password):
            session['user_id'] = user.id
            session['name'] = user.name
            if request.json.get('remember'):
                session.permanent = True
            return jsonify({'message': 'Logged in successfully'}), 200
        return jsonify({'error': 'Invalid email or password'}), 401
    return jsonify({'message': 'Send POST request with email and password to login'}), 200

@app.route('/forgot-password/', methods=['GET', 'POST'])

@app.route('/forgot-password', methods=['GET', 'POST'])
def forget_password():
    if request.method =='POST':
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        if user is not None:
            otp = sendOTP(email)
            if Otp.query.filter_by(email=email).first() is not None:
                db.session.delete(Otp.query.filter_by(email=email).first())
                db.session.commit()
            otp_record = Otp(email=email, otp=otp)
            print(f'OTP sent to {email}:',otp)
            print('OTP record added to database :', otp_record.otp)
            db.session.add(otp_record)
            db.session.commit()
            return jsonify({'message': 'OTP sent to your email'}), 200
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': 'Send POST request with email to request forgot password'}), 200

@app.route('/forgot-password/verify', methods=['POST','GET'])
def forgot_password_verify():
    if request.method == 'POST':
        try:
            
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
           
            data = request.get_json()
            if data is None:
                return jsonify({'error': 'Invalid JSON data'}), 400

            
            otpEntered = data.get('otp')
            email = data.get('email')
            new_password = data.get('newPassword')

            
            if otpEntered is None or email is None or new_password is None:
                return jsonify({'error': 'otp, email, and new_password are required'}), 400

            
            otpEntered = str(otpEntered)
            email = str(email)
            new_password = str(new_password)

            
            otpDB = Otp.query.filter_by(email=email).first()
            if otpDB is not None:
                otp = str(otpDB.otp)
                
                
                if otpEntered.strip() == otp.strip():
                    user = User.query.filter_by(email=email).first()
                    if user is None:
                        return jsonify({'error': 'User not found'}), 404
                    
                    print('old pass for user:', user.password)
                    user.password = gph(new_password)
                    print('new pass for user:', user.password)
                    db.session.commit()
                    
                    return jsonify({'message': 'Password changed successfully'}), 200
                return jsonify({'error': 'Invalid OTP'}), 400
            return jsonify({'error': 'No OTP found for this email'}), 404
            
        except ValueError as e:
            return jsonify({'error': 'Invalid data format'}), 400
        except Exception as e:
            db.session.rollback()
            print(f"Error in forgot password verify: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
            
    return jsonify({'message': 'Send POST request with otp, email and new password to verify'}), 200








app.run(debug=True,host='0.0.0.0',port=8888)
