import secrets
from EmailOtp import sendOTP 
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from google import genai
from flask import Flask, request, redirect, render_template , session, flash, jsonify
from werkzeug.security import generate_password_hash as gph, check_password_hash as cph
import pymysql
from dotenv import load_dotenv 

pymysql.install_as_MySQLdb()
load_dotenv()
app=Flask(__name__)
import os

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.secret_key = os.getenv('SECRET_KEY')
client = genai.Client(api_key=os.getenv('GENAI_API_KEY'))

app.permanent_session_lifetime = timedelta(days=7) 
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5501"}}, supports_credentials=True)
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'  
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(30), nullable=False)
    gender = db.Column(db.String(1), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    otp = db.Column(db.Integer, nullable=True, autoincrement=False)
    otpcorrect = db.Column(db.Integer, nullable=False, autoincrement=False,default=0)





@app.route('/', methods=['GET','POST'])
def home():
    return redirect('/login')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=request.json
        email=user.get('email')
        psw=user.get('password')
        user_record = User.query.filter_by(email=email).first()
        if user_record and cph(user_record.password, psw):
            session['user_id'] = user_record.id
            if user.get('remember',False):
                session.permanent = True
            return jsonify({'success': 'True',
                            'message': 'Login successful',
                                'code': 200}) , 200
        
        if not user_record:
            return jsonify({'success': 'False',
                            'message': 'User not found',
                        'code': 403}), 403
    
    return jsonify({
        "message": "Send POST request with {email, password, remember} to login"
    }), 200

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        user=request.json
        email=user.get('email')
        if User.query.filter_by(email=email).first():
            return jsonify({'success': 'False',
                            'message': 'Email already exists',
                        'code': 409}), 409
        psw=user.get('password')
        name=user.get('name')
        gender=user.get('gender')
        otp=sendOTP(email)
        print(otp)
        
        session['reg-det']={'email':email,'name':name,'gender':gender,'otp':otp,'password':psw}
    
        return jsonify({'success': 'True',
                            'message': 'otp sent to'+email,
                            
                            'code': 200}) , 200

    return jsonify({'message': 'Send POST request with {email, password, name, gender, otp} to register'}), 200
        

@app.route('/register/verify',methods=['POST','GET'])
def verify():
    if request.method == 'POST':
        otpEntered = request.json.get('otp')       
        otp = session.get('reg-det').get('otp')

        
        
        if otpEntered is not None and otp is not None and str(otpEntered).strip() == str(otp).strip():

            session['reg-otp'] = None
            userCheck=User.query.filter_by(email=session.get('reg-det').get('email')).first()
            if userCheck:
                return jsonify({'success': 'False',
                            'message': 'Email already registered',
                        'code': 409}), 409
            user_record = User(email=session.get('reg-det').get('email'),
                           name=session.get('reg-det').get('name'),
                           gender='M' if session.get('reg-det').get('gender').lower() == 'male' else 'F',
                           password=gph(session.get('reg-det').get('password')),otp=otp)
                                        
            print(user_record.otp)
            db.session.add(user_record)
            db.session.commit()
            session.pop('reg-det', None)
            return jsonify({'success': 'True',
                            'message': 'Registration successful',
                        'code': 200}) , 200
        return jsonify({'success': 'False',
                    'message': 'Invalid OTP',
                    'code': 403}), 403
    
    return jsonify({'message': 'Send POST request with otp to verify'}), 200
    

@app.route('/forgot-password/', methods=['GET', 'POST'])
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        userEmail = request.json.get('email')
        user_record = User.query.filter_by(email=userEmail).first()
        if user_record:
            otp = sendOTP(userEmail)
            session['forgot-password'] = {'email': userEmail, 'otp': otp}
            return jsonify({'success': 'True',
                            'message': 'otp sent to'+userEmail,
                        'code': 200}) , 200
        return jsonify({'success': 'False',
                            'message': 'User not found',
                        'code': 404}), 404
    
    return jsonify({'message': 'Send POST request with email to request forgot password'}), 200


@app.route('/forgot-password/verify',methods=['POST','GET'])
def verify_forgot_password():
    if request.method =='POST':
        otpEntered = request.json.get('otp')
        otp = session.get('forgot-password').get('otp')
        
        if otpEntered is not None and otp is not None and str(otpEntered).strip() == str(otp).strip():
            
            session['password-reset'] = {'allow-reset': True, 'email': session.get('forgot-password').get('email')}
            session['forgot-password'] = None
            return jsonify({'success': 'True',
                            'message': 'OTP verified successfully',
                        'code': 200}) , 200
        return jsonify({'success': 'False',
                    'message': 'Invalid OTP',
                    'code': 403}), 403

    return jsonify({'message': 'Send POST request with otp to verify'}), 200

@app.route('/forgot-password/reset',methods=['POST','GET'])
def reset_forgot_password():
    if request.method == 'POST' and session.get('password-reset').get('allow-reset') is True:
        userEmail = session.get('password-reset').get('email').strip()
        newPassword = request.json.get('password')
        user_record = User.query.filter_by(email=userEmail).first()
        if user_record:
            user_record.password = gph(newPassword)
            db.session.commit()
            session.pop('password-reset', None)
            return jsonify({'success': 'True',
                            'message': 'Password reset successful',
                        'code': 200}) , 200
        return jsonify({'success': 'False',
                            'message': 'User not found',
                        'code': 404}), 404
    
    return jsonify({'message': 'Send POST request with password to reset forgot password'}), 200



if __name__=='__main__':
    app.run(debug=True, host='0.0.0.0')
