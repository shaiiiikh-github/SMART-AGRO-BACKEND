from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson import ObjectId
import requests
import bcrypt
import secrets
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)
CORS(app, supports_credentials=True)
load_dotenv()

# Configuration
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session expires after 7 days

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client["smart_agro"]
users_collection = db["users"]
messages_collection = db["messages"]

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Authentication routes
@app.route("/api/auth/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['fullName', 'username', 'phone', 'email', 'password', 'state', 'district', 'village']
        if not all(field in data for field in required_fields):
            return jsonify({"message": "Missing required fields"}), 400

        # Check if user already exists
        if users_collection.find_one({"email": data["email"]}):
            return jsonify({"message": "Email already exists"}), 409

        if users_collection.find_one({"username": data["username"]}):
            return jsonify({"message": "Username already taken"}), 409

        # Hash password before storing
        hashed_password = hash_password(data["password"])

        user = {
            "fullName": data["fullName"],
            "username": data["username"],
            "phone": data["phone"],
            "email": data["email"],
            "password": hashed_password,
            "state": data["state"],
            "district": data["district"],
            "village": data["village"],
            "createdAt": datetime.utcnow()
        }

        # Insert new user
        result = users_collection.insert_one(user)
        user_id = str(result.inserted_id)

        # Create session
        session['user_id'] = user_id
        session.permanent = True

        # Return user data (without password)
        user.pop('password', None)
        return jsonify({
            "message": "Signup successful",
            "user": user
        }), 201

    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({"message": "Server error during signup"}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"message": "Username and password required"}), 400

        # Find user by username or email
        user = users_collection.find_one({
            "$or": [
                {"username": username},
                {"email": username}
            ]
        })

        if not user:
            return jsonify({"message": "Invalid credentials"}), 401

        # Verify password
        if not check_password(password, user['password']):
            return jsonify({"message": "Invalid credentials"}), 401

        # Create session
        session['user_id'] = str(user['_id'])
        session.permanent = True

        # Return user data (without password)
        user_data = {
            "id": str(user['_id']),
            "username": user['username'],
            "email": user['email'],
            "fullName": user['fullName'],
            "state": user.get('state'),
            "district": user.get('district'),
            "village": user.get('village')
        }

        return jsonify({
            "message": "Login successful",
            "user": user_data
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"message": "Server error during login"}), 500

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    try:
        session.pop('user_id', None)
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({"message": "Server error during logout"}), 500

@app.route("/api/auth/check", methods=["GET"])
def check_auth():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"authenticated": False}), 200

        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            session.pop('user_id', None)
            return jsonify({"authenticated": False}), 200

        user_data = {
            "id": str(user['_id']),
            "username": user['username'],
            "email": user['email'],
            "fullName": user['fullName'],
            "state": user.get('state'),
            "district": user.get('district'),
            "village": user.get('village')
        }

        return jsonify({
            "authenticated": True,
            "user": user_data
        }), 200

    except Exception as e:
        print(f"Auth check error: {str(e)}")
        return jsonify({"message": "Server error during auth check"}), 500

# OAuth routes (updated)
@app.route("/api/auth/oauth/google", methods=["POST"])
def google_oauth():
    try:
        data = request.get_json()
        token = data.get('credential')
        
        # Verify Google token (in production, use proper verification)
        # This is a simplified version - in production, verify the token properly
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        # Check if user exists
        user = users_collection.find_one({"email": decoded['email']})
        
        if not user:
            # Create new user
            user = {
                "email": decoded['email'],
                "username": decoded['email'].split('@')[0],
                "fullName": decoded.get('name'),
                "googleId": decoded['sub'],
                "createdAt": datetime.utcnow()
            }
            result = users_collection.insert_one(user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user['_id'])

        # Create session
        session['user_id'] = user_id
        session.permanent = True

        # Return user data
        return jsonify({
            "message": "Google login successful",
            "user": {
                "id": user_id,
                "username": user.get('username'),
                "email": user.get('email'),
                "fullName": user.get('fullName')
            }
        }), 200

    except Exception as e:
        print(f"Google OAuth error: {str(e)}")
        return jsonify({"message": "Google login failed"}), 400

# Contact route (updated)
@app.route("/api/contact", methods=["POST"])
def contact():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['name', 'email', 'message']):
            return jsonify({"message": "Missing required fields"}), 400

        # Store message in database
        message_entry = {
            "name": data["name"],
            "email": data["email"],
            "message": data["message"],
            "createdAt": datetime.utcnow()
        }
        messages_collection.insert_one(message_entry)

        # Send email notification (optional)
        email_user = os.getenv("EMAIL_USER")
        email_pass = os.getenv("EMAIL_PASS")
        
        if email_user and email_pass:
            msg = MIMEMultipart()
            msg['From'] = email_user
            msg['To'] = email_user
            msg['Subject'] = f"New Contact Message from {data['name']}"
            msg.attach(MIMEText(data['message'], 'plain'))
            
            try:
                with smtplib.SMTP('smtp.gmail.com', 587) as server:
                    server.starttls()
                    server.login(email_user, email_pass)
                    server.send_message(msg)
            except Exception as e:
                print(f"Email sending failed: {str(e)}")

        return jsonify({"message": "Message submitted successfully"}), 200

    except Exception as e:
        print(f"Contact form error: {str(e)}")
        return jsonify({"message": "Server error processing message"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)