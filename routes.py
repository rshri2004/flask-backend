from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from models import (
    db, Account, UserPersonalData, Conditions, Medications,
    DietType, PhysicalActivityLevel, AlcoholConsumption,
    InterstitialFluidElement, DeviceDataQuery, ChatManager, Message, NotificationCache
)
import jwt
import os
import json
from app import app
from flask_cors import CORS
from functools import wraps
import boto3
import traceback
from botocore.exceptions import ClientError
import re
import hashlib


CORS(app, resources={r"/*": {"origins": "*"}})


# JWT Authentication middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        # Check if user is already authenticated via Flask-Login
        if current_user and current_user.is_authenticated:
            return f(*args, **kwargs)

        # If no token, check for session-based authentication
        if not token:
            try:
                # Try to access current_user
                if current_user.is_authenticated:
                    return f(*args, **kwargs)
                else:
                    return jsonify({'message': 'Authentication required', 'success': False}), 401
            except:
                return jsonify({'message': 'Authentication required', 'success': False}), 401

        try:
            # Decode the token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_account = Account.query.get(data['account_id'])

            if not current_account:
                return jsonify({'message': 'User not found', 'success': False}), 401

            # Store the user for the duration of this request
            request.current_token_user = current_account

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired', 'success': False}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token', 'success': False}), 401

        # Pass to the route
        return f(*args, **kwargs)

    return decorated


# Helper function to get current user from either Flask-Login or JWT token
def get_current_user():
    if hasattr(request, 'current_token_user'):
        return request.current_token_user
    elif current_user and current_user.is_authenticated:
        return current_user
    return None


@app.route('/', methods=['GET'])
def api_home():
    return jsonify({
        "message": "Health Monitoring API",
        "version": "1.0",
        "endpoints": [
            "/api/register",
            "/api/login",
            "/api/patient",
            "/api/conditions",
            "/api/medications"
        ]
    })


# Authentication Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check for required fields
    required_fields = ['first_name', 'last_name', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}', 'success': False}), 400

    # Check if user already exists
    existing_user = Account.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'User with this email already exists', 'success': False}), 409

    # Create new user
    new_user = Account(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        role=data.get('role', 'Patient')  # Default role is Patient
    )

    try:
        new_user.set_password(data['password'])
    except ValueError as e:
        return jsonify({'message': str(e), 'success': False}), 400

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'account_id': new_user.account_id, 'success': True}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required', 'success': False}), 400

    user = Account.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid email or password', 'success': False}), 401

    # Log in the user with Flask-Login
    login_user(user)

    # Generate a JWT token
    token = jwt.encode(
        {
            'account_id': user.account_id,
            'email': user.email,
            'exp': datetime.utcnow() + timedelta(hours=24)
        },
        current_app.config['SECRET_KEY']
    )

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict(),
        'success': True
    }), 200


@app.route('/logout', methods=['POST'])
@token_required
def logout():
    # If using Flask-Login
    if current_user.is_authenticated:
        logout_user()

    return jsonify({'message': 'Logout successful', 'success': True}), 200


# Account Routes
@app.route('/account', methods=['GET'])
@token_required
def get_account():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    return jsonify({'user': user.to_dict(), 'success': True}), 200


@app.route('/account', methods=['PUT'])
@token_required
def update_account():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    data = request.get_json()

    # Update fields if provided
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'email' in data:
        # Check if email is already in use by another user
        existing_user = Account.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.account_id != user.account_id:
            return jsonify({'message': 'Email already in use', 'success': False}), 409
        user.email = data['email']
    if 'password' in data:
        try:
            user.set_password(data['password'])
        except ValueError as e:
            return jsonify({'message': str(e), 'success': False}), 400

    db.session.commit()

    return jsonify({
        'message': 'Account updated successfully',
        'user': user.to_dict(),
        'success': True
    }), 200


# UserPersonalData Routes
@app.route('/patient', methods=['POST'])
@token_required
def create_patient_data():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    data = request.get_json()

    # Check for required fields
    required_fields = ['age', 'gender']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}', 'success': False}), 400

    # Check if personal data already exists for this user
    existing_data = UserPersonalData.query.filter_by(user_account_id=user.account_id).first()
    if existing_data:
        return jsonify({'message': 'Personal data already exists for this user', 'success': False}), 409

    # Create new personal data
    new_data = UserPersonalData(
        user_account_id=user.account_id,
        age=data['age'],
        gender=data['gender'],
        date_of_visit=datetime.now().date(),
        diet_type_id=data.get('diet_type_id'),
        physical_activity_level_id=data.get('physical_activity_level_id'),
        is_smoker=data.get('is_smoker', True),
        alcohol_consumption_id=data.get('alcohol_consumption_id'),
        blood_pressure=data.get('blood_pressure'),
        weight_kg=data.get('weight_kg'),
        height_cm=data.get('height_cm')
    )

    # Calculate BMI if possible
    if new_data.weight_kg and new_data.height_cm:
        new_data.calculate_bmi()

    db.session.add(new_data)
    db.session.commit()

    return jsonify({
        'message': 'Patient data created successfully',
        'patient': new_data.to_dict(),
        'success': True
    }), 201


@app.route('/patient/account/<int:account_id>', methods=['GET'])
@token_required
def get_patient_by_account(account_id):
    """Get patient data by account ID"""
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Check if user has permission to access this data
    if account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    # Find patient data associated with this account
    patient = UserPersonalData.query.filter_by(user_account_id=account_id).first()

    if not patient:
        return jsonify({'message': 'No patient data found for this account', 'success': False}), 404

    return jsonify({'patient': patient.to_dict(), 'success': True}), 200


@app.route('/patient/<int:patient_id>', methods=['GET'])
@token_required
def get_patient_data(patient_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Check if user has permission to access this data
    patient = UserPersonalData.query.get_or_404(patient_id)
    print(f"patient.user_account_id :{patient.user_account_id}", f"user.account_id :{user.account_id}")
    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    return jsonify({'patient': patient.to_dict(), 'success': True}), 200


@app.route('/patient/<int:patient_id>', methods=['PUT'])
@token_required
def update_patient_data(patient_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Check if user has permission to update this data
    patient = UserPersonalData.query.get_or_404(patient_id)

    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    # Update fields if provided
    updatable_fields = [
        'age', 'gender', 'diet_type_id', 'physical_activity_level_id',
        'is_smoker', 'alcohol_consumption_id', 'blood_pressure',
        'weight_kg', 'height_cm'
    ]

    for field in updatable_fields:
        if field in data:
            setattr(patient, field, data[field])

    # Update visit date if specified
    if 'date_of_visit' in data:
        try:
            patient.date_of_visit = datetime.strptime(data['date_of_visit'], '%Y-%m-%d').date()
            patient.previous_visits += 1
        except ValueError:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD', 'success': False}), 400

    # Recalculate BMI if weight or height changed
    if 'weight_kg' in data or 'height_cm' in data:
        patient.calculate_bmi()

    db.session.commit()

    return jsonify({
        'message': 'Patient data updated successfully',
        'patient': patient.to_dict(),
        'success': True
    }), 200


# Condition Routes
@app.route('/conditions', methods=['GET'])
@token_required
def get_conditions():
    conditions = Conditions.query.all()
    return jsonify({'conditions': [condition.to_dict() for condition in conditions], 'success': True}), 200


@app.route('/conditions', methods=['POST'])
@token_required
def create_condition():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Only admin can create new conditions
    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'condition_name' not in data:
        return jsonify({'message': 'Condition name is required', 'success': False}), 400

    # Check if condition already exists
    existing_condition = Conditions.query.filter_by(condition_name=data['condition_name']).first()
    if existing_condition:
        return jsonify({'message': 'Condition already exists', 'success': False}), 409

    new_condition = Conditions(condition_name=data['condition_name'])
    db.session.add(new_condition)
    db.session.commit()

    return jsonify({
        'message': 'Condition created successfully',
        'condition': new_condition.to_dict(),
        'success': True
    }), 201


@app.route('/patient/<int:patient_id>/conditions', methods=['POST'])
@token_required
def add_condition_to_patient(patient_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'condition_id' not in data:
        return jsonify({'message': 'Condition ID is required', 'success': False}), 400

    condition = Conditions.query.get_or_404(data['condition_id'])

    # Check if patient already has this condition
    if patient.conditions.filter_by(condition_id=condition.condition_id).first():
        return jsonify({'message': 'Patient already has this condition', 'success': False}), 409

    patient.conditions.append(condition)
    db.session.commit()

    return jsonify({
        'message': 'Condition added to patient successfully',
        'patient': patient.to_dict(),
        'success': True
    }), 200


# Medication Routes
@app.route('/medications', methods=['GET'])
@token_required
def get_medications():
    medications = Medications.query.all()
    return jsonify({'medications': [medication.to_dict() for medication in medications], 'success': True}), 200


@app.route('/medications', methods=['POST'])
@token_required
def create_medication():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Only admin can create new medications
    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'medication_name' not in data:
        return jsonify({'message': 'Medication name is required', 'success': False}), 400

    # Check if medication already exists
    existing_medication = Medications.query.filter_by(medication_name=data['medication_name']).first()
    if existing_medication:
        return jsonify({'message': 'Medication already exists', 'success': False}), 409

    new_medication = Medications(medication_name=data['medication_name'])
    db.session.add(new_medication)
    db.session.commit()

    return jsonify({
        'message': 'Medication created successfully',
        'medication': new_medication.to_dict(),
        'success': True
    }), 201


@app.route('/patient/<int:patient_id>/medications', methods=['POST'])
@token_required
def add_medication_to_patient(patient_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'medication_id' not in data:
        return jsonify({'message': 'Medication ID is required', 'success': False}), 400

    medication = Medications.query.get_or_404(data['medication_id'])

    # Check if patient already has this medication
    if patient.medications.filter_by(medication_id=medication.medication_id).first():
        return jsonify({'message': 'Patient already has this medication', 'success': False}), 409

    patient.medications.append(medication)
    db.session.commit()

    return jsonify({
        'message': 'Medication added to patient successfully',
        'patient': patient.to_dict(),
        'success': True
    }), 200


# Device Data Routes
@app.route('/device-data', methods=['POST'])
@token_required
def log_device_data():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    data = request.get_json()

    required_fields = ['recorded_value', 'element_id', 'user_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}', 'success': False}), 400

    # Verify patient exists and user has permission
    patient = UserPersonalData.query.get_or_404(data['user_id'])
    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    # Verify element exists
    element = InterstitialFluidElement.query.get_or_404(data['element_id'])

    new_data = DeviceDataQuery(
        recorded_value=data['recorded_value'],
        element_id=data['element_id'],
        user_id=data['user_id'],
        date_logged=datetime.now().date(),
        time_stamp=datetime.now().time()
    )

    db.session.add(new_data)
    db.session.commit()

    return jsonify({
        'message': 'Device data logged successfully',
        'device_data': new_data.to_dict(),
        'success': True
    }), 201


@app.route('/patient/<int:patient_id>/device-data', methods=['GET'])
@token_required
def get_patient_device_data(patient_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != user.account_id and user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    # Get query parameters for filtering
    element_id = request.args.get('element_id', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Build query
    query = DeviceDataQuery.query.filter_by(user_id=patient_id)

    if element_id:
        query = query.filter_by(element_id=element_id)

    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            query = query.filter(DeviceDataQuery.date_logged >= start_date)
        except ValueError:
            return jsonify({'message': 'Invalid start_date format. Use YYYY-MM-DD', 'success': False}), 400

    if end_date:
        try:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(DeviceDataQuery.date_logged <= end_date)
        except ValueError:
            return jsonify({'message': 'Invalid end_date format. Use YYYY-MM-DD', 'success': False}), 400

    # Order by date and time
    query = query.order_by(DeviceDataQuery.date_logged, DeviceDataQuery.time_stamp)

    device_data = query.all()
    return jsonify({'data': [data.to_dict() for data in device_data], 'success': True}), 200


# Reference Data Routes
@app.route('/diet-types', methods=['GET'])
@token_required
def get_diet_types():
    diet_types = DietType.query.all()
    return jsonify({'diet_types': [diet.to_dict() for diet in diet_types], 'success': True}), 200


@app.route('/activity-levels', methods=['GET'])
@token_required
def get_activity_levels():
    activity_levels = PhysicalActivityLevel.query.all()
    return jsonify({'activity_levels': [level.to_dict() for level in activity_levels], 'success': True}), 200


@app.route('/alcohol-consumption-levels', methods=['GET'])
@token_required
def get_alcohol_consumption_levels():
    consumption_levels = AlcoholConsumption.query.all()
    return jsonify({'levels': [level.to_dict() for level in consumption_levels], 'success': True}), 200


@app.route('/fluid-elements', methods=['GET'])
@token_required
def get_fluid_elements():
    elements = InterstitialFluidElement.query.all()
    return jsonify({'elements': [element.to_dict() for element in elements], 'success': True}), 200


# Admin-only routes for reference data management
@app.route('/admin/diet-types', methods=['POST'])
@token_required
def create_diet_type():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'diet_type' not in data:
        return jsonify({'message': 'Diet type is required', 'success': False}), 400

    existing = DietType.query.filter_by(diet_type=data['diet_type']).first()
    if existing:
        return jsonify({'message': 'Diet type already exists', 'success': False}), 409

    new_diet_type = DietType(diet_type=data['diet_type'])
    db.session.add(new_diet_type)
    db.session.commit()

    return jsonify({
        'message': 'Diet type created successfully',
        'diet_type': new_diet_type.to_dict(),
        'success': True
    }), 201


@app.route('/admin/activity-levels', methods=['POST'])
@token_required
def create_activity_level():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'activity_level' not in data:
        return jsonify({'message': 'Activity level is required', 'success': False}), 400

    existing = PhysicalActivityLevel.query.filter_by(activity_level=data['activity_level']).first()
    if existing:
        return jsonify({'message': 'Activity level already exists', 'success': False}), 409

    new_activity_level = PhysicalActivityLevel(activity_level=data['activity_level'])
    db.session.add(new_activity_level)
    db.session.commit()

    return jsonify({
        'message': 'Activity level created successfully',
        'activity_level': new_activity_level.to_dict(),
        'success': True
    }), 201


@app.route('/admin/fluid-elements', methods=['POST'])
@token_required
def create_fluid_element():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'element_name' not in data:
        return jsonify({'message': 'Element name is required', 'success': False}), 400

    existing = InterstitialFluidElement.query.filter_by(element_name=data['element_name']).first()
    if existing:
        return jsonify({'message': 'Fluid element already exists', 'success': False}), 409

    new_element = InterstitialFluidElement(
        element_name=data['element_name'],
        upper_limit=data.get('upper_limit'),
        lower_limit=data.get('lower_limit'),
        upper_critical_limit=data.get('upper_critical_limit'),
        lower_critical_limit=data.get('lower_critical_limit')
    )
    db.session.add(new_element)
    db.session.commit()

    return jsonify({
        'message': 'Fluid element created successfully',
        'element': new_element.to_dict(),
        'success': True
    }), 201


@app.route('/admin/alcohol-consumption', methods=['POST'])
@token_required
def create_alcohol_consumption():
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    if user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    data = request.get_json()

    if not data or 'consumption_level' not in data:
        return jsonify({'message': 'Consumption level is required', 'success': False}), 400

    existing = AlcoholConsumption.query.filter_by(consumption_level=data['consumption_level']).first()
    if existing:
        return jsonify({'message': 'Alcohol consumption level already exists', 'success': False}), 409

    new_level = AlcoholConsumption(consumption_level=data['consumption_level'])
    db.session.add(new_level)
    db.session.commit()

    return jsonify({
        'message': 'Alcohol consumption level created successfully',
        'level': new_level.to_dict(),
        'success': True
    }), 201

def generate_title_with_claude(first_message):
    """Generate a descriptive title for a chat using Claude itself"""
    try:
        # Set up the AWS session exactly as we do for regular Claude calls
        if (os.environ.get("AWS_PROFILE") is None):
            session = boto3.Session(
                aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                # If short-lived creds:
                #aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
                region_name='us-east-1'
            )
        else:
            print("Using profile")
            session = boto3.Session(
                profile_name=os.environ.get("AWS_PROFILE")
            )
            
        bedrock_runtime = session.client(service_name='bedrock-runtime')
        
        # Special prompt to ask Claude to generate a short, descriptive title
        title_prompt = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 20,  # Short response
            "temperature": 0.7,
            "messages": [
                {
                    "role": "user", 
                    "content": f"Based on this first message in a conversation, generate a very concise, descriptive title (5 words maximum, no quotes): \"{first_message}\""
                }
            ]
        }
        
        # Call Claude via Bedrock for title generation
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-5-sonnet-20240620-v1:0",
            body=json.dumps(title_prompt)
        )
        
        # Parse the response
        response_body = json.loads(response['body'].read().decode())
        
        if "content" in response_body and len(response_body["content"]) > 0:
            title = response_body["content"][0]["text"].strip()
            
            # Clean up the title (remove quotes if present)
            if title.startswith('"') and title.endswith('"'):
                title = title[1:-1]
                
            return title
        
        return "New Chat"  # Fallback
    except Exception as e:
        print(f"Error generating title: {e}")
        return "New Chat"  # Fallback

@app.route('/chat-ai/<int:user_id>/<int:chat_id>', methods=['POST'])
@token_required
def chat_ai(user_id, chat_id):
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({'message': 'Missing prompt', 'success': False}), 400

    #prompt to user_prompt
    prompt = data['prompt'].strip()
    if not prompt:
        return jsonify({'message': 'Prompt is empty', 'success': False}), 400

    ##This is where we get the user data into the chatbot
    #Retrieve current user using JWT token
    user = get_current_user()
    health_context = ""

    if user:
    # Retrieve health profile for the user
        profile = UserPersonalData.query.filter_by(user_account_id=user.account_id).first()

        if profile:
            # Build a context string with the key health metrics,
            # explicitly checking for None so that even falsy numbers are included.
            health_context = "Profile Info: "

            if profile.age is not None:
                health_context += f"Age: {profile.age}. "
            else:
                health_context += "Age: unknown. "

            if profile.weight_kg is not None:
                health_context += f"Weight: {profile.weight_kg} kg. "
            else:
                health_context += "Weight: unknown. "

            if profile.height_cm is not None:
                health_context += f"Height: {profile.height_cm} cm. "
            else:
                health_context += "Height: unknown. "

            if profile.blood_pressure:
                health_context += f"Blood Pressure: {profile.blood_pressure}. "
            else:
                health_context += "Blood Pressure: not provided. "

            if profile.bmi is not None:
                health_context += f"BMI: {profile.bmi}. "
            else:
                health_context += "BMI: unknown. "

            # End with a newline to separate from the user's question
            health_context += "\n"

    # Combine the health context with the user's prompt
    profile_prompt = health_context + prompt

    # Set the region and model details
    region = "us-east-1"
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"  # Claude 3.5 Sonnet v1 ID
    knowledge_base_id = os.environ.get("KNOWLEDGE_BASE_ID")

    if not knowledge_base_id:
        return jsonify({'message': 'Knowledge Base ID not set', 'success': False}), 500

    # Check if this chat exists for this user
    chat = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()

    # Track if this is the first message (for title generation)
    first_message = False

    if not chat:
        # Create new chat if it doesn't exist
        chat = ChatManager(user_id=user_id, chat_id=chat_id, title="New Chat")
        db.session.add(chat)
        db.session.commit()
        first_message = True
    else:
        # Check if there are any messages in this chat
        first_message = not Message.query.filter_by(chat_id=chat.id).first()

    # Get previous messages from this chat
    previous_messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp).all()

    # context-aware prompt by adding previous conversations
    enhanced_prompt = profile_prompt

    # Only include history if there are previous messages
    if previous_messages and len(previous_messages) > 0:
        # Limit to last 5 exchanges to avoid token limits(for user and assistant)
        history_text = []
        recent_messages = previous_messages[-10:]  # Get last 10 messages

        for msg in recent_messages:
            role = "User" if msg.sender == "user" else "Assistant"
            history_text.append(f"{role}: {msg.content}")

        # Construct enhanced prompt with history context
        if history_text:
            history_string = "\n".join(history_text)
            enhanced_prompt = f"""
                Previous conversation:{history_string}
                New question: {profile_prompt}
                Please respond to the new question in the context of the previous conversation.
                """

    if (os.environ.get("AWS_PROFILE") is None):
        session = boto3.Session(
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            # If short-lived creds:
            #aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
            region_name='us-east-1'
        )
    else:
        print("Using profile")
        session = boto3.Session(
            profile_name=os.environ.get("AWS_PROFILE")
        )

    # Use the bedrock-agent-runtime client
    bedrock_agent_client = session.client(service_name='bedrock-agent-runtime')
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    try:
        # Use the enhanced prompt that includes conversation history
        response = bedrock_agent_client.retrieve_and_generate(
            input={'text': enhanced_prompt},
            retrieveAndGenerateConfiguration={
                'type': 'KNOWLEDGE_BASE',
                'knowledgeBaseConfiguration': {
                    'knowledgeBaseId': knowledge_base_id,
                    'modelArn': model_arn
                }
            }
        )

        # Attempt to parse Claude's response
        generated_text = None

        if "output" in response and "text" in response["output"]:
            generated_text = response["output"]["text"]
        elif "content" in response and isinstance(response["content"], list):
            text_blocks = [block["text"] for block in response["content"]
                           if block.get("type") == "text" and "text" in block]
            generated_text = "\n".join(text_blocks)

        if not generated_text:
            return jsonify({
                'message': 'Unable to parse Claude 3.5 response',
                'raw_response': response,
                'success': False
            }), 200

        storeMessage(user_id, chat_id, "user", prompt)
        storeMessage(user_id, chat_id, "assistant", generated_text)

        # Generate a title if this is the first message
        if first_message:
            title = generate_title_with_claude(prompt)
            chat.title = title
            db.session.commit()

        return jsonify({
            'message': 'Claude success',
            'generated_text': generated_text,
            'title': chat.title,
            'success': True
        }), 200

    except ClientError as e:
        return jsonify({'message': f'Bedrock error: {str(e)}', 'success': False}), 500
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}', 'success': False}), 500
    
def storeMessage(user_id, chat_id, sender, content):
    # Get the actual ChatManager record to get its ID
    chat_manager = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()

    if not chat_manager:
        # This shouldn't happen since you create the chat if it doesn't exist
        return

    new_message = Message(
        chat_id=chat_manager.id,  # Use the primary key of ChatManager
        sender=sender,
        content=content,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_message)
    db.session.commit()


def createNewChat(user_id, chat_id):
    new_chat = ChatManager(user_id=user_id, chat_id=chat_id)
    db.session.add(new_chat)
    db.session.commit()


# GetUserChats test!!
@app.route('/chats/<int:user_id>', methods=['GET'])
@token_required
def get_user_chats(user_id):
    chats = ChatManager.query.filter_by(user_id=user_id).all()

    return jsonify({
        'success': True,
        'chats': [
            {
                'id': chat.id,
                'chat_id': chat.chat_id,
                'title': chat.title or f"Chat #{chat.chat_id}"
            } for chat in chats
        ]
    })


# Get Chat History
@app.route('/chat-history/<int:user_id>/<int:chat_id>', methods=['GET'])
@token_required
def get_chat_history(user_id, chat_id):
    chat = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()

    if not chat:
        return jsonify({'message': 'Chat not found', 'success': False}), 404

    messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp).all()

    return jsonify({
        'success': True,
        'title': chat.title,
        'messages': [
            {
                'id': msg.id,
                'sender': msg.sender,
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%Y-%m-%dT%H:%M:%S')
            } for msg in messages
        ]
    })


@app.route('/chats/<int:user_id>', methods=['POST'])
@token_required
def create_new_chat(user_id):
    # Find the Highest Chat ID for user and increment by 1
    max_chat = ChatManager.query.filter_by(user_id=user_id).order_by(ChatManager.chat_id.desc()).first()
    new_chat_id = 1
    if max_chat:
        new_chat_id = max_chat.chat_id + 1

    new_chat = ChatManager(user_id=user_id, chat_id=new_chat_id, title=f"New Chat #{new_chat_id}")
    db.session.add(new_chat)
    db.session.commit()

    return jsonify({
        'message': 'Chat created successfully',
        'chat_id': new_chat_id,
        'title': new_chat.title,
        'success': True
    }), 201


@app.route('/chats/<int:user_id>/<int:chat_id>', methods=['DELETE'])
@token_required
def delete_chat(user_id, chat_id):
    chat = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()

    if not chat:
        print("Chat not found")
        return jsonify({'message': 'Chat not found', 'success': False}), 404

    #delete all messages associated with this chat
    #Message.query.filter_by(chat_id=chat.id).delete()
    db.session.delete(chat)
    db.session.commit()

    return jsonify({'message': 'Chat deleted successfully', 'success': True}), 200

# Update chat title
@app.route('/chats/<int:user_id>/<int:chat_id>/title', methods=['PUT'])
@token_required
def update_chat_title(user_id, chat_id):
    user = get_current_user()
    if not user:
        return jsonify({'message': 'Authentication required', 'success': False}), 401

    # Get chat
    chat = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()
    if not chat:
        return jsonify({'message': 'Chat not found', 'success': False}), 404

    # Verify chat owner
    if chat.user_id != user.account_id:
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    # Get new title
    data = request.get_json()
    if not data or 'title' not in data:
        return jsonify({'message': 'Title is required', 'success': False}), 400

    chat.title = data['title']
    db.session.commit()

    return jsonify({
        'message': 'Chat title updated successfully',
        'chat': {
            'id': chat.id,
            'chat_id': chat.chat_id,
            'title': chat.title
        },
        'success': True
    }), 200


# Helper function to generate cache key based on user data and biomarker readings
def generate_cache_key(user_id, profile_data=None, latest_reading_timestamp=None):
    #Generate a unique cache key based on user ID and latest data changes
    key_parts = [str(user_id)]

    # Add profile data last updated timestamp if available
    if profile_data and hasattr(profile_data, 'date_of_visit'):
        key_parts.append(str(profile_data.date_of_visit))

    # Add latest biomarker reading timestamp if available
    if latest_reading_timestamp:
        key_parts.append(str(latest_reading_timestamp))

    # Add day component to expire cache each day at minimum
    key_parts.append(datetime.now().strftime('%Y-%m-%d'))

    # Create a unique hash from the combined values
    cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
    return cache_key


@app.route('/health-notifications/<int:user_id>', methods=['GET'])
@token_required
def get_health_notifications(user_id):
    """
    Generate health notifications based on user profile and biomarker data.

    Uses a database-backed caching layer to improve performance:
    - Cache invalidation based on data changes and time thresholds
    - Force refresh option via query parameter
    """
    # Get current user from token
    current_user = get_current_user()

    # Check if user has permission to access this data
    if user_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    # Check for force refresh parameter
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'

    try:
        # 1. Fetch user profile data
        profile = UserPersonalData.query.filter_by(user_account_id=user_id).first()
        if not profile:
            return jsonify({'message': 'User profile not found', 'success': False}), 404

        # 2. Get timestamp of latest biomarker reading
        latest_reading = DeviceDataQuery.query.filter_by(user_id=profile.patient_id).order_by(
            DeviceDataQuery.date_logged.desc(),
            DeviceDataQuery.time_stamp.desc()
        ).first()

        latest_timestamp = None
        if latest_reading:
            latest_timestamp = f"{latest_reading.date_logged} {latest_reading.time_stamp}"

        # 3. Generate cache key
        cache_key = generate_cache_key(user_id, profile, latest_timestamp)

        # 4. Try to get from cache first (unless force refresh is requested)
        if not force_refresh:
            # Try database cache
            db_cache = NotificationCache.query.filter_by(cache_key=cache_key).first()
            if db_cache and db_cache.is_valid():
                # Valid cache entry found in database
                notifications = json.loads(db_cache.notifications_json)

                return jsonify({
                    'message': 'Health notifications retrieved from cache',
                    'notifications': notifications,
                    'cached': True,
                    'cache_updated': db_cache.last_updated.strftime('%Y-%m-%d %H:%M:%S'),
                    'success': True
                }), 200

        # 5. No valid cache found or force refresh generate fresh notifications

        # Fetch user conditions and medications
        conditions = [condition.condition_name for condition in profile.conditions]
        medications = [medication.medication_name for medication in profile.medications]

        # Fetch biomarker data for different time frames
        today = datetime.now().date()
        time_frames = {
            "today": (today, today),
            "past_week": (today - timedelta(days=7), today),
            "past_month": (today - timedelta(days=30), today),
            "past_three_months": (today - timedelta(days=90), today),
            "past_six_months": (today - timedelta(days=180), today),
            "past_year": (today - timedelta(days=365), today)
        }

        # Get all biomarker elements
        elements = InterstitialFluidElement.query.all()
        element_map = {element.element_id: element.element_name for element in elements}

        # Initialize biomarker data structure
        biomarker_data = {}

        # Get device data for each time frame
        for period_name, (start_date, end_date) in time_frames.items():
            # Query data for this time frame
            query = DeviceDataQuery.query.filter_by(user_id=profile.patient_id).filter(
                DeviceDataQuery.date_logged >= start_date,
                DeviceDataQuery.date_logged <= end_date
            ).order_by(DeviceDataQuery.date_logged, DeviceDataQuery.time_stamp)

            device_data = query.all()

            # Process data into a structured format
            if device_data:
                biomarker_data[period_name] = {}
                for data_point in device_data:
                    element_name = element_map.get(data_point.element_id)
                    if element_name not in biomarker_data[period_name]:
                        biomarker_data[period_name][element_name] = []

                    # Add data point with date and value
                    biomarker_data[period_name][element_name].append({
                        "date": data_point.date_logged.strftime('%Y-%m-%d'),
                        "time": data_point.time_stamp.strftime('%H:%M:%S'),
                        "value": data_point.recorded_value
                    })

        # Calculate statistics for each biomarker and time frame
        biomarker_stats = {}
        for period_name, period_data in biomarker_data.items():
            biomarker_stats[period_name] = {}
            for element_name, readings in period_data.items():
                # Only calculate stats if we have readings
                if readings:
                    values = [reading["value"] for reading in readings]
                    biomarker_stats[period_name][element_name] = {
                        "count": len(values),
                        "min": min(values),
                        "max": max(values),
                        "avg": sum(values) / len(values),
                        "first": values[0],
                        "last": values[-1],
                        # Calculate trend (positive = increasing, negative = decreasing)
                        "trend": values[-1] - values[0] if len(values) > 1 else 0
                    }

        # Get reference ranges for each biomarker
        element_reference_ranges = {}
        for element in elements:
            element_reference_ranges[element.element_name] = {
                "lower_limit": float(element.lower_limit) if element.lower_limit else None,
                "upper_limit": float(element.upper_limit) if element.upper_limit else None,
                "lower_critical_limit": float(element.lower_critical_limit) if element.lower_critical_limit else None,
                "upper_critical_limit": float(element.upper_critical_limit) if element.upper_critical_limit else None
            }

        # Build the context for the AWS RAG query
        health_context = {
            "profile": {
                "age": profile.age,
                "gender": profile.gender,
                "bmi": float(profile.bmi) if profile.bmi else None,
                "weight_kg": profile.weight_kg,
                "height_cm": profile.height_cm,
                "blood_pressure": profile.blood_pressure,
                "conditions": conditions,
                "medications": medications,
                "is_smoker": profile.is_smoker,
                "diet_type_id": profile.diet_type_id,
                "physical_activity_level_id": profile.physical_activity_level_id,
                "alcohol_consumption_id": profile.alcohol_consumption_id
            },
            "biomarker_stats": biomarker_stats,
            "reference_ranges": element_reference_ranges
        }

        # Convert to JSON string
        health_context_json = json.dumps(health_context, indent=2)

        # Create the prompt for Claude
        prompt = f"""
        Based on the following patient health data, generate a list of ACTIONABLE health notifications that should be shown to the patient in their home feed.

        Patient health data:
        {health_context_json}

        For each notification:
        1. Focus on significant findings, concerning trends, or positive improvements
        2. Prioritize notifications (Critical, Warning, Informational, Positive)
        3. Make suggestions specific and actionable
        4. Reference specific biomarkers and their values/trends
        5. Put the information in context of the patient's conditions and risk factors
        6. Explain in simple terms why this notification matters to their health
        7. Use a supportive, non-alarming tone even for critical notifications
        8. Specify which time range was used for the recommendation (today, past_week, past_month, past_three_months, past_six_months, past_year)

        Return the results in the following JSON format:
        {{
          "notifications": [
            {{
              "id": 1,
              "priority": "Critical|Warning|Informational|Positive",
              "title": "Brief clear description",
              "message": "Detailed explanation and recommendation",
              "related_biomarkers": ["biomarker1", "biomarker2"],
              "time_range": "time period used for this insight (today, past_week, past_month, etc.)",
              "recommendation": "Specific action the user should take"
            }}
          ]
        }}

        Return at most 5 notifications, prioritizing the most significant findings.
        """

        # Setup AWS session
        if (os.environ.get("AWS_PROFILE") is None):
            session = boto3.Session(
                aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                region_name='us-east-1'
            )
        else:
            session = boto3.Session(
                profile_name=os.environ.get("AWS_PROFILE")
            )

        # Use the bedrock-agent-runtime client
        bedrock_agent_client = session.client(service_name='bedrock-agent-runtime')

        # Get the knowledge base ID from environment
        knowledge_base_id = os.environ.get("KNOWLEDGE_BASE_ID")
        if not knowledge_base_id:
            return jsonify({'message': 'Knowledge Base ID not set', 'success': False}), 500

        # Set the model details
        region = "us-east-1"
        model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"  # Claude 3.5 Sonnet v1 ID
        model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

        # Call AWS Bedrock RAG
        response = bedrock_agent_client.retrieve_and_generate(
            input={'text': prompt},
            retrieveAndGenerateConfiguration={
                'type': 'KNOWLEDGE_BASE',
                'knowledgeBaseConfiguration': {
                    'knowledgeBaseId': knowledge_base_id,
                    'modelArn': model_arn
                }
            }
        )

        # Parse the response
        generated_text = None
        if "output" in response and "text" in response["output"]:
            generated_text = response["output"]["text"]
        elif "content" in response and isinstance(response["content"], list):
            text_blocks = [block["text"] for block in response["content"]
                           if block.get("type") == "text" and "text" in block]
            generated_text = "\n".join(text_blocks)

        if not generated_text:
            return jsonify({
                'message': 'Unable to parse Claude response',
                'success': False
            }), 500

        # Extract JSON from the response
        try:
            # Extract JSON part from the response
            json_match = re.search(r'```json\s*(.*?)\s*```', generated_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # If no JSON code block, try to find JSON object directly
                json_match = re.search(r'({[\s\S]*})', generated_text)
                json_str = json_match.group(1) if json_match else generated_text

            notifications_data = json.loads(json_str)
            notifications = notifications_data.get('notifications', [])

            # 6. Store in database cache
            # Calculate expiration time (24 hours later)
            invalidate_time = datetime.utcnow() + timedelta(hours=24)

            # Check if we have an existing cache entry
            existing_cache = NotificationCache.query.filter_by(cache_key=cache_key).first()

            if existing_cache:
                # Update existing cache entry
                existing_cache.notifications_json = json.dumps(notifications)
                existing_cache.last_updated = datetime.utcnow()
                existing_cache.invalidate_after = invalidate_time
            else:
                # Create new cache entry
                new_cache = NotificationCache(
                    user_id=user_id,
                    cache_key=cache_key,
                    notifications_json=json.dumps(notifications),
                    invalidate_after=invalidate_time
                )
                db.session.add(new_cache)

            db.session.commit()

            # Return the parsed notifications
            return jsonify({
                'message': 'Health notifications generated successfully',
                'notifications': notifications,
                'cached': False,
                'success': True
            }), 200

        except (json.JSONDecodeError, AttributeError) as e:
            # If JSON parsing fails, return the raw text
            return jsonify({
                'message': 'Failed to parse notifications as JSON',
                'generated_text': generated_text,
                'error': str(e),
                'success': False
            }), 200

    except ClientError as e:
        return jsonify({'message': f'Bedrock error: {str(e)}', 'success': False}), 500
    except Exception as e:
        print(f"Error generating health notifications: {traceback.format_exc()}")
        return jsonify({'message': f'Error: {str(e)}', 'success': False}), 500


# Utility endpoint to manually invalidate the notification cache
@app.route('/health-notifications/<int:user_id>/invalidate-cache', methods=['POST'])
@token_required
def invalidate_notification_cache(user_id):
    """Manually invalidate the cached notifications for a user"""
    current_user = get_current_user()

    # Check permissions
    if user_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access', 'success': False}), 403

    try:
        # Find all cache entries for this user
        cache_entries = NotificationCache.query.filter_by(user_id=user_id).all()

        # Delete all entries
        for entry in cache_entries:
            db.session.delete(entry)

        db.session.commit()

        return jsonify({
            'message': f'Cache invalidated for user {user_id}',
            'entries_removed': len(cache_entries),
            'success': True
        }), 200

    except Exception as e:
        return jsonify({'message': f'Error invalidating cache: {str(e)}', 'success': False}), 500