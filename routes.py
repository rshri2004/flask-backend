from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from models import (
    db, Account, UserPersonalData, Conditions, Medications,
    DietType, PhysicalActivityLevel, AlcoholConsumption,
    InterstitialFluidElement, DeviceDataQuery, ChatManager, Message
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

@app.route('/chat-docs', methods=['POST'])
def chat_docs():
    """
    Chat with a knowledge base (containing multiple PDF documents) using Claude 3.5 Sonnet.
    The client must send a JSON payload with a "prompt" (the user’s question).
    The knowledge base is already set up with your documents.
    """
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({'message': 'Missing prompt', 'success': False}), 400

    question = data['prompt'].strip()
    if not question:
        return jsonify({'message': 'Prompt is empty', 'success': False}), 400

    # Set the region and model details (make sure these match your AWS setup)
    region = "us-east-1"  # Update if necessary
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"  # Claude 3.5 Sonnet v1 ID
    knowledge_base_id = os.environ.get("KNOWLEDGE_BASE_ID")#"WOGDHCEZX6"  # Your knowledge base ID

    # Create a Boto3 session
    session = boto3.Session(
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        # If using short-lived credentials, also set:
        # aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        region_name=region
    )
    # Use the bedrock-agent-runtime client
    bedrock_agent_client = session.client(service_name='bedrock-agent-runtime')
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"

    try:
        response = bedrock_agent_client.retrieve_and_generate(
            input={'text': question},
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

        return jsonify({
            'message': 'Doc chat success',
            'generated_text': generated_text,
            'success': True
        }), 200

    except ClientError as e:
        traceback.print_exc()
        return jsonify({'message': f'Bedrock error: {str(e)}', 'success': False}), 500
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': f'Error: {str(e)}', 'success': False}), 500


@app.route('/chat-ai/<int:user_id>/<int:chat_id>', methods=['POST'])
def chat_ai(user_id, chat_id):
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({'message': 'Missing prompt', 'success': False}), 400

    prompt = data['prompt'].strip()
    if not prompt:
        return jsonify({'message': 'Prompt is empty', 'success': False}), 400

    # Check if this chat exists for this user
    chat = ChatManager.query.filter_by(user_id=user_id, chat_id=chat_id).first()
    if not chat:
        # Only create a new chat if it doesn't exist
        # This allows chat_id=1 to be reused if it exists
        chat = ChatManager(user_id=user_id, chat_id=chat_id)
        db.session.add(chat)
        db.session.commit()

    #
    if (os.environ.get("AWS_PROFILE") is None):
        session = boto3.Session(
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            # If short-lived creds:
            # aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
            region_name='us-east-1'  # or your chosen region
            # profile_name = "Jeguilos"
        )
    else:
        print("Using profile")
        session = boto3.Session(
            profile_name=os.environ.get("AWS_PROFILE")
        )
    bedrock_client = session.client('bedrock-runtime')

    # The inference profile ID for Claude 3.7 Sonnet
    model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"

    # This matches the example from AWS docs:
    # "anthropic_version": "bedrock-2023-05-31"
    # "max_tokens": <some integer>
    # plus optional fields like "temperature", "top_k", "top_p", "stop_sequences".
    print(prompt)
    request_payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 200,
        "top_k": 250,
        "temperature": 1,
        "top_p": 0.999,
        "stop_sequences": [],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    }
                ]
            }
        ]
    }

    try:
        response = bedrock_client.invoke_model(
            modelId=model_id,
            body=json.dumps(request_payload),
            contentType="application/json",
            accept="application/json"
        )
        response_body = json.loads(response["body"].read())

        # Attempt to parse AI text
        generated_text = None

        # If the response has "content", join all text segments
        if "content" in response_body and isinstance(response_body["content"], list):
            # If there's more than one block, you might join them
            text_blocks = []
            for block in response_body["content"]:
                if block.get("type") == "text" and "text" in block:
                    text_blocks.append(block["text"])
            generated_text = "\n".join(text_blocks)  # or " ".join(...)

        # If we still haven't found text, handle that
        if not generated_text:
            return jsonify({
                'message': 'Unable to parse Claude response',
                'raw_response': response_body,
                'success': False
            }), 200

        storeMessage(user_id, chat_id, "user", prompt)
        storeMessage(user_id, chat_id, "assistant", generated_text)

        return jsonify({
            'message': 'Claude success',
            'generated_text': generated_text,
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
                'chat_id': chat.chat_id
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

    new_chat = ChatManager(user_id=user_id, chat_id=new_chat_id)
    db.session.add(new_chat)
    db.session.commit()

    return jsonify({
        'message': 'Chat created successfully',
        'chat_id': new_chat_id,
        'success': True
    }), 201
