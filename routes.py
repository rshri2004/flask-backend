from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from models import (
    db, Account, UserPersonalData, Conditions, Medications,
    DietType, PhysicalActivityLevel, AlcoholConsumption,
    InterstitialFluidElement, DeviceDataQuery
)
import jwt
import os
from app import app


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
            return jsonify({'message': f'Missing required field: {field}'}), 400

    # Check if user already exists
    existing_user = Account.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'User with this email already exists'}), 409

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
        return jsonify({'message': str(e)}), 400

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'account_id': new_user.account_id}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400

    user = Account.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401

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
        'user': user.to_dict()
    }), 200


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200


# Account Routes
@app.route('/account', methods=['GET'])
@login_required
def get_account():
    return jsonify(current_user.to_dict()), 200


@app.route('/account', methods=['PUT'])
@login_required
def update_account():
    data = request.get_json()

    # Update fields if provided
    if 'first_name' in data:
        current_user.first_name = data['first_name']
    if 'last_name' in data:
        current_user.last_name = data['last_name']
    if 'email' in data:
        # Check if email is already in use by another user
        existing_user = Account.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.account_id != current_user.account_id:
            return jsonify({'message': 'Email already in use'}), 409
        current_user.email = data['email']
    if 'password' in data:
        try:
            current_user.set_password(data['password'])
        except ValueError as e:
            return jsonify({'message': str(e)}), 400

    db.session.commit()

    return jsonify({
        'message': 'Account updated successfully',
        'user': current_user.to_dict()
    }), 200


# UserPersonalData Routes
@app.route('/patient', methods=['POST'])
@login_required
def create_patient_data():
    data = request.get_json()

    # Check for required fields
    required_fields = ['age', 'gender']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400

    # Check if personal data already exists for this user
    existing_data = UserPersonalData.query.filter_by(user_account_id=current_user.account_id).first()
    if existing_data:
        return jsonify({'message': 'Personal data already exists for this user'}), 409

    # Create new personal data
    new_data = UserPersonalData(
        user_account_id=current_user.account_id,
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
        'patient': new_data.to_dict()
    }), 201


@app.route('/patient/account/<int:account_id>', methods=['GET'])
@login_required
def get_patient_by_account(account_id):
    """Get patient data by account ID"""
    # Check if user has permission to access this data
    if account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    # Find patient data associated with this account
    patient = UserPersonalData.query.filter_by(user_account_id=account_id).first()

    if not patient:
        return jsonify({'message': 'No patient data found for this account'}), 404

    return jsonify(patient.to_dict()), 200

@app.route('/patient/<int:patient_id>', methods=['GET'])
@login_required
def get_patient_data(patient_id):
    # Check if user has permission to access this data
    patient = UserPersonalData.query.get_or_404(patient_id)
    print(f"patient.user_account_id :{patient.user_account_id}", f"current_user.account_id :{current_user.account_id}")
    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    return jsonify(patient.to_dict()), 200


@app.route('/patient/<int:patient_id>', methods=['PUT'])
@login_required
def update_patient_data(patient_id):
    # Check if user has permission to update this data
    patient = UserPersonalData.query.get_or_404(patient_id)

    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

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
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400

    # Recalculate BMI if weight or height changed
    if 'weight_kg' in data or 'height_cm' in data:
        patient.calculate_bmi()

    db.session.commit()

    return jsonify({
        'message': 'Patient data updated successfully',
        'patient': patient.to_dict()
    }), 200


# Condition Routes
@app.route('/conditions', methods=['GET'])
@login_required
def get_conditions():
    conditions = Conditions.query.all()
    return jsonify([condition.to_dict() for condition in conditions]), 200


@app.route('/conditions', methods=['POST'])
@login_required
def create_condition():
    # Only admin can create new conditions
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'condition_name' not in data:
        return jsonify({'message': 'Condition name is required'}), 400

    # Check if condition already exists
    existing_condition = Conditions.query.filter_by(condition_name=data['condition_name']).first()
    if existing_condition:
        return jsonify({'message': 'Condition already exists'}), 409

    new_condition = Conditions(condition_name=data['condition_name'])
    db.session.add(new_condition)
    db.session.commit()

    return jsonify({
        'message': 'Condition created successfully',
        'condition': new_condition.to_dict()
    }), 201


@app.route('/patient/<int:patient_id>/conditions', methods=['POST'])
@login_required
def add_condition_to_patient(patient_id):
    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'condition_id' not in data:
        return jsonify({'message': 'Condition ID is required'}), 400

    condition = Conditions.query.get_or_404(data['condition_id'])

    # Check if patient already has this condition
    if patient.conditions.filter_by(condition_id=condition.condition_id).first():
        return jsonify({'message': 'Patient already has this condition'}), 409

    patient.conditions.append(condition)
    db.session.commit()

    return jsonify({
        'message': 'Condition added to patient successfully',
        'patient': patient.to_dict()
    }), 200


# Medication Routes
@app.route('/medications', methods=['GET'])
@login_required
def get_medications():
    medications = Medications.query.all()
    return jsonify([medication.to_dict() for medication in medications]), 200


@app.route('/medications', methods=['POST'])
@login_required
def create_medication():
    # Only admin can create new medications
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'medication_name' not in data:
        return jsonify({'message': 'Medication name is required'}), 400

    # Check if medication already exists
    existing_medication = Medications.query.filter_by(medication_name=data['medication_name']).first()
    if existing_medication:
        return jsonify({'message': 'Medication already exists'}), 409

    new_medication = Medications(medication_name=data['medication_name'])
    db.session.add(new_medication)
    db.session.commit()

    return jsonify({
        'message': 'Medication created successfully',
        'medication': new_medication.to_dict()
    }), 201


@app.route('/patient/<int:patient_id>/medications', methods=['POST'])
@login_required
def add_medication_to_patient(patient_id):
    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'medication_id' not in data:
        return jsonify({'message': 'Medication ID is required'}), 400

    medication = Medications.query.get_or_404(data['medication_id'])

    # Check if patient already has this medication
    if patient.medications.filter_by(medication_id=medication.medication_id).first():
        return jsonify({'message': 'Patient already has this medication'}), 409

    patient.medications.append(medication)
    db.session.commit()

    return jsonify({
        'message': 'Medication added to patient successfully',
        'patient': patient.to_dict()
    }), 200


# Device Data Routes
@app.route('/device-data', methods=['POST'])
@login_required
def log_device_data():
    data = request.get_json()

    required_fields = ['recorded_value', 'element_id', 'user_id']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400

    # Verify patient exists and user has permission
    patient = UserPersonalData.query.get_or_404(data['user_id'])
    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

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
        'device_data': new_data.to_dict()
    }), 201


@app.route('/patient/<int:patient_id>/device-data', methods=['GET'])
@login_required
def get_patient_device_data(patient_id):
    patient = UserPersonalData.query.get_or_404(patient_id)

    # Check if user has permission
    if patient.user_account_id != current_user.account_id and current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

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
            return jsonify({'message': 'Invalid start_date format. Use YYYY-MM-DD'}), 400

    if end_date:
        try:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(DeviceDataQuery.date_logged <= end_date)
        except ValueError:
            return jsonify({'message': 'Invalid end_date format. Use YYYY-MM-DD'}), 400

    # Order by date and time
    query = query.order_by(DeviceDataQuery.date_logged, DeviceDataQuery.time_stamp)

    device_data = query.all()
    return jsonify([data.to_dict() for data in device_data]), 200


# Reference Data Routes
@app.route('/diet-types', methods=['GET'])
@login_required
def get_diet_types():
    diet_types = DietType.query.all()
    return jsonify([diet.to_dict() for diet in diet_types]), 200


@app.route('/activity-levels', methods=['GET'])
@login_required
def get_activity_levels():
    activity_levels = PhysicalActivityLevel.query.all()
    return jsonify([level.to_dict() for level in activity_levels]), 200


@app.route('/alcohol-consumption-levels', methods=['GET'])
@login_required
def get_alcohol_consumption_levels():
    consumption_levels = AlcoholConsumption.query.all()
    return jsonify([level.to_dict() for level in consumption_levels]), 200


@app.route('/fluid-elements', methods=['GET'])
@login_required
def get_fluid_elements():
    elements = InterstitialFluidElement.query.all()
    return jsonify([element.to_dict() for element in elements]), 200


# Admin-only routes for reference data management
@app.route('/admin/diet-types', methods=['POST'])
@login_required
def create_diet_type():
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'diet_type' not in data:
        return jsonify({'message': 'Diet type is required'}), 400

    existing = DietType.query.filter_by(diet_type=data['diet_type']).first()
    if existing:
        return jsonify({'message': 'Diet type already exists'}), 409

    new_diet_type = DietType(diet_type=data['diet_type'])
    db.session.add(new_diet_type)
    db.session.commit()

    return jsonify({
        'message': 'Diet type created successfully',
        'diet_type': new_diet_type.to_dict()
    }), 201


@app.route('/admin/activity-levels', methods=['POST'])
@login_required
def create_activity_level():
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'activity_level' not in data:
        return jsonify({'message': 'Activity level is required'}), 400

    existing = PhysicalActivityLevel.query.filter_by(activity_level=data['activity_level']).first()
    if existing:
        return jsonify({'message': 'Activity level already exists'}), 409

    new_activity_level = PhysicalActivityLevel(activity_level=data['activity_level'])
    db.session.add(new_activity_level)
    db.session.commit()

    return jsonify({
        'message': 'Activity level created successfully',
        'activity_level': new_activity_level.to_dict()
    }), 201


@app.route('/admin/fluid-elements', methods=['POST'])
@login_required
def create_fluid_element():
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'element_name' not in data:
        return jsonify({'message': 'Element name is required'}), 400

    existing = InterstitialFluidElement.query.filter_by(element_name=data['element_name']).first()
    if existing:
        return jsonify({'message': 'Fluid element already exists'}), 409

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
        'element': new_element.to_dict()
    }), 201


@app.route('/admin/alcohol-consumption', methods=['POST'])
@login_required
def create_alcohol_consumption():
    if current_user.role != 'Admin':
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()

    if not data or 'consumption_level' not in data:
        return jsonify({'message': 'Consumption level is required'}), 400

    existing = AlcoholConsumption.query.filter_by(consumption_level=data['consumption_level']).first()
    if existing:
        return jsonify({'message': 'Alcohol consumption level already exists'}), 409

    new_level = AlcoholConsumption(consumption_level=data['consumption_level'])
    db.session.add(new_level)
    db.session.commit()

    return jsonify({
        'message': 'Alcohol consumption level created successfully',
        'level': new_level.to_dict()
    }), 201