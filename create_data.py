#!/usr/bin/env python3
"""
Database seed script for the health monitoring application.
Creates admin and patient users, reference data, and sample records.
Run this script to initialize the database with sample data.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create the application
from app import create_app

app = create_app()


def create_users():
    """
    Create admin user and sample patients with specified passwords.
    """
    from models import db, Account

    # Create admin user
    admin = Account(
        first_name="Admin",
        last_name="User",
        email="admin@example.com",
        role="Admin"
    )
    admin.set_password("Admin123!")
    db.session.add(admin)

    # Create patient users
    patient1 = Account(
        first_name="John",
        last_name="Doe",
        email="patient1@example.com",
        role="Patient"
    )
    patient1.set_password("Patient1!")
    db.session.add(patient1)

    patient2 = Account(
        first_name="Jane",
        last_name="Smith",
        email="patient2@example.com",
        role="Patient"
    )
    patient2.set_password("Patient2!")
    db.session.add(patient2)

    db.session.commit()
    print("Users created: admin@example.com (Admin), patient1@example.com (Patient), patient2@example.com (Patient)")

    return admin, patient1, patient2


def create_reference_data():
    """
    Create all reference data: diet types, activity levels, conditions, etc.
    """
    from models import db, DietType, PhysicalActivityLevel, AlcoholConsumption, Conditions, InterstitialFluidElement, \
        Medications

    # Create diet types
    diet_types = [
        "Omnivore", "Vegetarian", "Vegan", "Pescatarian",
        "Paleo", "Keto", "Mediterranean", "Gluten-Free"
    ]
    for diet in diet_types:
        db.session.add(DietType(diet_type=diet))

    # Create physical activity levels
    activity_levels = [
        "Sedentary", "Lightly Active", "Moderately Active",
        "Very Active", "Extremely Active"
    ]
    for level in activity_levels:
        db.session.add(PhysicalActivityLevel(activity_level=level))

    # Create alcohol consumption levels
    consumption_levels = [
        "None", "Occasional", "Moderate", "Heavy"
    ]
    for level in consumption_levels:
        db.session.add(AlcoholConsumption(consumption_level=level))

    # Create health conditions
    conditions = [
        "Hypertension", "Diabetes Type 1", "Diabetes Type 2",
        "Asthma", "Arthritis", "Depression", "Anxiety",
        "Heart Disease", "Obesity", "Hypothyroidism"
    ]
    for condition in conditions:
        db.session.add(Conditions(condition_name=condition))

    # Create medications
    medications = [
        "Lisinopril", "Metformin", "Insulin", "Albuterol",
        "Ibuprofen", "Aspirin", "Alprazolam", "Atorvastatin",
        "Levothyroxine", "Vitamin D"
    ]
    for medication in medications:
        db.session.add(Medications(medication_name=medication))

    # Create interstitial fluid elements
    elements = [
        {
            "name": "Glucose",
            "lower_limit": 3.9,
            "upper_limit": 7.8,
            "lower_critical_limit": 3.0,
            "upper_critical_limit": 11.1
        },
        {
            "name": "Sodium",
            "lower_limit": 135.0,
            "upper_limit": 145.0,
            "lower_critical_limit": 120.0,
            "upper_critical_limit": 160.0
        },
        {
            "name": "Potassium",
            "lower_limit": 3.5,
            "upper_limit": 5.0,
            "lower_critical_limit": 2.5,
            "upper_critical_limit": 6.5
        },
        {
            "name": "Lactate",
            "lower_limit": 0.5,
            "upper_limit": 2.0,
            "lower_critical_limit": 0.2,
            "upper_critical_limit": 4.0
        }
    ]
    for element in elements:
        db.session.add(InterstitialFluidElement(
            element_name=element["name"],
            lower_limit=element["lower_limit"],
            upper_limit=element["upper_limit"],
            lower_critical_limit=element["lower_critical_limit"],
            upper_critical_limit=element["upper_critical_limit"]
        ))

    db.session.commit()
    print("Reference data created: diet types, activity levels, conditions, medications, fluid elements")


def create_patient_data(patients):
    """
    Create personal health data for patients.
    """
    from models import db, UserPersonalData, DietType, PhysicalActivityLevel, AlcoholConsumption, Conditions, \
        Medications

    # Get reference data IDs
    diet_mediterr = DietType.query.filter_by(diet_type="Mediterranean").first()
    diet_vegan = DietType.query.filter_by(diet_type="Vegan").first()

    activity_moderate = PhysicalActivityLevel.query.filter_by(activity_level="Moderately Active").first()
    activity_light = PhysicalActivityLevel.query.filter_by(activity_level="Lightly Active").first()

    alcohol_occasional = AlcoholConsumption.query.filter_by(consumption_level="Occasional").first()
    alcohol_none = AlcoholConsumption.query.filter_by(consumption_level="None").first()

    # Create patient data
    patient1_data = UserPersonalData(
        user_account_id=patients[0].account_id,
        age=45,
        gender="M",
        date_of_visit=datetime.now().date(),
        previous_visits=2,
        diet_type_id=diet_mediterr.diet_type_id,
        physical_activity_level_id=activity_moderate.pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_occasional.alcohol_consumption_id,
        blood_pressure="120/80",
        weight_kg=75,
        height_cm=178
    )
    patient1_data.calculate_bmi()
    db.session.add(patient1_data)

    patient2_data = UserPersonalData(
        user_account_id=patients[1].account_id,
        age=32,
        gender="F",
        date_of_visit=datetime.now().date(),
        previous_visits=1,
        diet_type_id=diet_vegan.diet_type_id,
        physical_activity_level_id=activity_light.pal_id,
        is_smoker=False,
        alcohol_consumption_id=alcohol_none.alcohol_consumption_id,
        blood_pressure="110/70",
        weight_kg=62,
        height_cm=165
    )
    patient2_data.calculate_bmi()
    db.session.add(patient2_data)

    db.session.commit()

    # Add conditions to patient 1
    patient1_conditions = ["Hypertension", "Anxiety"]
    for condition_name in patient1_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient1_data.conditions.append(condition)

    # Add conditions to patient 2
    patient2_conditions = ["Asthma", "Depression"]
    for condition_name in patient2_conditions:
        condition = Conditions.query.filter_by(condition_name=condition_name).first()
        if condition:
            patient2_data.conditions.append(condition)

    # Add medications to patient 1
    patient1_medications = ["Lisinopril", "Alprazolam"]
    for med_name in patient1_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient1_data.medications.append(medication)

    # Add medications to patient 2
    patient2_medications = ["Albuterol", "Vitamin D"]
    for med_name in patient2_medications:
        medication = Medications.query.filter_by(medication_name=med_name).first()
        if medication:
            patient2_data.medications.append(medication)

    db.session.commit()
    print("Patient health data created with conditions and medications")

    return patient1_data, patient2_data


def create_device_data(patient_data):
    """
    Create sample device measurement data for patients.
    """
    from models import db, InterstitialFluidElement, DeviceDataQuery

    # Get elements
    glucose = InterstitialFluidElement.query.filter_by(element_name="Glucose").first()
    sodium = InterstitialFluidElement.query.filter_by(element_name="Sodium").first()
    potassium = InterstitialFluidElement.query.filter_by(element_name="Potassium").first()
    lactate = InterstitialFluidElement.query.filter_by(element_name="Lactate").first()

    total_measurements = 0

    # Generate 30 days of data for each patient
    for patient in patient_data:
        for day in range(30, 0, -1):
            date = datetime.now().date() - timedelta(days=day)

            # Glucose measurements (3 times a day)
            for hour in [8, 13, 19]:
                glucose_value = round(random.uniform(4.0, 8.5) * 10)  # Normal range with some variation

                db.session.add(DeviceDataQuery(
                    date_logged=date,
                    time_stamp=datetime.strptime(f"{hour}:00", "%H:%M").time(),
                    recorded_value=glucose_value,
                    element_id=glucose.element_id,
                    user_id=patient.patient_id
                ))
                total_measurements += 1

            # Other measurements less frequently
            if day % 3 == 0:  # Every 3 days
                sodium_value = round(random.uniform(135, 145))
                db.session.add(DeviceDataQuery(
                    date_logged=date,
                    time_stamp=datetime.strptime("10:30", "%H:%M").time(),
                    recorded_value=sodium_value,
                    element_id=sodium.element_id,
                    user_id=patient.patient_id
                ))
                total_measurements += 1

            if day % 2 == 0:  # Every 2 days
                potassium_value = round(random.uniform(3.5, 5.0) * 10)
                db.session.add(DeviceDataQuery(
                    date_logged=date,
                    time_stamp=datetime.strptime("11:15", "%H:%M").time(),
                    recorded_value=potassium_value,
                    element_id=potassium.element_id,
                    user_id=patient.patient_id
                ))
                total_measurements += 1

            if day % 7 == 0:  # Once a week
                lactate_value = round(random.uniform(0.5, 2.0) * 10)
                db.session.add(DeviceDataQuery(
                    date_logged=date,
                    time_stamp=datetime.strptime("14:45", "%H:%M").time(),
                    recorded_value=lactate_value,
                    element_id=lactate.element_id,
                    user_id=patient.patient_id
                ))
                total_measurements += 1

    db.session.commit()
    print(f"Created {total_measurements} device measurements for patients")


if __name__ == "__main__":
    with app.app_context():
        print("Starting database seeding...")

        # First, confirm dropping all existing data
        confirm = input("WARNING: This will DELETE ALL EXISTING DATA. Continue? (yes/no): ")
        if confirm.lower() != "yes":
            print("Database seeding cancelled.")
            sys.exit(0)

        # Drop all tables and recreate them
        from models import db

        print("Dropping all existing tables...")
        db.drop_all()
        print("Creating new tables...")
        db.create_all()
        print("Database reset completed")

        # Create users
        print("\nCreating users...")
        admin, patient1, patient2 = create_users()

        # Create reference data
        print("\nCreating reference data...")
        create_reference_data()

        # Create patient data
        print("\nCreating patient health data...")
        patient1_data, patient2_data = create_patient_data([patient1, patient2])

        # Create device measurements
        print("\nCreating device measurements...")
        create_device_data([patient1_data, patient2_data])

        print("\nDatabase seeding completed!")
        print("\nLogin credentials:")
        print("Admin: admin@example.com / Admin123!")
        print("Patient 1: patient1@example.com / Patient1!")
        print("Patient 2: patient2@example.com / Patient2!")