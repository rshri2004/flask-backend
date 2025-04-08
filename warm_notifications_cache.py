"""
Cache Warmer Script for Health Notifications

This script warms up the notification cache for all users who have both profile data
and device measurements. It works directly within the application context to avoid
having to handle user credentials.

Usage:
  python warm_notification_cache.py [--force] [--verbose] [--env {dev|prod}]

Options:
  --force    Force refresh all caches even if they're still valid
  --verbose  Display detailed information during execution
  --env      Specify environment to use (dev or prod), overrides ENV environment variable

Environment Variables:
  ENV              The environment to use (dev or prod), default is 'dev'
  FLASK_APP        Set to the Flask application entry point
  FLASK_ENV        Flask environment (development or production)
"""

import os
import sys
import time
import argparse
import logging
from datetime import datetime, timedelta
import json
import traceback
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up logging before anything else
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cache_warmer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("cache_warmer")

# Import Flask application and models
from app import create_app, app
from models import db, Account, UserPersonalData, DeviceDataQuery, NotificationCache
from flask import appcontext_pushed

# Import route implementation functions directly from routes.py
# This is an internal method to directly call the function that generates notifications
from routes import get_health_notifications


def setup_argparse():
    """Set up command line arguments"""
    parser = argparse.ArgumentParser(description='Warm up health notification caches')
    parser.add_argument('--force', action='store_true', help='Force refresh all caches')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output')
    parser.add_argument('--env', choices=['dev', 'prod'], default=None,
                        help='Environment to use (dev or prod), overrides ENV environment variable')
    return parser.parse_args()


def get_environment_config(args):
    """
    Determine the environment configuration based on settings
    Priority: command-line argument > ENV environment variable > default

    Args:
        args: The parsed command-line arguments

    Returns:
        dict: Environment configuration
    """
    # First check if env was specified in command line
    if args.env:
        env = args.env
    else:
        # Otherwise check environment variable
        env = os.environ.get("ENV", "dev")

    # Return environment-specific configuration
    if env.lower() == "prod":
        return {
            "environment": "prod",
            "debug": False
        }
    else:
        return {
            "environment": "dev",
            "debug": True
        }


def has_profile_and_device_data(user_id):
    """
    Check if a user has both profile data and device measurements

    Args:
        user_id: The account ID of the user

    Returns:
        bool: True if user has both profile and device data, False otherwise
    """
    # Check if user has profile data
    profile = UserPersonalData.query.filter_by(user_account_id=user_id).first()
    if not profile:
        return False

    # Check if user has any device measurements
    measurements = DeviceDataQuery.query.filter_by(user_id=profile.patient_id).first()
    return measurements is not None


def has_valid_cache(user_id):
    """
    Check if a user has a valid notification cache

    Args:
        user_id: The account ID of the user

    Returns:
        bool: True if user has a valid cache, False otherwise
    """
    cache_entry = NotificationCache.query.filter_by(user_id=user_id).first()

    if not cache_entry:
        return False

    return cache_entry.is_valid()


def warm_cache_for_user(user, force_refresh=False):
    """
    Warm up the cache for a specific user by directly calling the health notifications function

    Args:
        user: The user account object
        force_refresh: Whether to force a cache refresh

    Returns:
        dict: Result information including success status and error if any
    """
    user_id = user.account_id

    try:
        # Create a mock request with the user's identity
        # This is a simplified approach - in the real script you'd use Flask's test client
        # or set up the proper request context

        start_time = time.time()

        # Direct function call approach
        # This directly calls the function that generates and caches notifications,
        # avoiding the API layer entirely
        from routes import get_current_user
        from flask import Request, request, current_app
        from werkzeug.test import EnvironBuilder
        from flask_login import login_user

        # Create request context with the user's identity
        with app.test_request_context():
            # Login the user
            login_user(user)

            # Call the health notifications function with the proper request
            # Simulating a GET request with the refresh parameter
            if force_refresh:
                with app.test_request_context('/?refresh=true'):
                    login_user(user)
                    result = get_health_notifications(user_id)
            else:
                with app.test_request_context('/'):
                    login_user(user)
                    result = get_health_notifications(user_id)

        elapsed_time = time.time() - start_time

        # Parse the result
        response, status_code = result

        if status_code == 200:
            response_data = json.loads(response.data)
            cached = response_data.get("cached", False)
            cache_status = "retrieved" if cached else "generated"

            return {
                "success": True,
                "cache_status": cache_status,
                "elapsed_time": round(elapsed_time, 2),
                "notification_count": len(response_data.get("notifications", [])),
                "error": None
            }
        else:
            return {
                "success": False,
                "cache_status": "failed",
                "elapsed_time": round(elapsed_time, 2),
                "notification_count": 0,
                "error": f"Function returned status code {status_code}: {response.data}"
            }

    except Exception as e:
        logger.error(f"Exception when warming cache for user {user_id}: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "success": False,
            "cache_status": "failed",
            "elapsed_time": 0,
            "notification_count": 0,
            "error": str(e)
        }


def main():
    """Main execution function"""
    args = setup_argparse()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Get the environment configuration
    env_config = get_environment_config(args)
    environment = env_config["environment"]

    logger.info(f"Starting cache warmer in {environment} environment")

    # Use the application context
    with app.app_context():
        start_time = time.time()

        # Get all users
        users = Account.query.all()
        logger.info(f"Found {len(users)} total users")

        eligible_users = []
        skipped_users = []

        # Check which users are eligible for cache warming (have profile and device data)
        for user in users:
            if has_profile_and_device_data(user.account_id):
                # If not forcing refresh, check if they already have a valid cache
                if not args.force and has_valid_cache(user.account_id):
                    skipped_users.append({
                        "account_id": user.account_id,
                        "name": f"{user.first_name} {user.last_name}",
                        "reason": "has valid cache"
                    })
                    continue

                eligible_users.append(user)
            else:
                skipped_users.append({
                    "account_id": user.account_id,
                    "name": f"{user.first_name} {user.last_name}",
                    "reason": "missing profile or device data"
                })

        logger.info(f"Found {len(eligible_users)} eligible users for cache warming")
        if args.verbose:
            for skipped in skipped_users:
                logger.debug(f"Skipping user {skipped['account_id']} ({skipped['name']}): {skipped['reason']}")

        # Warm cache for eligible users
        success_count = 0
        failure_count = 0

        for user in eligible_users:
            logger.info(f"Warming cache for user {user.account_id} ({user.first_name} {user.last_name})")

            result = warm_cache_for_user(
                user=user,
                force_refresh=args.force
            )

            if result["success"]:
                logger.info(
                    f"Successfully {result['cache_status']} cache for user {user.account_id} "
                    f"with {result['notification_count']} notifications in {result['elapsed_time']}s"
                )
                success_count += 1
            else:
                logger.error(f"Failed to warm cache for user {user.account_id}: {result['error']}")
                failure_count += 1

            # Add small delay to prevent resource contention
            time.sleep(0.5)

        # Calculate and log summary statistics
        total_time = time.time() - start_time
        logger.info("Cache warming completed")
        logger.info(f"Environment: {environment}")
        logger.info(f"Total time: {round(total_time, 2)}s")
        logger.info(f"Users processed: {len(eligible_users)}")
        logger.info(f"Successful: {success_count}")
        logger.info(f"Failed: {failure_count}")
        logger.info(f"Skipped: {len(skipped_users)}")


if __name__ == "__main__":
    main()