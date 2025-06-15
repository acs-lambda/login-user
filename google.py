"""
@file google.py
@module google
@description
Google-based signup/login flow for AWS Lambda handler.
Checks for existing Cognito user, auto-signs up if missing,
and issues a simple session cookie.
"""
import os
import json
import uuid
import boto3
from utils import invoke, AuthorizationError

# List of Cognito/Dynamo attributes you want to return
RETURN_FIELDS = ["name", "id"]

# Environment variables
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
SIGNUP_FUNCTION = "ProcessNewUserSupabase"
CREATE_SESSION_FUNCTION = os.environ.get("CREATE_SESSION_FUNCTION", "CreateNewSession")

# Initialize AWS clients
cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def create_session(user_id: str) -> tuple[str, dict]:
    """
    Create a new session for the user using CreateNewSession Lambda.
    Returns session ID and cookie.
    """
    try:
        payload = {
            "body": json.dumps({
                "uid": user_id
            })
        }
        
        response = invoke(CREATE_SESSION_FUNCTION, payload)
        response_body = json.loads(response.get("body", "{}"))
        
        if response.get("statusCode") != 200:
            raise AuthorizationError(f"Failed to create session: {response_body.get('message', 'Unknown error')}")
            
        session_id = response_body.get("sessionId")
        if not session_id:
            raise AuthorizationError("No session ID returned from CreateNewSession")
            
        cookie = f"session_id={session_id}; HttpOnly; Secure; SameSite=None; Max-Age=2592000"
        return session_id, cookie
        
    except Exception as e:
        raise AuthorizationError(f"Failed to create session: {str(e)}")

def google_login(email: str, name: str, cors_headers: dict) -> dict:
    """
    For Google provider:
    1. Check if user exists in Cognito (admin_get_user).
    2. If missing, invoke Signup Lambda (auto-create).
    3. Issue session_id cookie using CreateNewSession Lambda.
    """
    # 1) Find user by email
    user_id = None
    resp = cognito.list_users(
        UserPoolId=USER_POOL_ID,
        Filter=f'email = "{email}"',
        Limit=1
    )
    if resp.get("Users"):
        print("Found existing user:", resp["Users"])
        user_id = resp["Users"][0]["Username"]
        authType = "existing"
    else:
        # 2) Auto-signup via utility invoke function
        user_id = str(uuid.uuid4())
        payload = {
            "body": json.dumps({
                "id": user_id,
                "email": email,
                "name": name,
                "provider": "google"
            })
        }
        try:
            data = invoke(SIGNUP_FUNCTION, payload)
            if data.get("statusCode") not in (200, 201):
                return {
                    "statusCode": data.get("statusCode", 500),
                    "headers": cors_headers,
                    "body": data.get("body", json.dumps({"message": "Signup failed"}))
                }
        except Exception as e:
            return {
                "statusCode": 500,
                "headers": cors_headers,
                "body": json.dumps({"message": f"Signup failed: {str(e)}"})
            }
        authType = "new"

    # 3) Create session using CreateNewSession Lambda
    try:
        session_id, cookie = create_session(user_id)
    except AuthorizationError as e:
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({"message": str(e)})
        }

    headers = {
        **cors_headers,
        "Set-Cookie": cookie,
        "Content-Type": "application/json"
    }

    # Pick up configured RETURN_FIELDS
    info = {
        "id": user_id,
        "name": name
    }

    body = {"message": "Login successful (google)", **info, "authType": authType}
    response = {"statusCode": 200, "headers": headers, "body": json.dumps(body)}
    print("Google-based Response: ", response)
    return response
