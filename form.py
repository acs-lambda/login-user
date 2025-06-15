"""
@file form.py
@module form
@description
Form-based authentication flow for AWS Lambda login handler.
Uses Cognito USER_PASSWORD_AUTH to validate credentials,
and returns HTTP response with Cognito tokens as cookies.
"""
import os
import json
import hmac
import hashlib
import base64
import boto3
from utils import invoke, AuthorizationError

# Environment & Cognito client
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
CLIENT_SECRET = os.environ["COGNITO_CLIENT_SECRET"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
CREATE_SESSION_FUNCTION = os.environ.get("CREATE_SESSION_FUNCTION", "CreateNewSession")

# Initialize AWS clients
cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

# List of Cognito attributes to return
RETURN_FIELDS = ["name", "id"]

def get_secret_hash(username: str) -> str:
    """
    Compute Cognito SECRET_HASH for user/password auth.
    """
    msg = username + CLIENT_ID
    dig = hmac.new(
        CLIENT_SECRET.encode(),
        msg.encode(),
        hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

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

def form_login(email: str, password: str, cors_headers: dict) -> dict:
    """
    Authenticate user via Cognito USER_PASSWORD_AUTH.
    Return HTTP response dict with cookies and JSON body.
    Uses CreateNewSession Lambda for session management.
    """
    # Missing password check
    if not password:
        return {
            "statusCode": 400,
            "headers": cors_headers,
            "body": json.dumps({"message": "Password required for form login"})
        }
        
    try:
        # 0) Lookup user by email to get their Cognito Username (id)
        list_resp = cognito.list_users(
            UserPoolId=USER_POOL_ID,
            Filter=f'email = "{email}"',
            Limit=1
        )
        if not list_resp.get("Users"):
            return {
                "statusCode": 401,
                "headers": cors_headers,
                "body": json.dumps({"message": "Incorrect username or password"})
            }
        user_id = list_resp["Users"][0]["Username"]

        if not user_id or not user_id.strip():
            return {
                "statusCode": 401,
                "headers": cors_headers,
                "body": json.dumps({"message": "Incorrect username or password (user_id not found)"})
            }

        # 1) Authenticate using USER_PASSWORD_AUTH
        resp = cognito.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": user_id,
                "PASSWORD": password,
                "SECRET_HASH": get_secret_hash(user_id),
            }
        )
        auth = resp["AuthenticationResult"]

        # 2) Create session using CreateNewSession Lambda
        session_id, session_cookie = create_session(user_id)

        # 3) Fetch user attributes
        info = {}
        try:
            print("Fetching user attributes..." + user_id)
            user = cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=user_id)
            attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}
            info = {
                "id": user.get("Username"),
                "name": attrs.get("name")
            }
        except Exception as err:
            print("Error fetching user attributes:", err)

        # 4) Build response with all cookies
        cookies = [
            f"id_token={auth['IdToken']}; HttpOnly; Secure; SameSite=None; Max-Age=3600",
            f"access_token={auth['AccessToken']}; HttpOnly; Secure; SameSite=None; Max-Age=3600",
            f"refresh_token={auth['RefreshToken']}; HttpOnly; Secure; SameSite=None; Max-Age=1209600",
            session_cookie
        ]
        
        headers = {
            **cors_headers,
            "Set-Cookie": ",".join(cookies),
            "Content-Type": "application/json"
        }
        
        body = {"message": "Login successful (form)", **info, "authtype": "existing"}
        response = {"statusCode": 200, "headers": headers, "body": json.dumps(body)}
        print("Form login response:", response)
        return response

    except cognito.exceptions.NotAuthorizedException:
        return {
            "statusCode": 401,
            "headers": cors_headers,
            "body": json.dumps({"message": "Incorrect username or password"})
        }
    except AuthorizationError as e:
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({"message": str(e)})
        }
    except Exception as e:
        print("Form login error:", e)
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({"message": "Internal server error"})
        }

