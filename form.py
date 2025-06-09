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

# Environment & Cognito client
USER_POOL_ID   = os.environ["COGNITO_USER_POOL_ID"]
CLIENT_ID      = os.environ["COGNITO_CLIENT_ID"]
CLIENT_SECRET  = os.environ["COGNITO_CLIENT_SECRET"]
AWS_REGION     = os.environ.get("AWS_REGION", "us-east-2")
cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

# list of Cognito attributes you want to return
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


def form_login(email: str, password: str, cors_headers: dict) -> dict:
    """
    Authenticate user via Cognito USER_PASSWORD_AUTH.
    Return HTTP response dict with cookies and JSON body.
    """
    user_id = None
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

        if (not user_id) or (not user_id.strip()):
            return {
                "statusCode": 401,
                "headers": cors_headers,
                "body": json.dumps({"message": "Incorrect username or password (user_id not found)"})
            }

        # 1) Authenticate using USER_PASSWORD_AUTH with that user_id
        resp = cognito.initiate_auth(
            ClientId       = CLIENT_ID,
            AuthFlow       = "USER_PASSWORD_AUTH",
            AuthParameters = {
                "USERNAME":    user_id,
                "PASSWORD":    password,
                "SECRET_HASH": get_secret_hash(user_id),
            }
        )
        auth = resp["AuthenticationResult"]

        # fetch the requested RETURN_FIELDS: 
        #   - "id" from Cognito Username 
        #   - other fields from UserAttributes
        info = {}
        try:
            print("Fetching user attributes..." + user_id)
            user = cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=user_id)
            attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}
            for f in RETURN_FIELDS:
                if f == "id":
                    info[f] = user.get("Username")
                else:
                    info[f] = attrs.get(f)
        except Exception as err:
            print("Error fetching user attributes:", err)
            # if the lookup fails, info will remain empty

        # Build cookies
        cookies = [
            f"id_token={auth['IdToken']}; HttpOnly; Secure; SameSite=None; Max-Age=3600",
            f"access_token={auth['AccessToken']}; HttpOnly; Secure; SameSite=None; Max-Age=3600",
            f"refresh_token={auth['RefreshToken']}; HttpOnly; Secure; SameSite=None; Max-Age=1209600",
        ]
        headers = {
            **cors_headers,
            "Set-Cookie": ",".join(cookies),
            "Content-Type": "application/json"
        }
        body = {"message": "Login successful (form)", **info}
        response = {"statusCode": 200, "headers": headers, "body": json.dumps(body)}
        print("Form login response:", response)
        return response

    except cognito.exceptions.NotAuthorizedException:
        return {
            "statusCode": 401,
            "headers": cors_headers,
            "body": json.dumps({"message": "Incorrect username or password"})
        }
    except Exception as e:
        print("Form login error:", e)
        return {
            "statusCode": 500,
            "headers": cors_headers,
            "body": json.dumps({"message": "Internal server error"})
        }

