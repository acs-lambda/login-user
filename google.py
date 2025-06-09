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
import time
from datetime import datetime, timezone

# list of Cognito/Dynamo attributes you want to return
RETURN_FIELDS = ["name", "id"]


# Environment, Cognito and Lambda clients
USER_POOL_ID        = os.environ["COGNITO_USER_POOL_ID"]
AWS_REGION          = os.environ.get("AWS_REGION", "us-east-2")
SIGNUP_FUNCTION     = "ProcessNewUserSupabase"
cognito   = boto3.client("cognito-idp", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)
SESSIONS_TABLE      = os.environ.get("SESSIONS_TABLE", "Sessions")

# DynamoDB table for session storage
dynamodb            = boto3.resource("dynamodb", region_name=AWS_REGION)
sessions_table      = dynamodb.Table(SESSIONS_TABLE)



def google_login(email: str, name: str, cors_headers: dict) -> dict:
    """
    For Google provider:
    1. Check if user exists in Cognito (admin_get_user).
    2. If missing, invoke Signup Lambda (auto-create).
    3. Issue session_id cookie.
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
        # 2) Auto-signup via Invoke, now passing a generated id
        user_id = str(uuid.uuid4())
        payload = {
            "body": json.dumps({
                "id":       user_id,
                "email":    email,
                "name":     name,
                "provider": "google"
            })
        }
        resp = lambda_client.invoke(
            FunctionName   = SIGNUP_FUNCTION,
            InvocationType = "RequestResponse",
            Payload        = json.dumps(payload).encode()
        )
        data = json.loads(resp["Payload"].read().decode())
        print("Signup Lambda response:", data)
        if data.get("statusCode") not in (200, 201):
            return {
                "statusCode": data.get("statusCode", 500),
                "headers": cors_headers,
                "body": data.get("body", json.dumps({"message": "Signup failed"}))
            }
        authType = "new"

    # 3) Issue session cookie & prepare response body
    # — generate & persist session —
    session_id = str(uuid.uuid4())
    now        = datetime.now(timezone.utc).isoformat()
    expires    = int(time.time()) + 30*24*3600
    sessions_table.put_item(Item={
      "session_id": session_id,
      "user_id":    user_id,
      "created_at": now,
      "expiration": expires
    })

    cookie = f"session_id={session_id}; HttpOnly; Secure; SameSite=None; Max-Age=2592000"

    headers = {
        **cors_headers,
        "Set-Cookie": cookie,
        "Content-Type": "application/json"
    }
    # pick up configured RETURN_FIELDS
    info = {}
    for f in RETURN_FIELDS:
        if f == "id":
            info[f] = user_id
        elif f == "name":
            info[f] = name
    # if in future you want to fetch from Cognito instead, you can replicate the admin_get_user logic from form.py

    body = {"message": "Login successful (google)", **info, "authType": authType}
    response = {"statusCode": 200, "headers": headers, "body": json.dumps(body)}
    print("Google-based Response: ", response)
    return response
