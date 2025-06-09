# @file handler.py
# @module handler
# @description
# Main AWS Lambda entry point for user login in ACS (Python 3.13).
# Delegates to provider-specific flows in form.py and google.py.
import os
import json
import boto3
import uuid  # added for session cookie generation
from form import form_login
from google import google_login
import time
from datetime import datetime, timezone


# Environment & AWS clients
AWS_REGION    = os.environ.get("AWS_REGION", "us-east-2")
CORS_FUNCTION = os.environ.get("CORS_FUNCTION_NAME", "Allow-Cors")
lambda_client = boto3.client("lambda", region_name=AWS_REGION)


# DynamoDB table for session storage
SESSIONS_TABLE = os.environ.get("SESSIONS_TABLE", "Sessions")
dynamodb       = boto3.resource("dynamodb", region_name=AWS_REGION)
sessions_table = dynamodb.Table(SESSIONS_TABLE)


VALID_PROVIDERS = ("form", "google")


def get_cors_headers(event: dict) -> dict:
    """
    Invoke Allow-Cors Lambda to get CORS headers. Fallback to defaults.
    """
    default = {
        "Access-Control-Allow-Origin":      "*",
        "Access-Control-Allow-Methods":     "OPTIONS, POST",
        "Access-Control-Allow-Headers":     "Content-Type",
        "Access-Control-Allow-Credentials": "true",
    }
    try:
        resp = lambda_client.invoke(
            FunctionName   = CORS_FUNCTION,
            InvocationType = "RequestResponse",
            Payload        = json.dumps(event).encode()
        )
        data = json.loads(resp["Payload"].read().decode())
        return data.get("headers", default)
    except Exception:
        return default


def lambda_handler(event, context):
    """
    Entry point: parse request, route to form or google flow, return HTTP response.
    """
    cors_headers = get_cors_headers(event)

    # Handle CORS preflight
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": cors_headers, "body": ""}

    # Parse JSON body
    try:
        payload  = json.loads(event.get("body") or "{}")
        email    = payload["email"]
        provider = payload["provider"]
        password = payload.get("password")  # required only for form
        name     = payload.get("name")      # required only for google
    except (json.JSONDecodeError, KeyError):
        return {
            "statusCode": 400,
            "headers": cors_headers,
            "body": json.dumps({"message": "Invalid request: email and provider required"})
        }

    # Validate provider
    if provider not in VALID_PROVIDERS:
        return {
            "statusCode": 400,
            "headers": cors_headers,
            "body": json.dumps({"message": f"Provider must be one of {VALID_PROVIDERS}"})
        }

    # Route to provider-specific handler, with session cookie for form
    if provider == "form":
        # 1) Authenticate with Cognito and get your id/access/refresh tokens
        response = form_login(email, password, cors_headers)

        # 2) generate & persist our own session
        session_id = str(uuid.uuid4())
        now        = datetime.now(timezone.utc).isoformat()
        expires    = int(time.time()) + 30*24*3600
        sessions_table.put_item(Item={
          "session_id": session_id,
          "user_id":    email,
          "created_at": now,
          "expiration": expires
        })

        # 3) append our session cookie to whatever Cognito set
        session_cookie = f"session_id={session_id}; HttpOnly; Secure; SameSite=None; Max-Age=2592000"
        headers        = response["headers"]
        existing       = headers.get("Set-Cookie", "")
        headers["Set-Cookie"] = ",".join(filter(None, [existing, session_cookie]))
        response["headers"]   = headers
        return response

    else:  # google
        if not name:
            return {
                "statusCode": 400,
                "headers": cors_headers,
                "body": json.dumps({"message": "Name required for google signup/login"})
            }
        try:
            return google_login(email, name, cors_headers)
        except Exception as e:
            return {
                "statusCode": 500,
                "headers": cors_headers,
                "body": json.dumps({"message": str(e)})
            }
