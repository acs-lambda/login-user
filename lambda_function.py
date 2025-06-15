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
from utils import invoke, parse_event


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
    Uses utility functions for consistent event parsing and CORS handling.
    """
    cors_headers = get_cors_headers(event)

    # Handle CORS preflight
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": cors_headers, "body": ""}

    # Parse request using utility function
    try:
        payload = parse_event(event)
        email = payload["email"]
        provider = payload["provider"]
        password = payload.get("password", "")  # required only for form
        name = payload.get("name", "")      # required only for google
    except (KeyError, json.JSONDecodeError) as e:
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

    # Route to provider-specific handler
    if provider == "form":
        return form_login(email, password, cors_headers)
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
