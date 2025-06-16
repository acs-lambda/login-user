import json
import boto3
from typing import Dict, Any, Union, Optional
from botocore.exceptions import ClientError
import logging
from config import logger, AWS_REGION

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
lambda_client = boto3.client('lambda', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb')
sessions_table = dynamodb.Table('Sessions')

class AuthorizationError(Exception):
    """Custom exception for authorization failures"""
    pass

class LambdaError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(f"[{status_code}] {message}")

def create_response(status_code, body, headers=None):
    if headers is None:
        headers = {}
    
    base_headers = {
        "Content-Type": "application/json", 
        "Access-Control-Allow-Origin": "*"
    }
    
    # Add any additional headers
    base_headers.update(headers)
    
    return {
        "statusCode": status_code,
        "headers": base_headers,
        "body": json.dumps(body),
    }

def invoke_lambda(function_name, payload, invocation_type="RequestResponse"):
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType=invocation_type,
            Payload=json.dumps(payload),
        )
        response_payload = response["Payload"].read().decode("utf-8")
        parsed_payload = json.loads(response_payload)
        
        if "FunctionError" in response:
            raise LambdaError(500, f"Error in {function_name}: {response_payload}")
        
        if isinstance(parsed_payload, dict) and 'statusCode' in parsed_payload and parsed_payload['statusCode'] != 200:
            body = parsed_payload.get('body')
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    pass
            
            error_message = body.get('error', 'Invocation failed') if isinstance(body, dict) else 'Invocation failed'
            raise LambdaError(parsed_payload['statusCode'], error_message)

        return parsed_payload
    except ClientError as e:
        raise LambdaError(500, f"Failed to invoke {function_name}: {e.response['Error']['Message']}")
    except json.JSONDecodeError:
        raise LambdaError(500, "Failed to parse response from invoked Lambda.")
    except LambdaError:
        raise
    except Exception as e:
        raise LambdaError(500, f"An unexpected error occurred invoking {function_name}: {e}")

def parse_event(event):
    response = invoke_lambda('ParseEvent', event)
    return response.get('body')

def authorize(user_id: str, session_id: str) -> None:
    """
    Authorize a user by invoking the authorize Lambda function
    
    Args:
        user_id (str): The user ID to validate
        session_id (str): The session ID to validate
        
    Returns:
        None
        
    Raises:
        AuthorizationError: If authorization fails
    """
    try:
        # Invoke the authorize Lambda function
        response = invoke_lambda('Authorize', {
            'user_id': user_id,
            'session_id': session_id
        })
        
        # Check if authorization was successful
        if response['statusCode'] != 200 or not response['body'].get('authorized', False):
            raise AuthorizationError(response['body'].get('message', 'ACS: Unauthorized'))
            
    except ClientError as e:
        logger.error(f"Lambda invocation error during authorization: {str(e)}")
        raise AuthorizationError("ACS: Unauthorized")
    except Exception as e:
        logger.error(f"Unexpected error during authorization: {str(e)}")
        raise AuthorizationError("ACS: Unauthorized") 