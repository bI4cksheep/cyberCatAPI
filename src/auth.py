import datetime
import jwt
from flask import jsonify

jwtSecret = "21fa8f9ea6e580b4cfbb440d3cafe1c19f607086f44854de842d396efcf3fc69"

def encode_auth_token(username, role):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=1),
            "iat": datetime.datetime.utcnow(),
            "sub": username,
            "role": role
        }
        return jwt.encode(
            payload,
            jwtSecret,
            algorithm="HS256"
        )
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        # safe verification:
        payload = jwt.decode(auth_token, jwtSecret, algorithms=["HS256"])

        # unsafe verification, ist vulnerable as the signature is not verified and anybody can include anything as the role
        # payload = jwt.decode(auth_token, options={"verify_signature": False})
        return payload["sub"], payload["role"]
    except jwt.ExpiredSignatureError:
        return {
                "message": "Signature expired. Please log in again.",
                "error": "authError",
                "data": None
        }, 401
    except jwt.InvalidTokenError:
        return {
                "message": "Invalid token. Please log in again.",
                "error": "authError",
                "data": None
        }, 401
