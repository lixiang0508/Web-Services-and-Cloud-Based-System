from flask import g, request, Flask, current_app, jsonify
import jwt
from jwt import exceptions
import functools
import datetime
from static.resources import user_urls,username_password
headers = {
    'typ': 'jwt',
    'alg': 'HS256'
}
SALT = 'This is a secret key made by a geek from Vrije Universiteit Amsterdam' #secret key


def create_token(username, password):
    # construct payload
    payload = {
        'username': username,
        'password': password,  # customized ID
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # expiration date
    }
    result = jwt.encode(payload=payload, key=SALT, algorithm="HS256", headers=headers) #generate a token using jwt
    return result


def decode_token(token):
    """
    check jwt
    :param token: jwt token
    """

    try:
        payload = jwt.decode(token, SALT, algorithms=['HS256'])
        return payload
    except exceptions.ExpiredSignatureError:  # 'token is valid'
        return 'token is expired'
    except jwt.DecodeError:  # 'token authentication failed'
        return 'Token authentication failed'
    except jwt.InvalidTokenError:  # 'illegal token'
        return 'Invalid token'
def implement_register(username, password):

    if username in username_password:
        return False
    else:
        username_password[username]=password
        return True
def implement_login(username,password):
    if username_password[username]!=password:
        return 403,"false password"
    token=create_token(username,password)
    return {"username":username,"token":token}

def request_authenticated(request):
    data={}
    try:
        token =request.headers.get('access-token') #get token from request header
        data= decode_token(token)
    except:
        return False
    return "username" in data

def get_user_from_request(request):# get username from a request
    token = request.headers.get('access-token')
    data = decode_token(token)
    return data["username"]
