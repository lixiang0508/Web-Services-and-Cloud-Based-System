from flask import Flask
import redis
import jwt
from jwt import exceptions
import functools
import datetime
import json
import functools
import datetime
import base64
import json
import hmac
import hashlib
from static.resources import user_urls

from flask import Flask, request
from flask_cors import CORS

from static.resources import dict_map, reverse_map, user_urls
from utils import build_result, is_valid_url, generate_unique_id
app1 = Flask(__name__)
r = redis.Redis(host='localhost', port=6379,password='123456')
CORS(app1)
headers = {
    'typ': 'jwt',
    'alg': 'HS256'
}

SALT = 'This is a secret key made by a geek from Vrije Universiteit Amsterdam'  # secret key



@app1.route('/users', methods=['POST'])
def register():
    if 'username' not in request.form or 'password' not in request.form:
        return build_result(400, "Register fails")  # parameters not enough
    username = request.form.get('username')  # get username from request form
    password = request.form.get('password')  # get password from request form
    res = implement_register(username, password)  # cite implementation
    if not res:
        return build_result(400, "username has already existed")
    username_password = eval(r.get('username_password'))
    print('register! current username_password is ', username_password)
    return build_result(200, "Register success")


@app1.route('/users/login', methods=['POST'])
def login():
    if 'username' not in request.form or 'password' not in request.form:
        return build_result(400, "Login fails")  # password does not match the username
    username = request.form.get('username')
    password = request.form.get('password')
    # todo 如果传进来是错的  200， 403
    res = implement_login(username, password)


    if "username" not in res:
        return build_result(403,"invalid username and password")
    return build_result(200, implement_login(username, password))


@app1.route('/users', methods=['PUT'])
def change_password():  # users change their password
    username_password = eval(r.get('username_password'))
    # todo 改密码之后
    if 'username' not in request.form or 'old-password' not in request.form or 'new-password' not in request.form:
        return build_result(403, "invalid request")
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    username = request.form.get('username')  # get username from request form
    old_password = request.form.get('old-password')
    new_password = request.form.get('new-password')
    if username not in username_password:
        return build_result(403, "Forbidden request, the user does not exist")

    if username_password[username] != old_password:
        return build_result(403, "Forbidden request, wrong password")
    username_password[username] = new_password

    print(username_password)
    r.set('username_password',username_password)
    return build_result(200, "change password success")

def base64url_encode(input: bytes):
    return base64.urlsafe_b64encode(input).decode('utf-8').replace('=', '')

def create_token(username, password):
    # construct payload
    '''payload = {
        'username': username,
        'password': password,  # customized ID
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # expiration date
    }
    result = jwt.encode(payload=payload, key=SALT, algorithm="HS256", headers=headers)  # generate a token using jwt
    return result'''


    segments = []
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    exp = int(exp.timestamp())
    api_sec = SALT
    payload = {
        'username': username,
        'password': password,  # customized ID
        'exp': exp  # expiration date
    }

    header = {"typ": "JWT", "alg": "HS256"}

    print(payload)

    json_header = json.dumps(header, separators=(",", ":")).encode('utf-8')
    json_payload = json.dumps(payload, separators=(",", ":")).encode('utf-8')

    segments.append(base64url_encode(json_header))
    segments.append(base64url_encode(json_payload))

    signing_input = ".".join(segments).encode()
    key = api_sec.encode()
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()

    segments.append(base64url_encode(signature))

    encoded_string = ".".join(segments)

    return encoded_string

def base64url_decode(input: str):
        padding = b'=' * (4 - (len(input) % 4))
        return base64.urlsafe_b64decode(input.encode() + padding)

def decode_token(token):
    """
    check jwt
    :param token: jwt token
    """

    '''try:
        payload = jwt.decode(token, SALT, algorithms=['HS256'])
        return payload
    except exceptions.ExpiredSignatureError:  # 'token is valid'
        return 'token is expired'
    except jwt.DecodeError:  # 'token authentication failed'
        return 'Token authentication failed'
    except jwt.InvalidTokenError:  # 'illegal token'
        return 'Invalid token' '''

    def base64url_decode(input: str):
        padding = b'=' * (4 - (len(input) % 4))
        return base64.urlsafe_b64decode(input.encode() + padding)

    try:
        # split the token into its three segments
        header_b64, payload_b64, signature_b64 = token.split('.')

        # decode the header and payload segments
        # header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))

        # extract the expiration timestamp from the payload
        exp_timestamp = payload['exp']

        # convert the expiration timestamp to a datetime object
        nowstamp = int(datetime.datetime.utcnow().timestamp())

        # check if the token has expired
        if exp_timestamp < nowstamp:
            return 'Token has expired'

        # calculate the signature for the token
        signing_input = (header_b64 + '.' + payload_b64).encode()
        key = SALT.encode()
        signature = hmac.new(key, signing_input, hashlib.sha256).digest()
        signature_b64_calculated = base64url_encode(signature)

        # compare the calculated signature to the signature in the token
        if signature_b64 != signature_b64_calculated:
            return 'Invalid token signature'

        # return the decoded payload data
        return payload

    except (ValueError, json.JSONDecodeError):
        return 'Failed to decode token'
    except KeyError:
        return 'Missing required field in token'
    except Exception as e:
        return str(e)


def implement_register(username, password):

    username_password = eval(r.get('username_password'))

    if username in username_password:
        return False
    else:
        username_password[username] = password
        r.set('username_password',str(username_password))
        return True


def implement_login(username, password):

    username_password = eval(r.get('username_password'))
    if username not in username_password.keys():
        return{}  # User not found
    if username_password[username] != password:
        return {}
    print(username, 'is loggin in ')
    token = create_token(username, password)
    return {"username": username, "token": token}


def request_authenticated(request):

    username_password = eval(r.get('username_password'))
    print('current username_password is', username_password)
    data = {}
    try:
        token = request.headers.get('access-token')  # get token from request header
        data = decode_token(token)
        pwd = data["password"]
        userName  =data["username"]
    except:
        return False
    #pwd = data["password"]
    print('the decoded data is', data)
    print('current username_password is',username_password)
    return "username" in data and username_password[userName] == pwd


def get_user_from_request(request):  # get username from a request
    token = request.headers.get('access-token')
    data = decode_token(token)
    return data["username"]


if __name__ == '__main__':
    app1.run(port=5002)