import redis
from flask import Flask, request
from flask_cors import CORS
import datetime
import base64
import json
import hmac
import hashlib
# from authentication.authentication import request_authenticated,get_user_from_request

from utils import build_result, is_valid_url, generate_unique_id

app = Flask(__name__)
CORS(app)

import logging
import sys

# 配置日志输出的格式和级别
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

# 连接到 Redis
r = redis.Redis(host='redis', port=6379)
# Connect to Redis
# r = redis.Redis(host='redis', port=6379)

# Set variable value
username_password = {'user1': 'pwd1'}
r.set('username_password', str(username_password))
# Initialize a dict_map hash object and a reverse_map hash object
# r.delete('dict_map')
# r.delete('reverse_map')
# r.delete('user_urls')
# r.hset('dict_map','keys','values')
# r.hset('reverse_map','keys','values')
# r.hset('user_urls','keys','values')

headers = {
    'typ': 'jwt',
    'alg': 'HS256'
}

SALT = 'This is a secret key made by a geek from Vrije Universiteit Amsterdam'  # secret key


def get_user_from_request(request):  # get username from a request
    token = request.headers.get('access-token')
    data = decode_token(token)
    return data["username"]


def generate_id(url):  # generate an unique id for each url

    return generate_unique_id(url)


def base64url_encode(input: bytes):
    return base64.urlsafe_b64encode(input).decode('utf-8').replace('=', '')


def decode_token(token):
    """
    check jwt
    :param token: jwt token
    """

    def base64_url_decode(input: str):
        # padding binary = to make input length be a multiple of 4
        padding = b'=' * (4 - (len(input) % 4))
        return base64.urlsafe_b64decode(input.encode() + padding)

    try:
        # split the token into its three segments(like how it is created)
        header_b64, payload_b64, signature_b64 = token.split('.')

        # decode the payload segment
        payload = json.loads(base64_url_decode(payload_b64))

        # extract the expiration timestamp
        exp_timestamp = payload['exp']
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

        return payload

    except (ValueError, json.JSONDecodeError):
        return 'Failed to decode token'
    except KeyError:
        return 'Missing required field in token'
    except Exception as e:
        return str(e)


def request_authenticated(request):
    username_password = eval(r.get('username_password'))
    logging.info('current username password is ')
    logging.info(username_password)
    print('current username_password is', username_password)
    data = {}
    try:
        token = request.headers.get('access-token')  # get token from request header
        data = decode_token(token)
        pwd = data["password"]
        userName = data["username"]
    except:
        logging.info('Something wrong with the request authentication')
        return False
    # pwd = data["password"]
    logging.info('the decoded data is')
    logging.info(data)
    # print('current username_password is', username_password)
    return "username" in data and username_password[userName] == pwd


@app.route('/<id>', methods=['GET'])
def get_id(id):
    # if id not in r.hkeys('dict_map'): # this id does not exist
    if id.encode() not in r.hkeys('dict_map'):
        print("not found this id")
        return build_result(404, "This id does not exist")
    return build_result(301, r.hget('dict_map', str(id)).decode())
    # return build_result(301, r.hget('dict_map',str(id)))


@app.route('/<id>', methods=['PUT'])
def put_id_url(id):
    if not request_authenticated(request):  # the current user has no permission
        return build_result(403, "Request forbidden ")
    if "url" not in request.form:
        return build_result(400, "Error No url passed in ")

    if id.encode() not in r.hkeys('dict_map'):  # this id doesn't exist
        return build_result(404, "This id does not exist")

    url = request.form['url']
    username = get_user_from_request(request)
    print("reverse_map:", r.hgetall('reverse_map'))
    print("dict_map", r.hgetall('dict_map'))
    print('user_urls map', r.hgetall('user_urls'))
    if not is_valid_url(url):  # url is not valid
        return build_result(400, "error the given url is not valid")
    if url.encode() in r.hkeys('reverse_map'):  # the given url exists
        return build_result(400, "error the given url has already existed")

    # r.hget('user_urls','username').decode().split(',')
    if r.hget('dict_map', str(id)).decode() not in r.hget('user_urls', username).decode().split(
            ','):  # can only change your own url
        return build_result(403, 'Forbidden Can only change your own url!')
    # if username.encode() not in r.hkeys('user_urls'): # user_urls[username]=[]
    # print('this is a new user name')
    # r.hdel('user_urls',username)

    tmp_urls = r.hget('user_urls', username).decode().split(',')
    tmp_urls.append(url)
    r.hset('user_urls', username, ','.join(tmp_urls))
    # user_urls[username].append(url)

    previous_url = r.hget('dict_map', str(id)).decode()
    r.hdel('reverse_map', previous_url)

    # del reverse_map[previous_url]  #delete the previous url
    print('-------------')
    print("reverse_map:", r.hgetall('reverse_map'))
    print("dict_map", r.hgetall('dict_map'))
    print('user_urls map', r.hgetall('user_urls'))
    cur_urls = r.hget('user_urls', username)
    if cur_urls is not None:
        cur_urls = cur_urls.decode().split(',')
    else:
        cur_urls = []

    # cur_urls=r.hget('user_urls',username).decode().split(',')
    print('current url list is', cur_urls)
    print('previous url is ', previous_url)
    cur_urls.remove(previous_url)
    now_urls_str = ','.join(cur_urls)
    print('now url is ', now_urls_str)
    r.hset('user_urls', username, now_urls_str)
    # user_urls[username].remove(previous_url)

    r.hset('dict_map', str(id), url)  # update the id:yrl pair
    # reverse_map[url]=id
    r.hset('reverse_map', url, id)

    print('Put is done and now...')
    print("reverse_map:", r.hgetall('reverse_map'))
    print("dict_map", r.hgetall('dict_map'))
    print('user_urls map', r.hgetall('user_urls'))
    # print("reverse_map:", str(reverse_map))
    # print("dict_map", str(dict_map))
    # print('user_urls map', user_urls)
    return build_result(200, "")


@app.route('/<id>', methods=['DELETE'])
def delete_id(id):
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    if id.encode() not in r.hkeys('dict_map'):
        return build_result(404, "This id does not exist")
    url = r.hget('dict_map', str(id)).decode()
    username = get_user_from_request(request)
    # user_urls[username]
    if url.encode() not in r.hget('user_urls', username):  # can only delete his or her own url
        return build_result(403, 'Can only delete your own url!')
    # delete the url in user_urls
    now_urls = r.hget('user_urls', username).decode().split(',')
    now_urls.remove(url)
    r.hset('user_urls', username, ','.join(now_urls))
    # user_urls[username].remove(url)

    r.hdel('dict_map', id)
    r.hdel('reverse_map', url)
    '''
    del r.hget('dict_map',str(id))
    del reverse_map[url]
    '''
    print("reverse_map:", r.hgetall('reverse_map'))
    print("dict_map", r.hgetall('dict_map'))
    print('user_urls map', r.hgetall('user_urls'))
    return build_result(204, "Delete success")


@app.route('/', methods=['GET'])
def get_empty():  # check all the ids

    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    print('keys are', r.hkeys('dict_map'))
    decode_keylist = [s.decode() for s in r.hkeys('dict_map')]
    return build_result(200, decode_keylist)


@app.route('/', methods=['POST'])
def post_url():  # add a url to the server
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    if "url" not in request.form:
        return build_result(400, "No url passed in ")
    url = request.form['url']
    if not is_valid_url(url):
        return build_result(400, "error the given url is not valid")
    if url.encode() in r.hkeys('reverse_map'):
        return build_result(400, "error! This url has already existed")

    username = get_user_from_request(request)
    print('current username is ', username)
    if username.encode() not in r.hkeys('user_urls'):  # user_urls:
        # build_result(401, "not your url")
        # user_urls[username]=[]
        r.hset('user_urls', username, '')
    tmp_urls = r.hget('user_urls', username).decode().split(',')
    tmp_urls.append(url)
    r.hset('user_urls', username, ','.join(tmp_urls))

    # user_urls[username].append(url)
    new_id = generate_id(url)  # generate a new id
    '''
    reverse_map[url] = new_id
    dict_map[new_id] = url
    '''
    r.hset('reverse_map', url, new_id)
    r.hset('dict_map', new_id, url)
    print("reverse_map:", r.hgetall('reverse_map'))
    print("dict_map", r.hgetall('dict_map'))
    print('user_urls map', r.hgetall('user_urls'))
    # print("reverse_map:",str(reverse_map))
    # print("dict_map",str(dict_map))
    # print('user_urls map', user_urls)
    return build_result(201, new_id)


@app.route('/', methods=['DELETE'])
def delete_empty():  # delete all the id urls of a specific user
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    username = get_user_from_request(request)  # get username from request header
    print('current user is trying to delete, ', username)
    print('user_urls map', r.hgetall('user_urls'))
    # r.hget('user_urls',username)
    urls_to_delete = r.hget('user_urls', username).decode().split(',')
    print('deleteing urls:', urls_to_delete)
    ids_to_delete = []  # ids to delete and urls to delete
    for url in urls_to_delete:
        if r.hget('reverse_map', url) is not None:
            ids_to_delete.append(r.hget('reverse_map', url).decode())
        # ids_to_delete.append(reverse_map[url])
    print('deleting ids', ids_to_delete)
    for idx in ids_to_delete:
        # del dict_map[idx]
        r.hdel('dict_map', idx)

    for url in urls_to_delete:
        r.hdel('reverse_map', url)
        # del reverse_map[url]
    r.hdel('user_urls', username)
    # del user_urls[username]

    # print('current user_urls map', user_urls)

    return build_result(404, "")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
