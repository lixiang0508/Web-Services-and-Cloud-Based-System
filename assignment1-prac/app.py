from flask import Flask,request
from flask_cors import CORS
from authentication import implement_register,implement_login,request_authenticated,get_user_from_request
from static.resources import dict_map,reverse_map,user_urls,username_password
from utils import build_result,is_valid_url,generate_unique_id
app = Flask(__name__)
CORS(app)


def generate_id(url): # generate an unique id for each url

    return generate_unique_id(url)

@app.route('/register',methods=['POST'])
def register():
    if 'username' not in request.form or 'password' not in request.form:
        return build_result(400,"Register fails") # parameters not enough
    username = request.form.get('username') # get username from request form
    password = request.form.get('password') # get password from request form
    res=implement_register(username,password) # cite implementation
    if not res:
        return build_result(400,"username has already existed")
    print('username_password',username_password)
    return build_result(200,"Register success")

@app.route('/login',methods=['POST'])
def login():
    if 'username' not in request.form or 'password' not in request.form:
        return build_result(400,"Login fails") #password does not match the username
    username = request.form.get('username')
    password = request.form.get('password')

    return build_result(200,implement_login(username,password))


# 请求方式
@app.route('/<id>', methods=['GET'])
def get_id(id):
    if id not in dict_map.keys(): # this id does not exist
        print("not found this id")
        return build_result(404, "This id does not exist")
    return build_result(301, dict_map[id])


@app.route('/<id>', methods=['PUT'])
def put_id_url(id):
    if not request_authenticated(request):  # the current user has no permission
        return build_result(403, "Request forbidden ")
    if "url" not in request.form:
        return build_result(400, "No url passed in ")

    if id not in dict_map.keys(): # this id doesn't exist
        return build_result(404,"This id does not exist")

    url = request.form['url']
    username= get_user_from_request(request)
    print("reverse_map:", str(reverse_map))
    print("dict_map", str(dict_map))
    print('user_urls map', user_urls)
    if not is_valid_url(url): # url is not valid
        return build_result(400, "error the given url is not valid")
    if url in reverse_map.keys(): # the given url exists
        return build_result(400,"error the given url has already existed")


    if dict_map[id] not in user_urls[username]:  # can only change your own url
        return build_result(403, 'Can only change your own url!')
    if username not in user_urls:
        user_urls[username]=[]
    user_urls[username].append(url)

    previous_url = dict_map[id]
    del reverse_map[previous_url]  #delete the previous url
    user_urls[username].remove(previous_url)
    dict_map[id]=url #update the id:yrl pair
    reverse_map[url]=id


    print('Put is done and now...')
    print("reverse_map:", str(reverse_map))
    print("dict_map", str(dict_map))
    print('user_urls map', user_urls)
    return build_result(200, "")


@app.route('/<id>', methods=['DELETE'])
def delete_id(id):
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    if id not in dict_map.keys():
        return build_result(404, "This id does not exist")
    url = dict_map[id]
    username = get_user_from_request(request)
    if url not in user_urls[username]: #can only delete his or her own url
        return build_result(403,'Can only delete your own url!')
    # delete the url in user_urls
    user_urls[username].remove(url)
    del dict_map[id]
    del reverse_map[url]
    return build_result(204, "Delete success")


@app.route('/', methods=['GET'])
def get_empty(): #check all the ids
    return build_result(200, list(dict_map.keys()))


@app.route('/', methods=['POST'])
def post_url(): # add a url to the server
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    if "url" not in request.form:
        return build_result(400, "No url passed in ")
    url = request.form['url']
    if not is_valid_url(url):
        return build_result(400, "error the given url is not valid")
    if url in reverse_map.keys():
        return build_result(400, "error! This url has already existed")

    username = get_user_from_request(request)
    print('current username is ',username)
    if username not in user_urls:
        #build_result(401, "not your url")
        user_urls[username]=[]
    user_urls[username].append(url)
    new_id = generate_id(url) #generate a new id
    reverse_map[url] = new_id
    dict_map[new_id] = url
    print("reverse_map:",str(reverse_map))
    print("dict_map",str(dict_map))
    print('user_urls map', user_urls)
    return build_result(201, new_id)


@app.route('/', methods=['DELETE'])
def delete_empty(): #delete all the id urls of a specific user
    if not request_authenticated(request):
        return build_result(403, "Request forbidden ")
    username = get_user_from_request(request) #get username from request header
    print('current user is trying to delete, ',username)
    print('user_urls map',user_urls)
    urls_to_delete=user_urls[username]
    print('deleteing urls:', urls_to_delete)
    ids_to_delete=[] #ids to delete and urls to delete
    for url in urls_to_delete:
        ids_to_delete.append(reverse_map[url])
    print('deleting ids', ids_to_delete)
    for idx in ids_to_delete:
        del dict_map[idx]

    for url in urls_to_delete:
        del reverse_map[url]
    del user_urls[username]
    print('current user_urls map', user_urls)

    return build_result(404, "")






if __name__ == '__main__':
    app.run()
