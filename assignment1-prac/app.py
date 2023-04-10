#from urllib import request

from flask import Flask,request
from static.resources import dict_map,reverse_map
from utils import build_result,is_valid_url,generate_unique_id
app = Flask(__name__)


#dict_map = {}  # id : url
#reverse_map = {}  # url :id


#def build_result(code, value):
    #return {"code": code, "value": value}




def generate_id(url):
    #generate id based on the given url
    # whatever algorithm to generate an id
    #global idx
    #cur_id = g.get('idx')
    #g.idx= g.idx+1
    #idx+=1
    return generate_unique_id()


# 请求方式
@app.route('/<id>', methods=['GET'])
def get_id(id):
    if int(id) not in dict_map.keys():
        print("not found this id")
        return build_result(404, "This id does not exist")
    return build_result(301, dict_map[int(id)])


@app.route('/<id>', methods=['PUT'])
def put_id_url(id):
    if "url" not in request.form:
        return build_result(400, "No url passed in ")

    if int(id) not in dict_map.keys(): # this id doesn't exist
        return build_result(404,"This id does not exist")

    url = request.form['url']

    if url in reverse_map.keys(): # the given url exists
        return build_result(400,"error the given url has already existed")
    if not is_valid_url(url):
        return build_result(400, "error the given url is not valid")
    dict_map[int(id)]=url
    reverse_map[url]=int(id)
    return build_result(200, "")


@app.route('/<id>', methods=['DELETE'])
def delete_id(id):
    if int(id) not in dict_map.keys():
        return build_result(404, "This id does not exist")
    url = dict_map[int(id)]
    del dict_map[int(id)]
    del reverse_map[url]
    return build_result(204, "")


@app.route('/', methods=['GET'])
def get_empty():
    return build_result(200, list(dict_map.keys()))


@app.route('/<url>', methods=['POST'])
def post_url(url):
    #if "url" not in request.form:
        #return build_result(400, "No url passed in ")
    #url = request.form['url']
    if not is_valid_url(url):
        return build_result(400, "error the given url is not valid")
    if url in reverse_map.keys():
        return build_result(400, "error! This url has already existed")
    if not is_valid_url(url):
        return build_result(400, "error! This url is not valid")
    new_id = generate_id(url)
    reverse_map[url] = new_id
    dict_map[new_id] = url
    print("reverse_map:",str(reverse_map))
    print("dict_map",str(dict_map))
    return build_result(201, new_id)


@app.route('/', methods=['DELETE'])
def delete_empty():
    #TODO we have to identify the user and delete his own id-url pairs
    return build_result(404, "")



def check_map():
    return str(dict_map)



def check_reversemap():
    return str(reverse_map)


if __name__ == '__main__':
    #idx=0
    app.run()
