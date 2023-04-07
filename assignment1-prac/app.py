from flask import Flask
from static.resources import dict_map,reverse_map,idx
app = Flask(__name__)

#dict_map = {}  # id : url
#reverse_map = {}  # url :id


def build_result(code, value):
    return {"code": code, "value": value}




def generate_id(url):
    #generate id based on the given url
    # whatever algorithm to generate an id
    global idx
    #cur_id = g.get('idx')
    #g.idx= g.idx+1
    idx+=1
    return idx


# 请求方式
@app.route('/<id>', methods=['GET'])
def get_id(id):
    if int(id) not in dict_map.keys():
        print("not found this id")
        return build_result(404, "")
    return build_result(301, dict_map[int(id)])


@app.route('/<id>/<url>', methods=['PUT'])
def put_id_url(id,url):
    #generate
    if int(id) not in dict_map.keys(): # this id doesn't exist
        return build_result(404,"")
    if url in reverse_map.keys(): # the given url exists
        return build_result(400,"error")
    dict_map[int(id)]=url
    reverse_map[url]=int(id)
    return build_result(200, "")


@app.route('/<id>', methods=['DELETE'])
def delete_id(id):
    if int(id) not in dict_map.keys():
        return build_result(404, "")
    url = dict_map[int(id)]
    del dict_map[int(id)]
    del reverse_map[url]
    return build_result(204, "")


@app.route('/', methods=['GET'])
def get_empty():
    return build_result(200, list(dict_map.keys()))


@app.route('/<url>', methods=['POST'])
def post_url(url):
    if url in reverse_map.keys():
        return build_result(400, "error")
    new_id = generate_id(url)
    reverse_map[url] = new_id
    dict_map[new_id] = url
    print("reverse_map:",str(reverse_map))
    print("dict_map",str(dict_map))
    return build_result(201, new_id)


@app.route('/', methods=['DELETE'])
def delete_empty():
    return build_result(404, "")


@app.route('/checkmap')
def check_map():
    return str(dict_map)


@app.route('/check_reversemap')
def check_reversemap():
    return str(reverse_map)


if __name__ == '__main__':
    idx=0
    app.run()
