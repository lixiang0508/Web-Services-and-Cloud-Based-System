
For assignment 3.1:

1 Go to the path of the assignment3- basic frame

2 Execute docker-compose up --build

3 Send request from postman, for the url-shorten service the urls start with http://localhost:4000 and for the authentication service the urls start with http://localhost:4002

For assignment 3,2:

1 For all the yaml files ,kubectl apply -f <filename>.yaml
  
2 kubectl patch pv pv-redis -p '{"spec":{"claimRef":{"name":"redis-pv-claim"}}}'
  
3 kubectl patch pvc authentication-pv -p '{"spec": {"volumeName": "pv-authentication"}}'
  
4 From browser send request http://145.100.135.184:30002/ to visit the authentication service and http://145.100.135.184:30000/ to visit the url-shorten service
