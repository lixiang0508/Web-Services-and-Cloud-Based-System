
import unittest

import static

import utils
import app
import authentication

class Test(unittest.TestCase):

    def test_url1(self):
        url ='http://google.com'
        return self.assertTrue(utils.is_valid_url(url))

    def test_url2(self):
        url ='www.google.com'
        return self.assertFalse(utils.is_valid_url(url))

    def test_generate_id(self):
        print(utils.generate_unique_id())


    def test_create_token(self):
        username="zlx"
        password="123456"
        print(authentication.create_token(username,password))
    def test_implement_login(self):
        username = "zlx"
        password = "123456"
        token =authentication.create_token(username,password)
        print({"username":username,"token":token})
        #print(authentication.implement_login(username,password))





if __name__ == "__main__":
    unittest.main()
