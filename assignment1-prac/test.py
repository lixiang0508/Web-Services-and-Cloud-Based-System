
import unittest
import utils
import app

class Test(unittest.TestCase):

    def test_url1(self):
        url ='http://google.com'
        return self.assertTrue(utils.is_valid_url(url))

    def test_url2(self):
        url ='www.google.com'
        return self.assertFalse(utils.is_valid_url(url))

    def test_generate_id(self):
        print(utils.generate_unique_id())

    def test_check_map(self):
        print(app.check_map())

    def test_check_reversemap(self):
        print(app.check_reversemap())





if __name__ == "__main__":
    unittest.main()
