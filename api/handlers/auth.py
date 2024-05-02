from datetime import datetime
from time import mktime
from tornado.gen import coroutine

#The Author import decryption function from utils.py
from .utils import decrypt  

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {

            'email': 1,
            'expiresIn': 1,
            'encrypted_address': 1,
            'encrypted_dateOfBirth': 1,
            'encrypted_phone_number': 1,
            'encrypted_disabilities' : 1,
             'encrypted_dsiplay_name': 1,
            
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return
        
        
        self.current_user = {
            'email': user['email'],
            'display_name': decrypt(user['encrypted_dsiplay_name']),
            'disabilities': decrypt(user['encrypted_disabilities']),
            'address':decrypt(user['encrypted_address']),
            'phone_number' : decrypt(user['encrypted_phone_number']),
            'disability':decrypt(user['encrypted_disability'])
        }
       
        return user
