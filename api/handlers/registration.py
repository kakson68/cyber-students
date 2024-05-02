from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
#Below utils file stores the Encryption,Decryption and Hash functions
from .utils import my_encrypt, hash_pass #

from .base import BaseHandler

class RegistrationHandler(BaseHandler):
    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)

            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            
            dateOfBirth = body['dateOfBirth']
            if not isinstance(dateOfBirth, str):
                raise Exception()
            
            phone_number = body['phone_number']
            if not isinstance(phone_number, str):
                raise Exception()

            disabilities = body['disabilities', str]
            if not isinstance(disabilities, str):
                raise Exception()



        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return
        if not dateOfBirth:
            self.send_error(400, message='The date Of Birth name is invalid!')
            return
        
        if not phone_number:
            self.send_error(400, message='The phone number   is invalid!')
            return
        
        if not disabilities:
            self.send_error(400, message='The disability  is invalid!')
            return


        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        #The Writer called my_encrypt function from utils.py to encrypt all sensitve data (personal information) before is writen to the MongoDB
        
        encrypted_display_name = my_encrypt(display_name)
        encrypted_phone_number = my_encrypt(phone_number)
        encrypted_disabilities = my_encrypt(disabilities)
        encrypted_address = my_encrypt(address)
        encrypted_dateOfBirth = my_encrypt(dateOfBirth)
        

        #I called the hash function from utils.py file to hash the password/passphrase before is writen to the MongoDB
        hashed_password = hash_pass(password)

        #We can now  save the enrypted personal information to the Database in compliance with GDPR regulations
        yield self.db.users.insert_one({
            'email': email,
            'hashed_password': hashed_password,
            'displayName': encrypted_display_name,
            'address':encrypted_address,
            'phone_number':encrypted_phone_number,
            'disabilities': encrypted_disabilities,
            'dateOfBirth' : encrypted_dateOfBirth
       })
        # Successful response  is returned to the user 
        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['address'] = address
        self.response['phoneNumber'] = phone_number
        self.response['disabilities'] = disabilities
        self.response['dateOfBirth'] = dateOfBirth

        self.write_json()