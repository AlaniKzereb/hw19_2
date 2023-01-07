import calendar
import datetime
import hashlib

import jwt
import utcnow as utcnow

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.user import UserDAO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_d):
        user_d['password'] = self.get_hash(user_d['password'])
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ).decode("utf-8", "ignore")


    def get_access_token(self, data: dict):

        min10 = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        data['exp'] = calendar.timegm(min10.timetuple())
        access_token = jwt.encode(data, PWD_HASH_SALT)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, PWD_HASH_SALT)


        # min10 = datetime.utcnow() + datetime.timedelta(min=10)
        # data['exp'] = int(min10.timestamp())
        # access_token = jwt.encode(data, PWD_HASH_SALT)
        #
        # days130 = datetime.utcnow() + datetime.timedelta(days=130)
        # data['exp'] = int(days130.timestamp())
        # refresh_token = jwt.encode(data, PWD_HASH_SALT)

        return {'access_token': access_token, 'refresh_token': refresh_token, 'exp': data['exp']}


    def auth_user(self, username, password):
        user = self.dao.get_user_by_username(username)

        if not user:
            return None

        hash_password = self.get_hash(password)

        if hash_password != user.password:
            return None

        data = {
            'username': user.username,
            'role': user.role
        }

        return self.get_access_token(data)

    def check_refresh_token(self, refresh_token: str):
        try:
            data = jwt.decode(jwt=refresh_token, key=PWD_HASH_SALT, algorithms='HS256')
        except Exception as e:
            return None

        return self.get_access_token(data)
