import os

class Config(object):
    REDIS_SERVICE_HOST = os.environ.get('REDIS_SERVICE_HOST') or 'localhost'
    REDIS_SERVICE_PORT = os.environ.get('REDIS_SERVICE_PORT') or 6379

    MONGO_DB = os.environ.get('MONGO_DB') or 'local_db'
    MONGO_HOST = os.environ.get('MONGO_HOST') or 'localhost'
    MONGO_PORT = os.environ.get('MONGO_PORT') or '3306'
    MONGO_USER = os.environ.get('MONGO_USER') or 'root'
    MONGO_PWD = os.environ.get('MONGO_PWD') or 'pwned'

    WORK_KEY = "toWorker"
