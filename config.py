import os


class Config(object):

    DEBUG = False
    MONGO_DB = os.environ.get("MONGO_DB", "InfoSec-CVE-RealTime")
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://dev:kvFI6xB79VLKWtmG@cluster0.nlaa2al.mongodb.net/?retryWrites=true&w=majority")
    SECRET_KEY = os.environ.get("SECRET_KEY", "secret")

    # WORK_KEY = "toWorker"


class DevelopmentConfig(Config):
    DEBUG = True
