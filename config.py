import os


class Config(object):
    # REDIS_SERVICE_HOST = os.environ.get("REDIS_SERVICE_HOST", "localhost")
    # REDIS_SERVICE_PORT = os.environ.get("REDIS_SERVICE_PORT", 6379)

    DEBUG = False
    MONGO_DB = os.environ.get("MONGO_DB", "cve_data")
    MONGO_URI = os.environ.get("MONGO_URL", "mongodb://localhost:27017/")
    SECRET_KEY = os.environ.get("SECRET_KEY", "secret")

    # WORK_KEY = "toWorker"


class DevelopmentConfig(Config):
    DEBUG = True
    MONGO_DB = os.environ.get("MONGO_DB", "dev_cve_data")
