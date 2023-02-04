import os
from flask import Flask
from app.config import Config
# from flask_debug import Debug
import logging

app = Flask(__name__)
app.config.from_object(Config)

from app.logger import RedisHandler, formatter

redisHandler = RedisHandler()
redisHandler.setFormatter(formatter)
redisHandler.setLevel(level=logging.INFO)
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(redisHandler)

from app import routes
