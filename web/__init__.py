import os
from flask import Flask

app = Flask(__name__)
app.config.from_object(os.environ.get("APP_SETTINGS", "config.DevelopmentConfig"))

from web import routes
