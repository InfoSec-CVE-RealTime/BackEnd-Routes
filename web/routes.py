from flask import Flask
from web import app


@app.route('/')
def hello():
    return 'Hello, World!'
