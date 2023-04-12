from flask_script import Manager
from flask_cors import CORS
import os
from web import app

cors = CORS(app)
manager = Manager(app)


if __name__ == '__main__':
    app.secret_key = os.urandom(12)
    manager.run()