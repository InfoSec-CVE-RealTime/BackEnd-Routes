from flask_script import Manager
import os
from web import app

manager = Manager(app)


if __name__ == '__main__':
    app.secret_key = os.urandom(12)
    manager.run()
