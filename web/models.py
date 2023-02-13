from web.db import db, BaseDocument, DataType
from datetime import datetime


class Test(BaseDocument):
    collection = db.test
    fields = {
        "name": DataType(str, nullable=False),
        "time": DataType(datetime, nullable=False)
    }
