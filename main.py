from flask import Flask
from flask_restful import Api

from controllers.hafnium_scan import HafniumScan

app = Flask(__name__)
api = Api(app)

api.add_resource(HafniumScan, "/v2/hafniumScan")

if __name__ == "__main__":
    app.run()
