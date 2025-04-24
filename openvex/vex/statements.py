from dataclasses import dataclass
import json

# class Products:
#     product = json.dumps({"@id": product}
    # return json.dumps({"@id": product})

@dataclass
class Statements:
    # product = ""
    status = "under_investigation"
    products = []
