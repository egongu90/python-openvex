import json
from dataclasses import dataclass
from datetime import datetime

from openvex.vex.statements import Statements


@dataclass
class Vex:
    type_uri = "https://openvex.dev/ns"
    context = "https://openvex.dev/ns"
    id = ""
    author = "Unknown Author"
    role = ""
    version = 1
    spec_version = "0.2.0"
    public_namespace = "https://openvex.dev/docs"
    timestamp = str(datetime.now())
    products = []
    status = ""
    vulnerability_id = ""
    vulnerability_name = ""
    vulnerability_description = ""
    vulnerability_aliases = []
    justification = ""
    impact_statement = ""

    def new(self):
        document = {
            "@context": self.context,
            "@id": self.id,
            "author": self.author,
            "role": self.role,
            "timestamp": self.timestamp,
            "version": self.version,
            "statements": Statements().return_statements(
                self.status,
                self.products,
                self.vulnerability_id,
                self.vulnerability_name,
                self.vulnerability_description,
                self.vulnerability_aliases,
                self.justification,
                self.impact_statement,
            ),
        }
        return json.dumps(document, default=vars)
