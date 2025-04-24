from datetime import datetime
from dataclasses import dataclass
from openvex.vex.statements import Statements

import json

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
    statements = [Statements()]

    def new(self):
        document = {"@context": self.context,
                    "@id": self.id,
                    "author": self.author,
                    "role": self.role,
                    "timestamp": self.timestamp,
                    "version": self.version,
                    "statements": self.statements,
                   }
        return json.dumps(document, default=vars)

