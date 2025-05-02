class Statements:
    def return_status(self, status):
        return status

    def return_products(self, products):
        return [
            {
                "@id": x.get("id", None),
                "hashes": x.get("hashes", None),
                "identifiers": x.get("identifiers", None),
            }
            for x in products
        ]

    def return_vulnerabilities(
        self,
        vulnerability_id,
        vulnerability_name,
        vulnerability_description,
        vulnerability_aliases,
    ):
        return {
            "@id": vulnerability_id,
            "name": vulnerability_name,
            "description": vulnerability_description,
            "aliases": vulnerability_aliases,
        }

    def return_justification(self, justification):
        return justification

    def return_impact_statement(self, impact_statement):
        return impact_statement

    # @staticmethod
    def return_statements(
        self,
        status,
        products,
        vulnerability_id,
        vulnerability_name,
        vulnerability_description,
        vulnerability_aliases,
        justification,
        impact_statement,
    ):
        return [
            {
                "vulnerability": self.return_vulnerabilities(
                    vulnerability_id,
                    vulnerability_name,
                    vulnerability_description,
                    vulnerability_aliases,
                ),
                "products": self.return_products(products),
                "status": self.return_status(status),
                "justification": self.return_justification(justification),
                "impact_statement": self.return_impact_statement(
                    impact_statement
                ),
            }
        ]
