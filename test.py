from openvex.vex.vex import Vex

vex = Vex()
vex.author = "Eduardo"
vex.role = "Dev"
vex.id = "my-vexdoc2"
vex.status = "xxxxxxx"
vex.vulnerability_id = "https://nvd.nist.gov/vuln/detail/CVE-2019-17571"
vex.vulnerability_name = "CVE-2019-17571"
vex.vulnerability_aliases = [
    "GHSA-2qrg-x229-3v8q",
    "openSUSE-SU-2020:0051-1",
    "SNYK-RHEL7-LOG4J-1472071",
    "DSA-4686-1",
    "USN-4495",
    "DLA-2065-1",
]
vex.vulnerability_description = "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid."
vex.justification = "vulnerable_code_not_in_execute_path"
vex.impact_statement = "XXXX not affected"

vex.products = [
    {
        "id": "xxxx",
        "hashes": {"sha-256": "1111111"},
        "identifiers": {"purl": "xxxxxpurl"},
    },
    {
        "id": "yyyyy",
        "hashes": {"sha-256": "2222222"},
        "identifiers": {"purl": "yyyyypurl"},
    },
]

print(vex.new())
