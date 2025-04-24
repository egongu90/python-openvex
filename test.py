from openvex.vex.vex import Vex

vex = Vex()
vex.author = "Eduardo"
vex.id = "my-vexdoc2"

vex.statements[0].status = "test"
# vex.statements[1].status = "test2"
vex.statements[0].products = []
products = ["xxxx", "yyyy"]
vex.statements[0].products.extend(products)
print(vex.new())
