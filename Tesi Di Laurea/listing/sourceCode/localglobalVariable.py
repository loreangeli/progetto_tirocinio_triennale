from pyteal import *

#  variabili globali
program = App.globalPut(Bytes("MyKey"), Int(50))
program = App.globalGet(Bytes("MyKey"))
program = App.globalDel(Bytes("MyKey"))

#  variabili locali
program = App.localPut(Int(0), Bytes("MyKey"), Int(50))
program = App.localGet(Int(0), Bytes("MyKey"))
program = App.localDel(Int(0), Bytes("MyKey"))
print (compileTeal(program, Mode.Application))