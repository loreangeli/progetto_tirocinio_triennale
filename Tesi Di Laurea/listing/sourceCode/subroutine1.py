@Subroutine(TealType.uint64)
def isEven(i) :
    return i%Int(2) == Int(0)
App.globalPut(Bytes("value_is_even"), isEven(Int(10)))