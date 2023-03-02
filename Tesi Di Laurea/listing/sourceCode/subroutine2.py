@Subroutine(TealType.uint64)
def recursiveisEven(i) :
    return (
        if (i == Int(0)
        .Then ( Int(1)
        .ElseIf ( i == Int(1))
        .Then ( Int(0))
        .Else (recursiveisEven( i-Int(2))