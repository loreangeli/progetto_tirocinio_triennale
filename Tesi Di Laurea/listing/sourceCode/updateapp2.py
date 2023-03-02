    is_not_update = Seq( Return(Int(1))
    program = If (
     OnComplete.UpdateApplication == Txn.on_completion(),
     Return(Int(0)),
     is_not_update
    )
    print(compileTeal(program, Mode.Application)