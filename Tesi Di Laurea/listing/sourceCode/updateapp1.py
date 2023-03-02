    program = Assert(Global.creator_address()==Txn.sender())
    print(compileTeal(program, Mode.Application)