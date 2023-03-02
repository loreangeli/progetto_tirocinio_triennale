program = Seq (
    if (App.globalGet(Bytes("count"))==Int(100))
    .then (
        #100esimo chiamante di questa app
        App.globalPut(Bytes("100thCaller"), Txn.sender())
    )
    .else (
        App.globalPut(Bytes("not100thcaller"), Txn.sender())
    ),
    App.globalPut(Bytes("count"), App.globalGet(Bytes("count"))+Int(1)),
    Approve(),
)