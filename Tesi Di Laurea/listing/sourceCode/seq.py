program = Seq (
    App.globalPut(Bytes("count"), App.globalGet(Bytes("count"))+Int(1)),
    Approve()
)