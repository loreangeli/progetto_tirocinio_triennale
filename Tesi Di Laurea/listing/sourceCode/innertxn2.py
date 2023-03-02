Seq (
    InnerTxnBuilder.Begin(),
    InnerTxnBuilder.setFields(
        {
            TxnField.type_enum: TxnType.Payment,
            TxnField.receiver: Txn.sender(),
            #misurato in microALGO: 1 ALGO = 1000000 microALGO
            TxnField.amount: Int(1_000_000), 
        }
    ),
    #invia 1 ALGO dall'escrow account al mittente della transazione
    InnerTxnBuilder.Submit()
)