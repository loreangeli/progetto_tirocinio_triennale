appAddr = Global.current_application_address()
Seq (
    #funzione usata per generare una transazione interna
    InnerTxnBuilder.Begin(), 
    InnerTxnBuilder.setFields (
        {
            TxnField.type_enum: Txn.AssetConfig,
            #nome che assegno all'asset
            TxnField.config_asset_name: Bytes("Decipher_coin")
            TxnField.config_asset_unit_name: Bytes("DC")
            TxnField.config_asset_url: Bytes("https://decipher.miami"),
            #numero di cifre dopo la virgola per la visualizzazione dell'asset
            TxnField.config_asset_decimals: Int(6) 
            #quantita totale di token che sto creando
            TxnField.config_asset_total: Int(800000000), 
            TxnField.config_asset_manager: appAddr,
        }
    ),
    #crea un decipher coin asset
    InnerTxn.Builder.Submit(),
    App.globalPut(Bytes("decipher_coin_ID"), InnerTxn.create_asset_id())