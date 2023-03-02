#vogliamo verificare che la transazione non faccia parte di un 
#gruppo
Global.group_size() = Int(1) 
#il destinatario della txn viene confrontato con l'indirizzo del 
#benefattore
Txn.receiver() == Addr(benefactor) 
Txn.close_remainder_to()