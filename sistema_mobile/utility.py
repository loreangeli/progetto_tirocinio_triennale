import  random

def asciitobin (string) :
    return bin(int.from_bytes(string.encode(), 'big'))

def bintoascii (bin) :
    n = int(bin, 2)
    bin = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    return bin

def generate_latitudine () :
    num = random.randint(0, 90)
    num2 = random.randint(0, 1) #Nord o Sud
    if num2==0 : 
        return str(num) + ":" + "Nord"
    else:
        return str(num) + ":" + "Sud"
    
def generate_longitudine () :
    num = random.randint(0, 180)
    num2 = random.randint(0, 1) #Est e Ovest
    if num2==0 : 
        return str(num) + ":" + "Ovest"
    else:
        return str(num) + ":" + "Est"
    
def generate_altitudine () :
    num = random.randint(0, 1500)

    return str(num)