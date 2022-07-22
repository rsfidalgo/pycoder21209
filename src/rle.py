from ast import Return
from fileinput import filename
from docopt import docopt
from enum import Enum
from io import SEEK_CUR
from typing import BinaryIO
from encrypt import *
from time import strftime,gmtime
from datetime import datetime
from time import time 
import os

"""
This module implements a RLE compressor and decompressor. Two RLE
methods are implemented here:

    A - Each ocurrence of a new byte is replaced by a counter with the 
        number of consecutive occurrences and the byte itself.
        Examples: 
            1) b'LLLLARRB' -> b'\x04L\x01A\x02R\x01B'.
            2) b'ABC'      -> b'\x01A\x01B\x01C'

    B - Only series with repetition (two or more consecutive occurrences
        of the same byte) are replaced by a double ocurrence of the
        byte and a counter. Bytes that don't repeat are passed directly
        to the output stream. 
        Examples: 
            1) b'LLLLARRB' -> b'LL\x04ARR\x02B'.
            2) b'ABC'      -> b'ABC'
        A double occurrence of the encoded byte "tells" the decoder that
        the next byte is a counter, whereas a byte that doesn't repeat 
        is copied directly to the output stream.

Please consult Wikipedia to obtain more information about RLE in general
and these specific methods.

(c) João Galamba, 2022
$$LICENSE(GPL)

$ python3 pycoder.py (-c [-t TYPE] | -d) [-p PASSWD] FILE

As opções -c e -d (ou --encode e --decode) indicam se vai codifcar ou descodifcar o fcheiro dado por FILE.
TYPE pode ser 1 (método A) ou 2 (método B), sendo 2 o valor por omissão. A versão longa desta opção é
--type=TYPE. 
À semelhança do comando gzip, apos codifcação (opção -c) o fcheiro FILE passa a possuir a extensão
.rle. Esta extensão é removida apos descodifcação, tal como sucede com o comando gunzip.
Com a opção -p pode introduzir uma palavra-passe que será utilizada para para encriptar, através de
criptografa simétrica, o fcheiro resultante da compressão RLE. Pode utilizar um modulo da biblioteca do
Python ou uma biblioteca externa instalável com pip (eg, criptography). Como alternativa, pode também
desenvolver um algoritmo de encriptação. Um algoritmo pedagogicamente interessante, ainda que pouco
seguro, e que se enquadra no espírito deste projecto, é a Cifra de Vigenère.



"""
######################################################################################################################################

doc = """\
Irá compactar ou descompactar um ficheiro

Usage: 
    pycoder.py
    pycoder.py (-c [-t TYPE] | -d) [-p PASSWD] FILE
    


Options:
    -c --ENCODE                      Encriptar 
    -d --DECODE                      Desencriptar 
    -t TYPE --type                   Tipo [default: 2]
    -p PASSWD --passwd               Password
    FILE                             Ficheiro
    """
    
args = docopt(doc)

####################################################################################################################################
def time_stamp_b():
    time_stamp_sec_b = int(time()).to_bytes(4,"big")
    return time_stamp_sec_b
#:

def decode_del (out_F):
        decode_rle(out_F, out_F[:-4])
        os.remove(out_F)
#:

def dvlv_met(file):
    with open(file, 'rb') as _f:
                curr = _f.read(1)
                if curr == b'\x8a':
                    op = '2'
                    _m = b'\x8a'
                    return op, _m
                #:
                elif curr == b'\x21':
                    op = '1'
                    _m = b'\x21'
                    opi=int.from_bytes(_m, "big")
                    return op, _m
                #:
    #:
#:

def exit_header(in_f, out_f, method, opcode):
    data_hota = strftime(f"%Y-%m-%d %H:%M")
    op=int.from_bytes(opcode, "big")
    cab = f"Decompressed '{in_f}' into '{out_f}' using method {method} (opcode {op})\nCompression date/time: {data_hota}\n\n"

    with open(out_f, 'r+') as f:
        lines = f.readlines()
        f.seek(0)
        f.write(cab)
        for line in lines:
            f.write(line)
        #:
    #:
#:
###############################################################################################################################################
__all__ = [
    'RLEMethod',
    'encode_rle',
    'decode_rle'
]

class RLEMethod(Enum):
    A = b'\x21'      # 33 or b'!'
    B = b'\x8a'      # 138
#:



def encode_rle(
        method: RLEMethod,
        in_file_path: str,
        out_file_path: str,
        overwrite: bool = True,
):
    """
    Encodes the file given by C{in_file_path} with the RLE compression
    method specified by the method parameter. Compressed data 
    is written into the file given by out_file_path.
    A KeyError exception is raised if the method parameter is passed 
    an unknown value.
    """
    encode_fn = {
        RLEMethod.A: _encode_mA,
        RLEMethod.B: _encode_mB,
    }[method]
    with open(in_file_path, 'rb') as in_file:
        with open(out_file_path, 'wb' if overwrite else 'xb') as out_file:
            ts = time_stamp_b()
            out_file.write(method.value) 
            out_file.write(ts)
            encode_fn(in_file, out_file)
#:

def _encode_mA(in_file: BinaryIO, out_file: BinaryIO):
    def write_fn(curr_byte: bytes, count: int):
        out_file.write(_int_to_byte(count))
        out_file.write(curr_byte)
    #:
    _do_encode(in_file, write_fn)
#:

def _encode_mB(in_file: BinaryIO, out_file: BinaryIO):
    def write_fn(curr_byte: bytes, count: int):
        out_file.write(curr_byte)
        if count > 1:
            out_file.write(curr_byte)
            out_file.write(_int_to_byte(count))
    #:
    _do_encode(in_file, write_fn)
#:

def _do_encode(in_: BinaryIO, write_fn):
    """
    This is the outline of the algorithm:
        1. curr_byte = 1st byte in 'in_'.
        2. count = 1
        3. For each byte in 'in_':
            3.1 If next_byte equals curr_byte:
                3.1.1 Increment count
            3.2 Else: (série de bytes consecutivos chegou ao fim)
                3.2.1 Write curr_byte and count
                3.2.2 count = 1
                3.2.3 curr_byte = next_byte
        4. Write last curr_byte and count
    NOTE: This outline ignores what happens when count > 255
    """
    curr_byte = in_.read(1)
    count = 1
    for next_byte in iter(lambda: in_.read(1), b''):
        if next_byte == curr_byte:
            count += 1
            if count == 256:
                write_fn(curr_byte, count - 1)
                count = 1
        else:
            write_fn(curr_byte, count)
            count = 1
            curr_byte = next_byte
    #:
    if curr_byte:
        write_fn(curr_byte, count)
    #:
#:

def decode_rle(
        in_file_path: str, 
        out_file_path: str, 
        overwrite: bool = True,
) -> RLEMethod:
    """
    Decodes the file given by C{in_file_path} with the RLE compression
    method specified by the 1st byte in that same input file.
    Uncompressed data is written into the file given by C{out_file_path}.
    A C{KeyError} exception is raised if the method value stored in the
    1st byte of the input file has an unknown value.
    """
    method = None
    with open(in_file_path, 'rb') as in_file:
        method = RLEMethod(in_file.read(1))
        ts = in_file.read(4)
        decode_fn = {
            RLEMethod.A: _decode_mA,
            RLEMethod.B: _decode_mB,
        }[method]
        with open(out_file_path, 'wb' if overwrite else 'xb') as out_file:
            decode_fn(in_file, out_file)
    return method
#:

def _decode_mA(in_file: BinaryIO, out_file: BinaryIO):
    for count, next_byte_int in iter(lambda: in_file.read(2), b''):
        out_file.write(count * _int_to_byte(next_byte_int))
#:

    # while True:
    #     dados = in_file.read(2)
    #     if not dados:
    #         break
    #     count, next_byte = dados
    #     out_file.write(count * _int_to_byte(next_byte_int))

    # out_file.write(count * _int_to_byte(next_byte_int)) 
    #       EQUIVALENTE A:
    # next_byte = _int_to_byte(next_byte_int)
    # out_data = count * _int_to_byte(next_byte_int)
    # out_file.write(out_data)

def _decode_mB(in_file: BinaryIO, out_file: BinaryIO):
    """
    1. Em ciclo, ler dois bytes de cada vez
        1.1 if not byte1:
            1.1.1 Fim ficheiro logo fim do ciclo
        1.2. Se byte1 == byte2 então
            1.2.1 Ler 3o byte com a contagem (count)
            1.2.2 Colocar na saída byte1 count vezes
        1.3 Senão (ou seja, se byte1 != byte2)
            1.3.1 Escrever byte1
            1.3.2 Se houver byte2, então voltar a colocar na entrada 
                  byte2 (para que a próxima iteração começe a partir 
                  deste byte2)
    """
    while True:
        # Note that 2 x read(1) != read(2). The later may not 
        # return 2 bytes, and that would break the code.
        b1, b2 = in_file.read(1), in_file.read(1) 
        if not b1:
            break

        if b1 == b2:
            b3 = in_file.read(1)
            count = b3[0]
        else:
            if b2:   # ou seja, se b2 != b''
                in_file.seek(-1, SEEK_CUR)
            count = 1
        out_file.write(count * b1)
    #:
#:

def _int_to_byte(byte: int) -> bytes:
    """
    This functions converts an integer between 0 and 255 to bytes.
    >>> int_to_byte(15)
    b'\x0f'
    >>> int_to_byte(254)
    b'\xfe'
    """
    return bytes([byte])
#:

######################################################################################################################################################

crypt = CryptMethod.FERNET_SMALL

#####################################################################################################################################################

if not args['--DECODE'] and not args['--ENCODE'] and not args['--passwd'] and not args['FILE']:
    from tkinter import * 
   
    root = Tk()
    root.title("PYCODER")

    def comp_File_a():
        try:
            ent = entrada1.get()
            out_f = ent + '.rle.'
            encode_rle(RLEMethod.A, ent, out_f) 
            os.remove(ent)
            ent2 = entrada2.get()
            if ent2:
                encrypt_file(crypt, out_f, ent2)
            #:
        #:
        except FileNotFoundError:
            entrada1.delete(0,END)
            entrada1.insert(0, "Erro: Ficheiro inexistente!")
        #:
    #:
        
    def comp_File_b():
        try:
            ent = entrada1.get()
            out_f = ent + '.rle.'
            encode_rle(RLEMethod.B, ent, out_f) 
            os.remove(ent)
            ent2 = entrada2.get()
            if ent2:
                encrypt_file(crypt, out_f, ent2)
            #:
        #:
        except FileNotFoundError:
            entrada1.delete(0,END)
            entrada1.insert(0, "Erro: Ficheiro inexistente!")
        #:
    #:
    
    def unc_File():
        try:
            ent = entrada1.get()
            ent2 = entrada2.get()
            if ent2:
                decrypt_file(crypt, ent, ent2)
            #:
            a, b = dvlv_met(ent)
            decode_del(ent)
            exit_header(ent,ent[:-4],a, b)
        #:
        except FileNotFoundError:
            entrada1.delete(0, END)
            entrada1.insert(0,'Erro: Ficheiro inexistente!')
        #:
        except ValueError:
            entrada1.delete(0,END)
            entrada1.insert(0,'Erro: Ficheiro incompatível. Certifique-se que é .rle!')
        #:
        except TypeError:
            entrada2.insert(0,'Erro: certifique-se de que insere uma password!')
        #:
    #:
        
    """ entrada de data """
    entrada1 = Entry(root, width=50, bg="Grey", fg="yellow", borderwidth=8)
    entrada2 = Entry(root, width=50, bg="Grey", fg="yellow", borderwidth=8)
    
    """ cria botao """
    myButton1 = Button(root, text=" RLEMethod.A", padx=5, pady=5, command=comp_File_a, fg="black", bg="green")
    myButton2 = Button(root, text=" RLEMethod.B", padx=5, pady=5, command=comp_File_b, fg="black", bg="green")
    myButton3 = Button(root, text="Descomprimir ficheiro", padx=5, pady=5, command=unc_File, fg="black", bg="yellow")
    
    """ cria label """
    myLabel1 = Label(root, text="Password")
    myLabel2 = Label(root, text="Nome do ficheiro: ")
    
    """ coloca no ecrã de acordo com row column.grip """
    myLabel1.grid(row=3, column=0)
    myLabel2.grid(row=1, column=0)

    myButton1.grid(row=2, column=1)
    myButton2.grid(row=2, column=2)
    myButton3.grid(row=2, column=3)

    entrada1.grid(row=1, column=2)
    entrada2.grid(row=3, column=2)

    root.mainloop()
############################################################################################################################:

if args['--type']:
    if args['--type'] == '1':
        tipo = RLEMethod.A
    #:
    elif args['--type'] == '2':
        tipo = RLEMethod.B
    #:
#:
 
if args['--ENCODE']:
    try:
        out_F = args['FILE'] + '.rle'
        encode_rle(tipo, args['FILE'], out_F)   
        os.remove(args['FILE'])
        if args['--passwd']:      
            pw = args['--passwd']
            encrypt_file(crypt, out_F, pw)
        #:
    #:
    except FileNotFoundError as ex:
        print('Erro: Ficheiro inexistente!\n --> {ex} <--')
    #:
#:

elif args['--DECODE'] and args['--passwd']:
    try:
        decrypt_file(crypt, args['FILE'], args['--passwd'])
        exit_F = args['FILE']
        out_F = exit_F[:-4]
        a, b = dvlv_met(args['FILE'])
        decode_del(args['FILE'])
        exit_header(args['FILE'],out_F,a, b)
    #:
    except FileNotFoundError as ex:
        print('Erro: Ficheiro inexistente!\n --> {ex} <--')
    #:
#:
    

elif args['--DECODE']:

    try:
        _F = args['FILE']
        out_F = _F[:-4]
        a, b = dvlv_met(args['FILE'])
        decode_del(args['FILE'])
        exit_header(args['FILE'],out_F,a, b)
    #:
    except FileNotFoundError as ex:
        print(f'Erro: Ficheiro inexistente!\n --> {ex} <--')
    #:
    except ValueError as ex:
        print(f'Erro: Ficheiro incompatível. Certifique-se que é .rle!\n --> {ex} <--')
    #:
    except TypeError as ex:
        print(f'Erro: Certifique-se de que insere uma password!\n --> {ex} <--')
    #:
#:
