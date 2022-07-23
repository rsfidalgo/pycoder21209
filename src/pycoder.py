"""
PyCoder is an RLE compression/decompression tool.

This module launches both the PyCoder GUI and the command line
interfaces. Unlike, gzip/gunzip, pycoder.py acts both as compressor and
decompressor.

It reads command line arguments using the docopt library and using
the following grammar:

    $ python3 pycoder.py (-c [-t TYPE] | -d) [-p PASSWD] FILE

This module is also a script and GUI application. Please see function 
'_main' for instructions on how to use 'pycoder.py' as script or GUI 
app.

(c) João Galamba, 2022
$$LICENSE(GPL)
"""

import rle
from docopt import docopt
import os
from time import strftime,gmtime
from encrypt import *

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

def decode_del (out_F):
        rle.decode_rle(out_F, out_F[:-4])
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
######################################################################################################################################
crypt = CryptMethod.FERNET_SMALL
######################################################################################################################################
if not args['--DECODE'] and not args['--ENCODE'] and not args['--passwd'] and not args['FILE']:
    from tkinter import * 

    
   
    root = Tk()
    root.title("PYCODER")

    inst2 = "Accesses files in the main folder\ninstructions to encrypt:\nEXAMPLE: Nome do ficheiro: music.mp3\nPress RELMethod.A or RELMethod.B buttons to run RLE method of choice\nif a password is inserted in Password box it will encrypt file usinf CryptMethod.FERNET_SMALL along with the REL method.\n\ninstructions to decrypt:\n\nEXAMPLE:Nome do ficheiro: music.mp3.rle\npress Descomprimir ficheiro button to decompress the file\nif the file was encrypted with CryptMethod.FERNET_SMALL make sure to use you password"
    
    def comp_File_a():
        try:
            ent = entrada1.get()
            out_f = ent + '.rle.'
            rle.encode_rle(rle.RLEMethod.A, ent, out_f) 
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
            rle.encode_rle(rle.RLEMethod.B, ent, out_f) 
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
        except TypeError as ex:
            entrada1.insert(0,'Erro --> {ex}')
        #:
    #:

    is_on = False

    def inst():
        global is_on
        if  is_on == False:
            myLabelInst.config(text=inst2)
            is_on = True
        else:
            root.after(50, lambda: myLabelInst.config(text=''))
            is_on = False

 

        
    """ entrada de data """
    entrada1 = Entry(root, width=50, bg="Grey", fg="yellow", borderwidth=8)
    entrada2 = Entry(root, width=50, bg="Grey", fg="yellow", borderwidth=8)
    
    """ cria botao """
    myButton1 = Button(root, text=" RLEMethod.A", padx=5, pady=5, command=comp_File_a, fg="black", bg="green")
    myButton2 = Button(root, text=" RLEMethod.B", padx=5, pady=5, command=comp_File_b, fg="black", bg="green")
    myButton3 = Button(root, text="Descomprimir Ficheiro", padx=5, pady=5, command=unc_File, fg="black", bg="yellow")
    myButtonINST = Button(root, text="instruções", padx=5, pady=5, command=inst, fg="black", bg="yellow")
    
    """ cria label """
    myLabel1 = Label(root, text="Password")
    myLabel2 = Label(root, text="Nome do ficheiro: ")
    myLabelInst = Label(root)
    
    """ coloca no ecrã de acordo com row column.grip """
    myLabel1.grid(row=3, column=0)
    myLabel2.grid(row=1, column=0)
    myLabelInst.grid(row=5, column=0, columnspan=3)

    myButton1.grid(row=2, column=1)
    myButton2.grid(row=2, column=2)
    myButton3.grid(row=2, column=3)
    myButtonINST.grid(row=4, column=3)

    entrada1.grid(row=1, column=2)
    entrada2.grid(row=3, column=2)

    root.mainloop()
############################################################################################################################:

if args['--type']:
    if args['--type'] == '1':
        tipo = rle.RLEMethod.A
    #:
    elif args['--type'] == '2':
        tipo = rle.RLEMethod.B
    #:
#:
 
if args['--ENCODE']:
    try:
        out_F = args['FILE'] + '.rle'
        rle.encode_rle(tipo, args['FILE'], out_F)   
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
        print(f'Erro: Possivel problema com a password\n --> {ex} <--')
    #:
#: