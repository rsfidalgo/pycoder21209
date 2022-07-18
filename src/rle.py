from docopt import docopt

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

doc = """\
Irá codificar ou descodificar um ficheiro

Usage: 
    pycoder.py (-c [-t TYPE] | -d) [-p PASSWD] FILE
    


Options:
    -c --ENCODE                      Encriptar 
    -d --DECODE                      Desencriptar 
    -t TYPE --type                   Tipo [default: 2]
    -p PASSWD --passwd               Password
    FILE                             Ficheiro
    """
    
args = docopt(doc)

from enum import Enum
from io import SEEK_CUR
from typing import BinaryIO
from encrypt import *
from datetime import datetime



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
            out_file.write(method.value)
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

if args['--type']:
    if args['--type']== 1:
        tipo = RLEMethod.A
    else:
        tipo = RLEMethod.B



if args['--ENCODE']:
    out_F = args['FILE'] + '.rle'
    encode_rle(tipo, args['FILE'], out_F)
    if args['--passwd']:       
        pw = args['--passwd']
        encrypt_file(crypt, out_F, pw)

elif args['--DECODE'] and args['--passwd']:
    decrypt_file(crypt, args['FILE'], args['--passwd'])
    exit_F = args['FILE']
    out_F = exit_F[:-4]
    decode_rle(args['FILE'], 'file') 

elif args['--DECODE']:
    exit_F = args['FILE']
    out_F = exit_F[:-4]
    decode_rle(args['FILE'], out_F)




 

        