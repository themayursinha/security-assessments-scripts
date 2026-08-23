#/bin/python
# -*- coding: utf-8 -*-
# xor file w/ byte array
import sys

class xor():

  def xor(self, orginal_file, new_file, xor_var):
    l = len(xor_var)
    data = bytearray(open(orginal_file, 'rb').read())
    result = bytearray((
      (data[i] ^ xor_var[i % l]) for i in range(0,len(data))
    ))
    with open(new_file, 'wb') as localFile:
      localFile.write(result)

  def hexToByte(self, hexStr):
    byte_values = []
    hexStr = ''.join( hexStr.split(" ") )
    for i in range(0, len(hexStr), 2):
      byte_values.append(int(hexStr[i:i+2], 16))
    return byte_values


if __name__ == '__main__':
  try:
    transform = xor()
    orginal_file = sys.argv[1]
    new_file = sys.argv[2]
    byte_values = transform.hexToByte(sys.argv[3])
    xor_var = bytearray(byte_values)
    transform.xor(orginal_file, new_file, xor_var)
  except IndexError:
    print('Usage: xor.py <input_file> <output_file> <"XOR hex bytes">')
    sys.exit(1)
