#/bin/python
# Python program for playing around with user defined exceptions

class TooSmallError(Exception):
  def __init__(self):
    super().__init__("Too small! Try again ;)")

class TooBigError(Exception):
  def __init__(self):
    super().__init__("Too big! Try again ;)")

class ExactError(Exception):
  def __init__(self):
    print("HAHAHA You hit the trap")
    super().__init__("Exact match triggered the trap")

class unhandledError(Exception):pass

def checkNumber(num):
  if(num <= 4):
    raise TooSmallError()
  elif(num >= 7):
    raise TooBigError()
  elif(num == 5):
    raise ExactError()
  return num

def main():
  while 1:
    try:
      usrInpt = int(input("Enter the magic number: "))
      print(checkNumber(usrInpt))
    except TooSmallError as e:
      print(e)
    except TooBigError as e:
      print(e)
    except ExactError as e:
      print(e)
    else:
      break

if __name__ == '__main__':
  main()
