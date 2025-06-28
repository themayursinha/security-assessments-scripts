#/bin/python
# Program for messing w/ threads and options

import threading
import queue
import time
import logging
import argparse

continue_threads = True

class WorkerThread(threading.Thread):

  def __init__(self, queue):
    threading.Thread.__init__(self)
    self.queue = queue
	
  def finish(self):
    self.cont = False
	
	
  def run(self):
    print("In WorkerThread")
    while continue_threads == True:
      counter = self.queue.get()
	  # thread Logic goes here
      print("Ordered to sleep for %d seconds!"%counter)
      time.sleep(counter)
      print("Finished sleeping for %d seconds"%counter)
 
      self.queue.task_done()
  


def main():

  # Setup the command line arguments.
  parser = argparse.ArgumentParser(description='Thread management program')

  # Output verbosity options
  parser.add_argument('-q', '--quiet', help='set logging to ERROR',
                  action='store_const', dest='loglevel',
                  const=logging.ERROR, default=logging.INFO)
  parser.add_argument('-d', '--debug', help='set logging to DEBUG',
                  action='store_const', dest='loglevel',
                  const=logging.DEBUG, default=logging.INFO)
  parser.add_argument('-v', '--verbose', help='set logging to COMM',
                  action='store_const', dest='loglevel',
                  const=5, default=logging.INFO)

  # Option for number of threads
  parser.add_argument("-t", "--threads", dest="threads",
                  help="The number of threads to spawn")
				  
  args = parser.parse_args()

  if args.threads is None:
    args.threads = input("How threads do you want to spawn: ")
  
  # Setup logging.
  logging.basicConfig(level=args.loglevel,
                      format='%(levelname)-8s %(message)s')


  # Main Event Loop:
  try:
    queue = queue.Queue()
  
    for i in range(int(args.threads)):
      print("Creating WorkerThread : %d"%i)
      worker = WorkerThread(queue)
      worker.setDaemon(True)
      worker.start()
      print("WorkerThread %d Created!"%i)

    for j in range(int(args.threads)):
      queue.put(j)
  
    queue.join()
  
  except (KeyboardInterrupt, EOFError) as e:
    continue_threads = False
    exit(0)
	
  print("All tasks complete!")
  
if __name__ == '__main__':
  main()
