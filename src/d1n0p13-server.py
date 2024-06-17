#!/usr/local/bin/python


import argparse
import bitarray
import bitarray.util
import crc
import netfilterqueue
import random
import subprocess

from DNP3_Lib import *
from scapy.all import *


def main():
	# Parse input
	parser = argparse.ArgumentParser(
			prog='D1N0P13-server',
			description='Recieve information over a covert \
					channel embedded in DNP3 messages',
			formatter_class=argparse.ArgumentDefaultsHelpFormatter)

	parser.add_argument('-m', '--method',
						help='Method for encoding',
						choices=["iin", "app-req", "app-resp"],
						required=True)
	parser.add_argument('-e', '--encryption',
						help='Optional key to enable stream cipher',
						required=False)
    #TODO do we need to check source interface
	parser.add_argument('-s', '--src', '--source',
						help='source to recieve from',
						required=False)
	parser.add_argument('-d', '--dst', '--destination',
						help='destination to filter for',
						required=False)
	parser.add_argument('-p', '--sport',
						help='source port',
						type=int,
						required=False)
	parser.add_argument('-P', '--dport', 
						help='destination port',
						type=int,
						required=False)

	global args
	args = parser.parse_args()


	# create variables used throughout
	# message is the bits that encode our secret data to transmit
	global message
	message = bitarray.bitarray()

	# The NFQUEUE to use, just need to be consitent between nfqueue and iptables
	QUE_NUM = 0


	# Output status to user
	print('Listening for a message')
	if args.encryption:
		print('Using encryption with key: ', args.encryption)
	if args.src:
		print('Only listening for packets with src == ', args.src)
	if args.dst:
		print('Only listening for packets with dst == ', args.dst)
	if args.sport:
		print('Only listening for packet with sport == ', args.sport)
	if args.dport:
		print('Only listening for packets with dport == ', args.dport)


	# Setup iptables rules to collect traffic
	RULE_NUM = '1'
	interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'INPUT', RULE_NUM]
	interceptRule.extend(['--protocol', 'tcp'])
	if args.src:
		interceptRule.extend(['--source', args.src])
	if args.dst:
		interceptRule.extend(['--destination', args.dst])
	if args.sport:
		interceptRule.extend(['--sport', str(args.sport)])
	if args.dport:
		interceptRule.extend(['--dport', str(args.dport)])
	interceptRule.extend(['--jump', 'NFQUEUE', '--queue-num', str(QUE_NUM)])
	subprocess.run(interceptRule)

	# Setup the nfqueue with alter_packets function
	nfque = netfilterqueue.NetfilterQueue()
	nfque.bind(QUE_NUM, extract_packets)

	# Run until user exit or end of tream
	try:
		nfque.run()
	except KeyboardInterrupt:
		print('User interupt, exiting')
	except NameError:
		print('\nReached the end of the stream, exiting')

	# remove the chr(0) terminator
	message_bytes = message.tobytes()[:-1]

	# if encryption is enabled, generate the same OTP and XOR
	if args.encryption:
		random.seed(args.encryption)
		key = random.randbytes(len(message_bytes))
		message_bytes = bytes([m ^ k for m, k in zip(message_bytes, key)])

	# pop off the last byte which is the CRC
	crc_byte = message_bytes[-1]
	message_bytes = message_bytes[:-1]

	# make sure the CRC matches what is expected
	if crc.Calculator(crc.Crc8.CCITT).verify(message_bytes, crc_byte):
		print('Message recieved: ', message_bytes.decode('ascii'))
	else:
		print('Error with the checksum, got: ', message_bytes.decode('ascii'))

	# Cleanup
	nfque.unbind()
	subprocess.run(['/usr/sbin/iptables', '-D', 'INPUT', RULE_NUM])


def extract_packets(packet):
	global args, message

	# cast to scapy for ease
	pkt = IP(packet.get_payload())

	# check if the packet is DNP3 and going to the right spot
	if match_packet(pkt):
		changed = False

		# if packet has ApplicationIIN
		if ((args.method == "iin") and pkt.haslayer(DNP3ApplicationIIN)):
			#decode the nmessage into the two reserved fieldsS
			message += str(pkt[DNP3ApplicationIIN].RESERVED_1)
			message += str(pkt[DNP3ApplicationIIN].RESERVED_2)

			# reset the IIN RESERVED bits to 0 to cover our tracks
			pkt[DNP3ApplicationIIN].RESERVED_1 = 0
			pkt[DNP3ApplicationIIN].RESERVED_2 = 0
			changed = True

		elif ((args.method == "app-resp")
				and pkt.haslayer(DNP3ApplicationResponse)
				and pkt[DNP3ApplicationResponse].FUNC_CODE
						not in [0x81, 0x82, 0x83]):
			extra = pkt[DNP3ApplicationResponset].FUNC_CODE - 0x83
			message += bitarray.util.int2ba(extra // 0x3 - 1, length=4)
			pkt[DNP3ApplicationRequest].FUNC_CODE = 0x81 + (extra % 0x3)
			changed = True

		elif ((args.method == "app-req")
				and pkt.haslayer(DNP3ApplicationRequest)
				and (pkt[DNP3ApplicationRequest].FUNC_CODE >= 0x22)):
			message += bitarray.util.int2ba(
					pkt[DNP3ApplicationRequest].FUNC_CODE // 0x22 - 1,
					length=2)
			pkt[DNP3ApplicationRequest].FUNC_CODE = \
					pkt[DNP3ApplicationRequest].FUNC_CODE % 0x22
			changed = True

		if changed:
			# and update the CRC
			crc = update_data_chunk_crc(bytes(pkt[DNP3Transport]))
			pkt[Raw].load = pkt[Raw].load[:-2] + crc[-2:]

			# and delete other checksums so scapy will calculate
			del pkt[IP].chksum
			del pkt[TCP].chksum
			packet.set_payload(bytes(pkt))

	# send the packet onwards
	packet.accept()

	# check if we have reached the end of the stream
	if ((len(message) > 0)
			and (len(message) % 8 == 0)
			and (message[-8:] == bitarray.bitarray('00000000'))):

		raise NameError("EndOfStream")


'''
match_packet(pkt)

	@param	pkt	scapy IP packet

	@return	bool	if the pkt meets the critera in args and is DNP3

	this function is called by alter_packets to determine if the passed
	packet meets the given criteria, and is a DNP3 packet
'''
def match_packet(pkt):
	global args

	if args.src and args.src != pkt.src:
		return False
	if args.dst and args.dst != pkt.dst:
		return False
	if args.sport and args.sport != pkt.sport:
		return False
	if args.dport and args.dport != pkt.dport:
		return False

	if pkt.haslayer(DNP3):
		return True

	return False



if __name__ == "__main__":
	main()
	
