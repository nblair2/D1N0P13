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
			prog='D1N0P13-client',
			description='Send information over a covert \
					channel embedded in DNP3 messages',
			formatter_class=argparse.ArgumentDefaultsHelpFormatter)

	parser.add_argument(dest='message',
						help='message to send')
	parser.add_argument('-m', '--method',
						help='Method for encoding',
						choices=['iin', 'app-req', 'app-resp'],
						required=True)
	parser.add_argument('-e', '--encryption',
						help='Optional key to enable stream cipher',
						required=False)
    #TODO do we need to check source interface
	parser.add_argument('-s', '--src', '--source',
						help='source to send from',
						required=False)
	parser.add_argument('-d', '--dst', '--destination',
						help='destination to send to',
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
	# The NFQUEUE to use, just need to be consitent between nfqueue and iptables
	QUE_NUM = 0

	# index keeps track of how many bits have been (and need to be) transmited
	global index
	index = 0

	# message is the bits that encode our secret data to transmit
	global message

	message_bytes = bytes(args.message, 'ascii')

	# calculate a crc byte to check our message, store at end
	crc_byte = crc.Calculator(crc.Crc8.CCITT).checksum(message_bytes)
	message_bytes += crc_byte.to_bytes(1, 'little')

	# if encryption is enabled, generate random OTP given seed and XOR
	if args.encryption:
		random.seed(args.encryption)
		key = random.randbytes(len(message_bytes))
		message_bytes = bytes([m ^ k for m, k in zip(message_bytes, key)])

	message = bitarray.bitarray()
	message.frombytes(message_bytes)
	# Add this chr(0) byte to mark end of message)
	message += '00000000'


	# Output status to user
	print('Sending Message: ', args.message)
	if args.encryption:
		print('Using encryption with key: ', args.encryption)
	if args.src:
		print('Only modifying packets with src == ', args.src)
	if args.dst:
		print('Only modifying packets with dst == ', args.dst)
	if args.sport:
		print('Only modifying packets with sport == ', args.sport)
	if args.dport:
		print('Only modifying packets with dport == ', args.dport)


	# Setup iptables rules to collect traffic
	RULE_NUM = '1'
	interceptRule = ['/usr/sbin/iptables', '-t', 'filter', '-I', 'OUTPUT', RULE_NUM]
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
	nfque.bind(QUE_NUM, alter_packets)

	# Run until user exit or end of Stream
	try:
		nfque.run()
	except KeyboardInterrupt:
		print('User interupt, exiting')
	except NameError:
		print('\nReached the end of the stream, exiting')

	# Cleanup
	nfque.unbind()
	subprocess.run(['/usr/sbin/iptables', '-D', 'OUTPUT', RULE_NUM])


'''
alter_packets(packet)

	@param	packet	netfilterqueue.packet type
					the packet intercepted before being sent

	this function is called by nfqueue and is used to selectively
	modify packets that meet the given criteria for the covert channel
'''
def alter_packets(packet):
	global args, message, index

	# cast to scapy for ease
	pkt = IP(packet.get_payload())

	# check if the packet is DNP3 and going to the right spot
	if match_packet(pkt):
		changed = False

		# if the packet has ApplicationIIN
		if (args.method == "iin") and pkt.haslayer(DNP3ApplicationIIN):
			#encode the message into the two reserved fields
			pkt[DNP3ApplicationIIN].RESERVED_1 = message[index]
			pkt[DNP3ApplicationIIN].RESERVED_2 = message[index + 1]
			# increment ind
			index += 2
			changed = True

		elif ((args.method == "app-resp")
				and pkt.haslayer(DNP3ApplicationResponse)):
			pass
			changed = True

		elif ((args.method == "app-req")
				and pkt.haslayer(DNP3ApplicationRequest)):
			bits = message[index : index + 2]
			pkt[DNP3ApplicationRequest].FUNC_CODE += \
					0x22 * (bitarray.util.ba2int(bits) + 1)
			index += 2
			changed = True

		if changed:
			# update the CRC
			crc = update_data_chunk_crc(bytes(pkt[DNP3Transport]))
			pkt[Raw].load = pkt[Raw].load[:-2] + crc[-2:]
			# remove checksums so they will be updated when sent
			del pkt[IP].chksum
			del pkt[TCP].chksum

	send(pkt, verbose=False)

	if index + 1 >= len(message):
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
	
