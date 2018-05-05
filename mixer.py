from mixasm import parseasm
from parsecode import elfinfo
import os
import sys


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print "usage: python mixer.py [binary] [arch]"
		exit()
	stream = open(sys.argv[1],"rb").read()
	point = elfinfo(sys.argv[1]).code_area()
	mixed = parseasm(stream[point['offset']:point['offset'] + point['size']], int(sys.argv[2], 10))
	mixed.substitution()
	mixed_stream = mixed.stream
	print len(mixed.stream)
	print len(stream[point['offset']:point['offset'] + point['size']])
	print len(stream)
	result = stream[:point['offset']]+ mixed.stream + stream[point['offset'] + point['size']:]
	print len(result)
	open(sys.argv[1] + ".out", "wb").write(result)
	os.system("xxd " + sys.argv[1] + " > 1.hex")
	os.system("xxd " + sys.argv[1] + ".out" + " > 2.hex")
	os.system("diff 1.hex 2.hex")
	os.system("rm *.hex")
