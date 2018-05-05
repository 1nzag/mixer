import os, sys
from pwn import *
from parsecode import elfinfo


class parseasm:
	def __init__(self, stream, arch_code):
		self.arch  = arch_code
		if arch_code == 32:
			context.arch = 'i386'
		else:
			context.arch = 'amd64'
		
		self.asm = []
		for line in disasm(stream).split('\n'):
			inst = {}
			target = line.split(' ')
			flag = -1
			cnt = 1
			inst_string = ""
			for i in range(len(target)):
				if target[i] != '' and flag == -1:
					inst['addr'] = int(target[i].split(":")[0], 16)
					flag += 1
				elif target[i] != '' and flag == 0:
					cnt += 1
					flag += 1
				elif target[i] != '' and flag == 1:
					cnt += 1
				elif target[i] == '' and flag == 1:
					inst['size'] = cnt
					flag += 1
				elif target[i] != '' and flag == 2:
					inst_string += target[i]
					flag += 1
				elif flag == 3:
					if target[i] == '':
						inst_string += " "
					else:
						inst_string += target[i]
					
			inst['inst'] = inst_string
			print inst
				
				
			

if __name__ == '__main__':
	stream = open(sys.argv[1], "rb").read()
	point = elfinfo(sys.argv[1]).code_area()
	parseasm(stream[point['offset']:point['offset'] + point['size']], 64)


			
