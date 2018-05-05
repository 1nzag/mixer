import os, sys
from pwn import *
from parsecode import elfinfo
import random

class parseasm:
	def __init__(self, stream, arch_code):
		self.arch  = arch_code
		if arch_code == 32:
			context.arch = 'i386'
		else:
			context.arch = 'amd64'
		
		self.asm = []
		self.stream = stream[:]
		for line in disasm(stream).split('\n'):
			inst = {}
			target = line.split(' ')
			flag = -1
			cnt = 0
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
			self.asm.append(inst)
	
	def nop_padding(self, inst, new_code):
		if len(new_code) < inst['size']:
			rand = random.randrange(inst['size'] - len(new_code) + 1)
			return ("\x90" * rand) + new_code + ("\x90" * (inst['size'] - len(new_code) - rand))
		elif len(new_code) > inst['size']:
			return False
		else:
			return new_code
	
	def substitution(self):
		for inst in self.asm:
			if "mov" in inst['inst']:
				#mov
				code = inst['inst'].split('mov')[1].replace(" ", "")
				src = code.split(",")[1]
				dest = code.split(",")[0]  #mov dest, src
				if "PTR" in src or "PTR" in dest:
					continue  #not serviced
				elif "l" in dest:
					continue  #not serviced
				elif "x" in dest:
					try:
						num = int(src, 16)
					except:
						continue # not serviced
					if num < 256:
						new_code = asm("xor " + dest + ", " + dest + ";" + "mov " + dest[1:].replace("x", "l") + ", " + src) 
						#print new_code
						padded_code = self.nop_padding(inst, new_code)
						#print len(new_code)
						#print len(padded_code)
						#print inst['size']
						if padded_code != False:
							self.stream = self.stream[:inst['addr']] + padded_code + self.stream[inst['addr'] + inst['size']:]
				else:
					continue # not serviced
	def result(self):
		return self.stream
							
			

if __name__ == '__main__':
	stream = open(sys.argv[1], "rb").read()
	point = elfinfo(sys.argv[1]).code_area()
	#print parseasm(stream[point['offset']:point['offset'] + point['size']], 64).substitution()


			
