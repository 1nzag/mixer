import os
import sys
import string
from pwn import *
from elftools.elf.elffile import ELFFile

class elfinfo:
	def __init__(self, filename):
		self.elf = ELFFile(open(filename, "rb"))
		self.section_num = self.elf.header['e_shnum']
		self.arch = self.elf.elfclass # 32, 64
	
	def user_code_area(self):
		for nsec, section in enumerate(self.elf.iter_sections()):
			if section.name == '.text':
				return {'addr':section['sh_addr'], 'offset': section['sh_offset'], 'size': section['sh_size']}
	def code_area(self):
		init = 0
		init_offset = 0
		for nsec, section in enumerate(self.elf.iter_sections()):
			if section.name == '.init':
				init = section['sh_addr']
				init_offset = section['sh_offset']
			elif section.name == '.fini':
				return {'addr': init, 'offset' : init_offset, 'size': section['sh_offset'] - init_offset + section['sh_size']}




if __name__ == '__main__':
	b = open(sys.argv[1], "rb")
	area = elfinfo(sys.argv[1]).code_area()
	stream = b.read()
	#print hexdump(stream[area['offset']:area['offset'] + area['size']])
	#print disasm(stream[area['offset']:area['offset'] + area['size']])
