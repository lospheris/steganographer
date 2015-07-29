import sys

def triple_to_int( triple ):
	
	__return_int = 0
	if len(triple) != 3:
		raise ValueError("The touple provided has too many elements!")
	for character in triple:
		__return_int |= ord(character)
		if character == triple[2]:
			break
		else:
			__return_int = __return_int << 8
	if sys.getsizeof(__return_int) > 24:
		raise ValueError("Something has caused the output integer to be too large!")
	return __return_int

def int_to_triple( integer ):
	
	return (chr((integer&0xFF0000)>>16), chr((integer&0x00FF00)>>8), chr((integer&0x0000FF)))

def string_to_int_list( input_string ):
	
	# Pad the string to make sure it fits evenly into integers
	input_string += "=" * (len(input_string)%3)
	
	__int_list = []
	
	for index in range(0, len(input_string)/3):
		proper_index = index*3
		__int_list.append(triple_to_int((input_string[proper_index], input_string[proper_index+1], input_string[proper_index+2])))
	return __int_list

def int_list_to_string( input_list ):
	
	__return_string = ""
	
	for integer in input_list:
		__char_tuple = int_to_triple(integer)
		__return_string += __char_tuple[0] + __char_tuple[1] + __char_tuple[2]
	return __return_string

if __name__ == "__main__":
	
	int_list = string_to_int_list("The quick brown fox jumped over the lazy dog!")

	print(int_list_to_string(int_list))
