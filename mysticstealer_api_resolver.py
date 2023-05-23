## IDA Python Script to resolve APIs in Mystic Stealer samples
## Tested on sample SHA256: 7c185697d3d3a544ca0cef987c27e46b20997c7ef69959c720a8d2e8a03cd5dc
## Prerequisites: 
##  - Offset of the function used to resolve the APIs (in the analyzed sample it is sub_00E3AD59 with Base address 0xE20000)
##  - Must run on Windows to have access to the list of DLLs in the System32 directory

import idautils
import pefile

xor_constant = 37801617
r_offset = 0x00E3AD59

modules = [
"C:\\Windows\\System32\\kernel32.dll", 
"C:\\Windows\\System32\\ntdll.dll", 
"C:\\Windows\\System32\\advapi32.dll", 
"C:\\Windows\\System32\\user32.dll",  
"C:\\Windows\\System32\\Ws2_32.dll", 
"C:\\Windows\\System32\\crypt32.dll",
"C:\\Windows\\System32\\gdiplus.dll", 
"C:\\Windows\\System32\\gdi32.dll" 
]


# Returns the hash of the input string
def get_hash(proc_name):
	h = 0
	for i in range(len(proc_name)):
		h = ord(proc_name[i]) ^ (xor_constant * h)
		h = h & 0x0FFFFFFFF # least-significant bits
	return hex(h)


# Receives an hash and returns the corresponding function name
def find_api_name(hash_tofind):
    for dll_path in modules:
        pe = pefile.PE(dll_path)
        # Get hash of all the exported functions in the DLL
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols: 
            if exp.name:
                api_name = exp.name.decode()
                api_hash = get_hash(api_name)
                if api_hash == hash_tofind:
                    return api_name
    return None
    

# Retrieves the value of the registry passed as argument from the specified offeset
def find_value_from_reg(off, register):
    for i in range(1, 301): 
        if i == 300: 
            # Limit to 300 searches to avoid infinite loops
            print("Hash not found for registry: " + registry)
            break
        off = idc.prev_head(off) 
        
        # Gets the operation type (must be a MOV)    
        operation = idc.print_insn_mnem(off) 
        # Gets first operand (must be the specified registry)
        first_operand = idc.print_operand(off, 0)
        # If the instruction is not MOV REG, ??? proceedes backword with the search
        print(operation + " " + first_operand)
        if not (operation == "mov" and (first_operand == register)):
            continue
        # Gets the hash value passed as input to the function    
        return idc.print_operand(off, 1)
    return None


# Adds a comment with the name of the function to be resolved near each call to the resolver function 
def resolve_apis(resolver_offset):
    # Retrieves all the Xrefs to the resolver function
    for xref in idautils.XrefsTo(resolver_offset):
        # Searches backword for the hash passed as input to the resolver function (second argument)
        # Starts at the offset preceding the call to the resolver function
        off = idc.prev_head(xref.frm)
        first_push_found = False
        for i in range(1, 101): 
            if i == 100: 
                # Limit to 100 searches to avoid infinite loops
                print("Hash not found for address: %s" % hex(xref.frm))
                break
            # Gets the operation type (must be PUSH)    
            operation = idc.print_insn_mnem(off) 
            # If the instruction is not PUSH ??? proceedes backword with the search
            if not (operation == "push"):
                off = idc.prev_head(off) 
                continue
            elif (operation == "push" and not first_push_found): # If the instruction is PUSH ??? proceedes backword to find the next PUSH instruction (me need the second argument to the function)
                first_push_found = True
                off = idc.prev_head(off)
                continue
            # Gets the hash value passed as input to the function    
            api_hash = idc.print_operand(off, 0) 
            if api_hash[0] == "e":
                api_hash = find_value_from_reg(off, api_hash)
                    
            # Removes the "h" character in the string representation of the Hex value and converts the result to Hex
            api_hash = hex(int(api_hash[:-1], 16))
            # Finds the function name corresponding to the Hash            
            api_name = find_api_name(api_hash) 
            # Adds a comment near the function invocation with the name of the function to be resolved ("unknown" otherwise)
            comment = "Unknown Function" if not api_name else api_name
            idc.set_cmt(xref.frm, comment, True) 
            break

            


def main(resolver_function):
    resolve_apis(resolver_function)

main(r_offset)
