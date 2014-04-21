#Copyright Tabish Siddiqui

#!/usr/bin/env python

#Import statements, re for regular expressions, Tkinter for GUI
import re
from Tkinter import *
from tkFileDialog import askopenfilename

#Matches a label (starts at the beginning of the line, and is alphanumeric, _ or .
labelRe = re.compile("^([.a-z_0-9$]+)", re.IGNORECASE)
#Everything after the label
notLabelRe = re.compile("^[.a-z_0-9$:]*\s+(.*)", re.IGNORECASE)
#Offset if present in [edx + 12], matches 12
offsetRe = re.compile("\D*(\d+)")

#All of the labels we have encountered (empty to start with)
labels = {}

class Label:
    """Creates a label, that holds an address, it acts as an opcode
        during 2nd pass, so bytes returns an empty sequence, since
        a label generates no code"""

    def __init__(self, name, defined):
        """Name is the name of the label, and defined is the line# the label defined in"""
        self.name = name
        self.defined = defined
        self.address = 0        #The address of the label
        self.src = ''           #The source code of the label definition

    def update(self, address):
        """address is used to set the address the label refers to"""
        self.address = address
        return address

    def bytes(self):
        """Used when generating data, this allows it to be treated as an opcode"""
        return []

def label(name, defined = 0):
    """Creates a label, if one does not already exist with that name, thus allows
    for forward references, so jmp notyetdefined .... notyetdefined: ..., creates
    the label notyetdefined, and the address is updated when it is encountered the
    next time"""

    if name not in labels:
        labels[name] = Label(name, defined)

    return labels[name]

class Register:
    """A register, maps the registers to a number, but it alos handles constants,
    indirect access with an optional offset"""

    def __init__(self, name, num, width):
        """name is the name of the register, num is the value associated with the
        register (or the constant value, width is size of the register in bits,
        such as EAX being a 32 bit value, and AX being 16 bits"""
        self.name = name
        self.num = num
        self.width = width
        self.indirect = False       #true if something like [EBP + 12]
        self.offset = 0             #offset is 12 if the register was [EBP + 12]
        self.constant = False       #true if the register represents a constant value

#List of predefined registers, this is more than is needed for the demo used
#but allows for fully implementing a 80x86 assembler
Registers = {
             'eax' : Register('eax', 0, 32),
             'ecx' : Register('ecx', 1, 32),
             'edx' : Register('edx', 2, 32),
             'ebx' : Register('ebx', 3, 32),
             'esp' : Register('esp', 4, 32),
             'ebp' : Register('ebp', 5, 32),
             'esi' : Register('esi', 6, 32),
             'edi' : Register('edi', 7, 32),
             'ax' : Register('ax', 0, 16),
             'cx' : Register('cx', 1, 16),
             'dx' : Register('dx', 2, 16),
             'bx' : Register('bx', 3, 16),
             'sp' : Register('sp', 4, 16),
             'bp' : Register('bp', 5, 16),
             'si' : Register('si', 6, 16),
             'di' : Register('di', 7, 16),
             'al' : Register('al', 0, 8),
             'cl' : Register('cl', 1, 8),
             'dl' : Register('dl', 2, 8),
             'bl' : Register('bl', 3, 8),
             'ah' : Register('ah', 0, 8),
             'ch' : Register('ch', 1, 8),
             'dh' : Register('dh', 2, 8),
             'bh' : Register('bh', 3, 8),
}

def register(reg):
    """Return a regustger for a string, so eax returns the instance
    of 'eax' in Registers, and '[edx]' retuns a register with the value
    of 'edx', with offset = 0 and indirect = true, 34 returns a register
    with the constant = true, and num = 34"""

    if reg in Registers:            #It always returns the same register instance for the same string
        return Registers[reg]

    start = reg.find('[')           #Check if [ is present (an indirect register access)
    if start >= 0:
        end = reg.find(']')
        reg = reg[start:end+1]      #Remove the text outside the [] (so DWORD PTR [ebx] becoems [ebx]
        negative = '-' in reg       #Check if the numeric offset is negative number
        indirect = reg[1:-1].strip()    #Get the inner connects
        offset = 0                  #Assume no offset
        match = offsetRe.match(indirect)    #Check for number
        if match:                   #If one was found
            offset = int(match.group(1))    #Convert it into an integer
        if indirect[:3] in Registers:   #Are the first first 3 characters a register definition eax, ebp, etc
            reg = indirect[:3]
        else:                           #No, so we are dealing with al, ax, etc
            reg = indirect[:2]
        indirect = '[' + reg            #convert it into canonical form so [ebp + 12] becomes [ebp+12]
        if offset:                      #if offset is not zero
            if negative:                #was it negative?
                offset = -offset        #yes, so the offset should be a negative value
                indirect += str(offset) #add to the string
            else:
                indirect += '+' + str(offset)   #need a plus and the offset
        indirect += ']'
        #print "Register:" + reg        #debug display code
        #print "Indirect:" + indirect
        #print "Offset:", offset
        if indirect in Registers:       #have we already encounted the canonical form?
            return Registers[indirect]  #yes, return it
        base = Registers[reg]           #get the register num
        update = Register(base.name, base.num, base.width)  #create a new register based on the original
        update.indirect = True          #mark it as indirect access
        update.offset = offset & 0xff   #the offset should be 1 byte, so and with 0xff
        Registers[indirect] = update    #add this to the list of registers, so it can be reused
        return update                   #return the version we juist created
    constant = Register(reg, int(reg) & 0xff, 8)    #we only allow constants that are 1 byte (this could be extended)
    constant.constant = True            #mark it as a constant
    Registers[reg] = constant           #and to the list of registers
    return constant                     #and return the value

class Opcode:
    """Represents an opcode"""
    def __init__(self, name, src):
        """Name of the ofpcde, and src is the line where it was defined, so we can display in second pass"""

        self.name = name
        self.byte_sequence = [] #the bytes generated by the opcode
        self.address = 0        #the address where the instruction occurs
        self.label = None       #label the opcode refers to (used when generating bytes)
        self.long_jump = False  #is the branch more than 1 byte in size (eg a call instruction)
        self.src = src          #the original line with the opcode defined

    def bytes(self):
        """return the encoded form of the instruction, if there is a label defined, then modified version"""
        if self.label:
            if self.long_jump:  #if it was a long jump, then it is 4th byte from the end (we only are compiling
                                #a small program, so branches are in 1 byte, but since it is little endian
                                #the offsets start at -4
                self.byte_sequence[-4] = int(self.label.address - self.address - len(self.byte_sequence)) & 0xff
            else:
                #Updates the branch, we have to take into account the instruction length, which is why it
                #refers to len(self.byte_sequence), we can't use len(self.bytes()) as that would be recursive call
                self.byte_sequence[-1] = int(self.label.address - self.address - len(self.byte_sequence)) & 0xff
        return self.byte_sequence

    def update(self, address):
        """Updates the address of the opcode, with the address, and returns the new addfress"""
        self.address = address
        return address + len(self.bytes())

    def encode(self, opcode, prefix = [], postfix = [], label = None, long_jump = False):
        """Encode the instruction, opcode is the byte for the instruction, prefix are a list
        of prefix bytes, none are used in the instructions used in this sample program,
        postfix includes all of the arguements encoded, label is the label used in the
        instruction (if any), and long_jump is set if the label refers to a 32 bit offset."""
        for byte in prefix:
            self.byte_sequence.append(byte)     #add prefix bytes first
        self.byte_sequence.append(opcode)       #add the opcode to the sequence
        for byte in postfix:                    #add each byte for the arguments
            self.byte_sequence.append(byte)
        self.label = label                      #add a reference to the label (if any)
        self.long_jump = long_jump              #and whether it was a long instruction

"""Routines to encode individual instructions, since they are called using a
function pointer, they take the opcode, and left and right argument"""

def push(opcode, left, right):
    """push eax, ebx, etc are single byte with 0x50 + register index)"""
    opcode.encode(0x50 + register(left).num)

def mov(opcode, left, right):
    """mov has a few version used, so we check if either is an indirect value"""
    leftReg = register(left)
    rightReg = register(right)
    if leftReg.indirect or rightReg.indirect:
        if leftReg.indirect:
            if rightReg.constant:
                #for encoding mov 	DWORD PTR [ebp-4], 1
                opcode.encode(0xc7, [], [0x40 | leftReg.num, leftReg.offset, rightReg.num, 0, 0, 0])
            else:
                #for encoding mov 	DWORD PTR [ebp-12], eax
                opcode.encode(0x89, [], [0x40 | (rightReg.num << 3) | leftReg.num, leftReg.offset])
        else:
            #for encoding mov 	eax, DWORD PTR [ebp-8]
            opcode.encode(0x8b, [], [0x40 | (leftReg.num << 3) | rightReg.num, rightReg.offset])
    else:
        #for encoding mov eax, edx
        opcode.encode(0x8b, [], [0xc0 | (leftReg.num << 3) | rightReg.num])

def add(opcode, left, right):
    """Encoding the add instruction"""
    leftReg = register(left)
    rightReg = register(right)
    if leftReg.indirect or rightReg.indirect:
        if leftReg.indirect:
            pass
        else:
            #For encoding add 	eax, DWORD PTR [ebp-12]
            opcode.encode(0x03, [], [0x40 | (leftReg.num << 3) | rightReg.num, rightReg.offset])
        pass
    else:
        if rightReg.constant:
            #add 	esp, -12
            opcode.encode(0x83, [], [0xc0 | leftReg.num, rightReg.num])

def cmp(opcode, left, right):
    """Encoding the cmp instruction"""
    leftReg = register(left)
    rightReg = register(right)
    if leftReg.offset and rightReg.constant:
        #cmp 	DWORD PTR [ebp + 8], 2
        opcode.encode(0x83, [], [0x78 | leftReg.num, leftReg.offset, rightReg.num])

def jl(opcode, left, right):
    """Encoding the jl instruction"""
    offset = label(left)    #create a reference to the label
    opcode.encode(0x7c, [], [0], label = offset)

def dec(opcode, left, right):
    """dec eax, ebx, etc are single byte with 0x48 + register index)"""
    opcode.encode(0x48 + register(left).num)


def call(opcode, left, right):
    """Encoding the jl instruction"""
    offset = label(left)    #create a reference to the label
    offset.wide = True      #the label offset should be 4 bytes instead of 1 byte
    opcode.encode(0xe8, [], [0, 0xff, 0xff, 0xff], label = offset, long_jump  =True)

def pop(opcode, left, right):
    """push eax, ebx, etc are single byte with 0x50 + register index)"""
    opcode.encode(0x58 + register(left).num)

def ret(opcode, left, right):
    #Encode the ret instruction"""
    opcode.encode(0xc3)

def jmp(opcode, left, right):
    #Encode the jmp instruction"""
    offset = label(left)
    opcode.encode(0xeb, [], [0], label = offset)

def ignore(opcode, left, right):
    """For assembler stuff such as PROC, ENDP"""
    return True

#All of the opcodes we have encoded, and the routine to call
Opcodes = {
            'push' : push,
            'mov' : mov,
            'add' : add,
            'cmp' : cmp,
            'jl' : jl,
            'dec' : dec,
            'call' : call,
            'pop' : pop,
            'ret' : ret,
            'jmp' : jmp,
            'proc' : ignore,
            'endp' : ignore,
}

def part(line, expr):
    """Return the part of the line matching the regular expression"""
    match = expr.match(line)
    if match:
        return match.group(1)
    return ''

def assemble(filename):
    """Assemble a file with the path filename"""
    output = []     #The output that would be printed to the screen (for the GUI interface)
    code = []       #The opcodes and labels
    with open(filename, "rU") as src:       #Open the file (rU means work the same with Windows or Linux line endings)
        address = 0         #The current address
        for linenum,line in enumerate(src):     #Get the linenum and line for each line in the file
            original = line.rstrip()        #Remove spaces at the right end (left end spaces are significant)
            comment = line.find(';')        #If there a comment
            if (comment >= 0):
                line = line[:comment]       #Strip out the comment
            line = line.rstrip()    #whitespace at start is significant
            if not line.strip():    #completely blank line, so ignore it
                continue
            line = line.lower()     #make the line into lower case
            label_name = part(line, labelRe)    #get the name of the label
            if label_name:          #if there was a label
                add_label = label(label_name, linenum + 1)  #add the label
                add_label.update(address)   #and set the address
                if not add_label.src:       #add it to the src (main PROC, main ENDP are the reason for the check for .src
                    add_label.src = original        #the unmodified line for the listing
                code.append(add_label)      #add the label the listing
            line = part(line, notLabelRe)       #get the contents of the line not including the label
            instruction = part(line, labelRe)   #get the forst word in the line, which must be the opcode
            if instruction:                 #unless it was a blank line, so check that
                line = line[len(instruction):]  #get the rest of the line (ignore the instruction)
                parts = line.split(',')     #get the parts of the line
                arg1 = ''
                arg2 = ''
                if parts:                   #if we have any arguments (eg ret, would not have any)
                    arg1 = parts[0].strip() #get the first argument
                if len(parts) > 1:          #it must be mov eax, edx or something similar
                    arg2 = parts[1].strip() #get the seocond argument
                opcode = Opcode(instruction, original)  #make an instruction
                if not Opcodes[instruction](opcode, arg1, arg2):    #if it was not an assembler directive
                    code.append(opcode)      #add it the the list of instructions
                address = opcode.update(address)    #Update the address of the opcode, and get the new address
                #bytes = opcode.bytes()
                #print "%s:\t%s\t%s,%s" % (label_name, instruction, arg1, arg2)
                #print " ".join("{:02x}".format(c) for c in bytes)

    exefile = '.'.join(filename.split('.')[:-1]) + ".exe"   #create .exe file with name of source file
    with open(exefile, "wb") as f:      #create file
        for opcode in code:             #for each opcode
            output.append(opcode.src)   #print opcode.src
            bytes = opcode.bytes()      #get the bytes the make up the instruciton
            for byte in bytes:          #for each byte in the sequence
                f.write(chr(byte))      #write it to the file
            #Append to the output the hex format 3A 46 04 BA for example
            output.append(" ".join("{:02x}".format(c) for c in bytes))

    return output   #For displaying GUI form

def gui():
    """Create a simple GUI"""
    root = Tk() # initialize Tkinter
    scrollbar = Scrollbar(root) #We want a scroll bar for the text
    assembled = Text(root, height=30, width=140)    #We want a window to display the text
    scrollbar.pack(side=RIGHT, fill=Y)          #The scroll bar should be on the right
    assembled.pack(side=LEFT, fill=Y)           #The text should be on the left
    scrollbar.config(command=assembled.yview)       #The scrollbar should link to the assembled view
    source = askopenfilename(title='Select .asm source code file')  #Select file to assemble
    assembled.config(yscrollcommand=scrollbar.set)  #The text window should use scrollbar
    output = assemble(source)                   #assemble the code

    assembled.insert(0.0,"\n".join(output)) #display the results
    assembled.pack(expand=1, fill=BOTH) # show the widget

    root.mainloop() #and let the user view the results

if __name__ == "__main__":
    gui()   #call the gui, if the module is the main module (ie not imported)
    #assemble("fib.asm")
