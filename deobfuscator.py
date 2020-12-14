import dis, marshal, struct, sys, time, types, binascii, zlib, copy_reg
from pprint import pprint

def substitute(marshaled, swapmap):
    #swapMap = {0: 135, 1: 252, 2: 67, 3: 25, 4: 174, 5: 202, 6: 220, 7: 232, 8: 188, 9: 97, 10: 46, 11: 157, 12: 199, 13: 203, 14: 239, 15: 190, 16: 0, 17: 24, 18: 122, 19: 118, 20: 149, 21: 212, 22: 22, 23: 113, 24: 187, 25: 191, 26: 240, 27: 126, 28: 65, 29: 2, 30: 5, 31: 176, 32: 158, 33: 245, 34: 63, 35: 207, 36: 54, 37: 142, 38: 150, 39: 195, 40: 91, 41: 243, 42: 73, 43: 105, 44: 33, 45: 35, 46: 172, 47: 197, 48: 184, 49: 206, 50: 121, 51: 47, 52: 244, 53: 3, 54: 177, 55: 164, 56: 234, 57: 217, 58: 1, 59: 175, 60: 109, 61: 125, 62: 119, 63: 183, 64: 100, 65: 194, 66: 166, 67: 213, 68: 205, 69: 133, 70: 155, 71: 221, 72: 151, 73: 77, 74: 50, 75: 238, 76: 103, 77: 153, 78: 48, 79: 27, 80: 68, 81: 62, 82: 61, 83: 58, 84: 34, 85: 224, 86: 37, 87: 132, 88: 196, 89: 90, 90: 55, 91: 7, 92: 140, 93: 170, 94: 154, 95: 209, 96: 6, 97: 165, 98: 192, 99: 117, 100: 99, 101: 4, 102: 180, 103: 12, 104: 101, 105: 249, 106: 161, 107: 40, 108: 87, 109: 231, 110: 241, 111: 218, 112: 215, 113: 181, 114: 82, 115: 9, 116: 84, 117: 128, 118: 32, 119: 141, 120: 214, 121: 38, 122: 57, 123: 156, 124: 168, 125: 219, 126: 228, 127: 178, 128: 163, 129: 179, 130: 88, 131: 83, 132: 169, 133: 92, 134: 114, 135: 13, 136: 236, 137: 41, 138: 200, 139: 254, 140: 110, 141: 233, 142: 138, 143: 49, 144: 104, 145: 146, 146: 251, 147: 131, 148: 246, 149: 94, 150: 167, 151: 80, 152: 222, 153: 137, 154: 96, 155: 147, 156: 64, 157: 66, 158: 210, 159: 129, 160: 225, 161: 242, 162: 17, 163: 173, 164: 89, 165: 255, 166: 56, 167: 143, 168: 148, 169: 51, 170: 201, 171: 29, 172: 120, 173: 108, 174: 186, 175: 162, 176: 127, 177: 60, 178: 106, 179: 39, 180: 30, 181: 248, 182: 230, 183: 107, 184: 247, 185: 86, 186: 21, 187: 85, 188: 124, 189: 144, 190: 139, 191: 185, 192: 130, 193: 19, 194: 171, 195: 75, 196: 10, 197: 193, 198: 43, 199: 45, 200: 226, 201: 42, 202: 23, 203: 98, 204: 31, 205: 198, 206: 160, 207: 71, 208: 112, 209: 208, 210: 26, 211: 227, 212: 145, 213: 152, 214: 76, 215: 235, 216: 134, 217: 189, 218: 123, 219: 8, 220: 115, 221: 74, 222: 20, 223: 11, 224: 59, 225: 111, 226: 136, 227: 250, 228: 223, 229: 70, 230: 78, 231: 81, 232: 159, 233: 15, 234: 102, 235: 182, 236: 16, 237: 116, 238: 204, 239: 216, 240: 53, 241: 44, 242: 93, 243: 79, 244: 72, 245: 28, 246: 237, 247: 211, 248: 69, 249: 52, 250: 14, 251: 253, 252: 36, 253: 18, 254: 229, 255: 95}
    marshaled = ('').join(map(chr, [ swapmap[ord(n)] for n in marshaled ]))
    return marshaled

def decode(code, swapmap):
    co_code = [ chr(((byte ^ 38) & 126 | (byte ^ 38) >> 7 & 1 | ((byte ^ 38) & 1) << 7) ^ 89) for byte in [ ord(byte) for byte in substitute(code, swapmap) ] ]
    return co_code

def dump_codeobj(name, codeobj, attempt_marshal):
    f = open(name, "wb")
    f.write(struct.pack("L",168686339))
    f.write(struct.pack("L",1603312128))
    if (attempt_marshal):
        marshal.dump(codeobj, f)
    else:
        f.write(codeobj)





def nop_dead_code(code, aliveoffsets):
    for x in range(len(code)):
        if (x not in aliveoffsets):
            code[x] = 9 #nop that bitch
            #print("nopped", x)
    return code

def traverse_alive_paths(code, offset, aliveoffsets):
    while (True):
        #eof?
        if (offset >= len(code)):
            print("eof ",offset, len(code))
            return aliveoffsets

        #check if we where here before
        if (offset in aliveoffsets):
            #print("ret, been here")
            return aliveoffsets
        else:
            aliveoffsets.add(offset)



        #get opcode
        opcode = (code[offset])
        #print("offset ", offset, ", opcode ", opcode)
        argument = 0
        offset += 1
        if (opcode > 90):
            #add these offsets to list of alive too
            aliveoffsets.add(offset)
            aliveoffsets.add(offset+1)
            argument = ((code[offset+1]) << 8) | (code[offset])
            offset += 2
            

        #check if the opcode is some sort of jump

        #JUMP_FORWARD   110
        #JUMP_IF_FALSE_OR_POP 111
        #JUMP_IF_TRUE_OR_POP 112
        #JUMP_ABSOLUTE  113
        #POP_JUMP_IF_FALSE 114
        #POP_JUMP_IF_TRUE 115
        #FOR_ITER    93

        branchopcodes = [110,111,112,113,114,115,93]
        #branchopcodes = [113,110]
        if (opcode in branchopcodes):
            #print("branch ", offset)

            targetoffset = argument #absolute by default

            if ((opcode == 110) or (opcode == 93)):
                targetoffset += offset #relative for these

            aliveoffsets.union(traverse_alive_paths(code, targetoffset, aliveoffsets))

            if (opcode == 113) or (opcode == 110):
                return aliveoffsets

            # test
            #if (opcode == 115):
            #    return aliveoffsets

            
        if (opcode == 83): #return
            return aliveoffsets


def get_broken_offset(namearray):
    #it seems that all consts that contain a space are bad
    #if type(namearray) == types.CodeType:
    #    print("fix const skipped because its a code object")
    #    return -1

    invalidafter = 0
    for valuename in namearray:
        if (type(valuename) ==  types.StringType):
            if (" " not in valuename):
                invalidafter += 1
            else:
                return invalidafter
        else:
            invalidafter += 1

    return invalidafter


    return

def fix_codeobj_bytecode(bytecode):
    print("fixing bytecode len ", len(bytecode))
    bytecodearray = bytearray(bytecode)
    filledknown = traverse_alive_paths(bytecodearray, 0, set())
    #print("traversed offsets", filledknown)
    fixed_code_block = (nop_dead_code(bytecodearray, filledknown))
    # code_fixed = types.CodeType(codeobj.co_argcount, 
    #     codeobj.co_nlocals, 
    #     codeobj.co_stacksize,
    #     codeobj.co_flags,
    #     str(fixed_code_block),
    #     codeobj.co_consts,
    #     codeobj.co_names, 
    #     codeobj.co_varnames, 
    #     codeobj.co_filename,
    #     codeobj.co_name, 
    #     codeobj.co_firstlineno, 
    #     codeobj.co_lnotab,
    #     codeobj.co_freevars, 
    #     codeobj.co_cellvars)
    return fixed_code_block

def fix_all_codeobj(root_codeobj):
    #code
    fixed_code = fix_codeobj_bytecode(root_codeobj.co_code)
    #consts
    col = list(root_codeobj.co_consts)
    c = 0
    for const in col:
        if type(const) == types.CodeType:
            col[c] = fix_all_codeobj(const)
        c += 1

    #fix consts
    # print("const array before fix", col)
    # cut_consts = col[:get_broken_offset(col)]
    # print("const array after  fix", cut_consts)

    # #fix names
    # varnames = list(root_codeobj.co_varnames)
    # print("varname array before fix",varnames)
    # cut_varnames = varnames[:get_broken_offset(varnames)]
    # print("varname array after  fix", cut_varnames)


    return types.CodeType(root_codeobj.co_argcount, 
        root_codeobj.co_nlocals, 
        root_codeobj.co_stacksize,
        root_codeobj.co_flags,
        str(fixed_code),
        tuple(col), #root_codeobj.co_consts,
        root_codeobj.co_names, 
        root_codeobj.co_varnames, 
        root_codeobj.co_filename,
        root_codeobj.co_name, 
        0,
        "",
        #root_codeobj.co_firstlineno, 
        #root_codeobj.co_lnotab,
        root_codeobj.co_freevars, 
        root_codeobj.co_cellvars)


def deobfuscate_codeobj(codeobj):
    size_code = len(codeobj.co_code)
    size_const = len(codeobj.co_consts[3])
    print(size_code)
    print(size_const)

    encrypted_code = codeobj.co_code[:]
    #print("key OTP from code section:", binascii.hexlify(codeobj.co_code[:]))
    #print("encrypted actual code:", binascii.hexlify(codeobj.co_consts[3]))

    decrypted_const = []
    for x in range(size_const):
        decrypted_const.append(ord(codeobj.co_consts[3][x]) ^ ord(encrypted_code[x % size_code]))
    base64 = ''.join(chr(e) for e in decrypted_const)
    #print("base64_stage1:", base64)
    decoded_decompressed = zlib.decompress(binascii.a2b_base64(base64))
    #print("decrypted actual code:", binascii.hexlify(decoded_decompressed))
    dumped_codeobj = marshal.loads(decoded_decompressed);

    #fixed_codeobj = fix_all_codeobj(dumped_codeobj)

    #print(fixed_codeobj)

    #print("fixed block",fixed_code_block) 
    #dump_codeobj("fixed_code_block.pyc", fixed_codeobj, True)
    dump_codeobj("decrypted_stage1.pyc", dumped_codeobj, True);
    

    #get swapmap
    swapmap = dumped_codeobj.co_consts[8].co_consts[1]
    print("swapmap", swapmap)

    decrypted_code = decode(codeobj.co_code[::-1],swapmap) #invert the code buffer using ::-1
    #print("decrypted pyc object:", decrypted_code)
    code_string = (''.join(str(e) for e in decrypted_code))
    dump_codeobj("decrypted_stage2.pyc", code_string , True)

    #extract b64 string yet again
    stage2_b64 = code_string[0x9d:code_string.find("\x28\x07\x00\x00\x00")][::-1]

    print("stage2 base64", stage2_b64)

    decoded_decompressed_stage3 = zlib.decompress(binascii.a2b_base64(stage2_b64))

    dump_codeobj("decrypted_stage3.pyc", marshal.loads(decoded_decompressed_stage3) , True)

    devoooo = marshal.loads(decoded_decompressed_stage3)
    dump_codeobj("singlefunction.pyc",fix_all_codeobj(devoooo.co_consts[4]), True)

    fixed_codeobj = fix_all_codeobj(marshal.loads(decoded_decompressed_stage3))

    dump_codeobj("decrypted_stage3_fixed.pyc", fixed_codeobj , True)

    #print("dumped pyc object:")
    

    #return

    #pprint(dir(dumped_codeobj))
    #pprint(dir(dumped_codeobj.co_freevars))

    #this is what client does for some reason
    
    #constlist = list(codeobj.co_consts)
    #constlist[1] = dumped_codeobj
    #code_fixed = type(codeobj)(codeobj.co_argcount, codeobj.co_nlocals, codeobj.co_stacksize,codeobj.co_flags, codeobj.co_code[4:], tuple(constlist),codeobj.co_names, codeobj.co_varnames, codeobj.co_filename,codeobj.co_name, codeobj.co_firstlineno, codeobj.co_lnotab,codeobj.co_freevars, codeobj.co_cellvars)
    #print("local count in fixed:",code_fixed.co_nlocals)
    #print(dis.dis(code_fixed))


    
    #dump_codeobj("decrypted_semi_fixed.pyc", code_fixed, True);



    #marshal.dump(codeobj, "teeessstttt");
    return


def load_code_obj(f):
    b = f.read()
    #print(b)
    codeobj = marshal.loads(b)
    
    pprint(dir(codeobj))
    deobfuscate_codeobj(codeobj)


def load_pyc(f):
    magic = f.read(4)
    moddate = f.read(4)
    header = [magic, moddate]
    modtime = time.asctime(time.localtime(struct.unpack('L', moddate)[0]))
    print("magic %s" % binascii.hexlify(magic))
    print("moddate %s (%s)" % (binascii.hexlify(moddate), modtime))
    #now comes code object, which we need to parse
    load_code_obj(f)

print(sys.argv[1])
f = open(sys.argv[1], "rb")
load_pyc(f)