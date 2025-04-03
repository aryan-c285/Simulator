import os
import sys

# Initialize register and memory state
REGISTER_MAP = {
    "00000": "r0", "00001": "r1", "00010": "r2", "00011": "r3",
    "00100": "r4", "00101": "r5", "00110": "r6", "00111": "r7",
    "01000": "r8", "01001": "r9", "01010": "r10", "01011": "r11",
    "01100": "r12", "01101": "r13", "01110": "r14", "01111": "r15",
    "10000": "r16", "10001": "r17", "10010": "r18", "10011": "r19",
    "10100": "r20", "10101": "r21", "10110": "r22", "10111": "r23",
    "11000": "r24", "11001": "r25", "11010": "r26", "11011": "r27",
    "11100": "r28", "11101": "r29", "11110": "r30", "11111": "r31"
}

REGISTER_STATE = {f"r{i}": "0" for i in range(32)}
REGISTER_STATE["r2"] = "380"  # Initial value for r2

MEMORY_DATA = {f"0x000100{format(i*4, '02X')}": "0" for i in range(32)}
STACK_DATA = {f"0x000001{format(i*4, '02X')}": "0" for i in range(32)}

execution_trace = []

def load_instructions(input_path):
    instruction_set = []
    with open(input_path, "r") as input_file:
        for instruction_line in input_file:
            instruction_set.append(instruction_line.strip())
    return instruction_set

def decode_operation(program_counter, instruction_dict):
    current_instruction = instruction_dict[program_counter]
    funct3 = current_instruction[17:20]
    op = current_instruction[25:32]

    operations = {
        ("000", "0110011"): "add" if current_instruction[:7] == "0000000" else 
                           "sub" if current_instruction[:7] == "0100000" else
                           "mul" if current_instruction[:7] == "0000001" else None,
        ("001", "0000000"): "rst",
        ("010", "0000000"): "halt",
        ("011", "0000000"): "rvrs",
        ("010", "0110011"): "slt",
        ("101", "0110011"): "srl",
        ("110", "0110011"): "or",
        ("111", "0110011"): "and",
        ("000", "0010011"): "addi",
        ("010", "0000011"): "lw",
        ("000", "1100111"): "jalr",
        ("010", "0100011"): "sw",
        ("000", "1100011"): "beq",
        ("001", "1100011"): "bne",
        ("100", "1100011"): "blt",
        ("1101111",): "jal"
    }
    
    for key, val in operations.items():
        if (len(key) == 2 and key == (funct3, op)) or (len(key) == 1 and key[0] == op):
            return val
    return -1

def create_instruction_memory(instruction_list):
    instruction_mem = {}
    counter = 0
    for inst in instruction_list:
        instruction_mem[counter] = inst
        counter += 4
    return instruction_mem

def convert_to_binary(num):
    num = int(num)
    if num < 0:
        binary = format((1 << 32) + num, "032b")
    else:
        binary = format(num, "032b")
    return binary

def complement_to_int(bin_str):
    bits = len(bin_str)
    num = int(bin_str, 2)
    if bin_str[0] == '1':
        num -= 1 << bits
    return num

def int_to_hex(num):
    return f"0x{format(num & 0xFFFFFFFF, '08x')}"

def show_registers(pc, registers):
    state_str = f"0b{convert_to_binary(pc)} "
    state_str += " ".join([f"0b{convert_to_binary(registers[reg])}" for reg in sorted(registers.keys())])
    return state_str

# Operation implementations
def reset_registers():
    for reg in REGISTER_STATE:
        REGISTER_STATE[reg] = "0"

def arithmetic_add(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[dest] = str(int(REGISTER_STATE[src1]) + int(REGISTER_STATE[src2]))
    REGISTER_STATE["r0"] = "0"

def arithmetic_sub(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[dest] = str(int(REGISTER_STATE[src1]) - int(REGISTER_STATE[src2]))
    REGISTER_STATE["r0"] = "0"

def arithmetic_mul(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[dest] = str(int(REGISTER_STATE[src1]) * int(REGISTER_STATE[src2]))
    REGISTER_STATE["r0"] = "0"

def reverse_bits(inst):
    src = REGISTER_MAP[inst[12:17]]
    dest = REGISTER_MAP[inst[20:25]]
    reversed_bits = convert_to_binary(int(REGISTER_STATE[src]))[::-1]
    REGISTER_STATE[dest] = str(complement_to_int(reversed_bits))
    REGISTER_STATE["r0"] = "0"

def set_less_than(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[dest] = "1" if int(REGISTER_STATE[src1]) < int(REGISTER_STATE[src2]) else "0"
    REGISTER_STATE["r0"] = "0"

def shift_right_logical(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    shift_amount = min(int(REGISTER_STATE[src2]), 31)
    REGISTER_STATE[dest] = str(int(REGISTER_STATE[src1]) // (2 ** shift_amount))
    REGISTER_STATE["r0"] = "0"

def bitwise_or(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    result = ""
    for b1, b2 in zip(convert_to_binary(int(REGISTER_STATE[src1])), 
                      convert_to_binary(int(REGISTER_STATE[src2]))):
        result += "1" if b1 == "1" or b2 == "1" else "0"
    REGISTER_STATE[dest] = str(complement_to_int(result))
    REGISTER_STATE["r0"] = "0"

def bitwise_and(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    result = ""
    for b1, b2 in zip(convert_to_binary(int(REGISTER_STATE[src1])), 
                      convert_to_binary(int(REGISTER_STATE[src2]))):
        result += "1" if b1 == "1" and b2 == "1" else "0"
    REGISTER_STATE[dest] = str(complement_to_int(result))
    REGISTER_STATE["r0"] = "0"

def add_immediate(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    imm = complement_to_int(inst[0:12])
    REGISTER_STATE[dest] = str(int(REGISTER_STATE[src1]) + imm)
    REGISTER_STATE["r0"] = "0"

def load_word(inst):
    dest = REGISTER_MAP[inst[20:25]]
    src1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:12])
    mem_addr = int_to_hex(int(REGISTER_STATE[src1]) + offset)
    REGISTER_STATE[dest] = MEMORY_DATA.get(mem_addr, STACK_DATA.get(mem_addr, "0"))
    REGISTER_STATE["r0"] = "0"

def jump_and_link_reg(pc, inst):
    dest = REGISTER_MAP[inst[20:25]]
    REGISTER_STATE[dest] = str(pc + 4)
    REGISTER_STATE["r0"] = "0"

def calculate_jalr_target(pc, inst):
    src1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:12])
    target = int(REGISTER_STATE[src1]) + offset
    target_bin = convert_to_binary(target)
    target_bin = target_bin[:31] + "0"
    return complement_to_int(target_bin)

def store_word(inst):
    src2 = REGISTER_MAP[inst[7:12]]
    src1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:7] + inst[20:25])
    mem_addr = int_to_hex(int(REGISTER_STATE[src1]) + offset)
    if mem_addr in MEMORY_DATA:
        MEMORY_DATA[mem_addr] = REGISTER_STATE[src2]
    else:
        STACK_DATA[mem_addr] = REGISTER_STATE[src2]
    REGISTER_STATE["r0"] = "0"

def branch_equal(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    if REGISTER_STATE[src1] == REGISTER_STATE[src2]:
        return pc + offset
    return pc + 4

def branch_not_equal(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    if REGISTER_STATE[src1] != REGISTER_STATE[src2]:
        return pc + offset
    return pc + 4

def branch_less_than(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    src1 = REGISTER_MAP[inst[12:17]]
    src2 = REGISTER_MAP[inst[7:12]]
    if int(REGISTER_STATE[src1]) < int(REGISTER_STATE[src2]):
        return pc + offset
    return pc + 4

def jump_and_link(pc, inst):
    offset = complement_to_int(inst[0] + inst[12:18] + inst[11] + inst[1:11])
    dest = REGISTER_MAP[inst[20:25]]
    REGISTER_STATE[dest] = str(pc + 4)
    REGISTER_STATE["r0"] = "0"
    target = convert_to_binary(offset + pc)
    target = target[:31] + "0"
    return complement_to_int(target)

def execute_program(instructions, instruction_mem):
    pc = 0
    if instructions[-1] != "00000000000000000000000001100011":
        execution_trace.clear()
        execution_trace.append("Error: Missing halt instruction")
        return

    for _ in range(10000):
        if instruction_mem.get(pc, "") == "00000000000000000000000001100011":
            execution_trace.append(show_registers(pc+4, REGISTER_STATE))
            break
        if pc not in instruction_mem:
            break
            
        current_op = decode_operation(pc, instruction_mem)
        if current_op == -1:
            execution_trace.clear()
            execution_trace.append(f"Error: Invalid instruction at line {(pc//4)+1}")
            break

        operation_handlers = {
            "add": lambda: (arithmetic_add(instruction_mem[pc]), pc + 4),
            "sub": lambda: (arithmetic_sub(instruction_mem[pc]), pc + 4),
            "mul": lambda: (arithmetic_mul(instruction_mem[pc]), pc + 4),
            "rst": lambda: (reset_registers(), pc + 4),
            "rvrs": lambda: (reverse_bits(instruction_mem[pc]), pc + 4),
            "slt": lambda: (set_less_than(instruction_mem[pc]), pc + 4),
            "srl": lambda: (shift_right_logical(instruction_mem[pc]), pc + 4),
            "or": lambda: (bitwise_or(instruction_mem[pc]), pc + 4),
            "and": lambda: (bitwise_and(instruction_mem[pc]), pc + 4),
            "addi": lambda: (add_immediate(instruction_mem[pc]), pc + 4),
            "lw": lambda: (load_word(instruction_mem[pc]), pc + 4),
            "jalr": lambda: (jump_and_link_reg(pc, instruction_mem[pc]), 
                           calculate_jalr_target(pc, instruction_mem[pc])),
            "sw": lambda: (store_word(instruction_mem[pc]), pc + 4),
            "beq": lambda: (None, branch_equal(pc, instruction_mem[pc])),
            "bne": lambda: (None, branch_not_equal(pc, instruction_mem[pc])),
            "blt": lambda: (None, branch_less_than(pc, instruction_mem[pc])),
            "jal": lambda: (None, jump_and_link(pc, instruction_mem[pc])),
            "halt": lambda: (None, None)
        }
        
        handler = operation_handlers.get(current_op)
        if handler:
            result, new_pc = handler()
            if current_op == "halt":
                execution_trace.append(show_registers(pc, REGISTER_STATE))
                break
            if new_pc is not None:
                pc = new_pc
            execution_trace.append(show_registers(pc, REGISTER_STATE))
        else:
            execution_trace.append("Error: Unrecognized instruction")
            break

def write_output(output_path):
    with open(output_path, "w") as out_file:
        # Write execution trace
        execution_trace[-1] = execution_trace[-2]  # Remove last entry (halt)
        for line in execution_trace:
            out_file.write(line + "\n")
        
        # Write memory contents
        out_file.write("")
        for addr in sorted(MEMORY_DATA.keys()):
            val = MEMORY_DATA[addr]
            out_file.write(f"{addr}:0b{convert_to_binary(val)}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python Simulator.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Validate instructions first
    program_instructions = load_instructions(input_file)
    valid_instructions = True
    
    for instruction in program_instructions:
        if len(instruction) != 32:
            execution_trace = [f"Error: Invalid instruction length at line {program_instructions.index(instruction)+1}"]
            valid_instructions = False
            break
    
    if valid_instructions:
        instruction_memory = create_instruction_memory(program_instructions)
        execute_program(program_instructions, instruction_memory)

    write_output(output_file)