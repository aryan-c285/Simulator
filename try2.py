import sys

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
REGISTER_STATE["r1"] = "16"
REGISTER_STATE["r2"] = "380"
REGISTER_STATE["r10"] = "5"
REGISTER_STATE["r14"] = "0"

MEMORY_DATA = {f"0x000100{format(i*4,'02X')}": "0" for i in range(32)}
STACK_DATA = {f"0x000001{format(i*4,'02X')}": "0" for i in range(32)}
execution_trace = []

def load_instructions(input_path):
    with open(input_path, "r") as input_file:
        return [line.strip() for line in input_file if line.strip()]

def decode_operation(pc, inst_dict):
    inst = inst_dict[pc]
    funct3 = inst[17:20]
    op = inst[25:32]
    
    operations = {
        ("000", "0110011"): "add" if inst[:7] == "0000000" else 
                            "sub" if inst[:7] == "0100000" else
                            "mul" if inst[:7] == "0000001" else None,
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

def create_instruction_memory(instructions):
    return {i*4: inst for i, inst in enumerate(instructions)}

def convert_to_binary(num):
    num = int(num)
    return format(num if num >= 0 else (1 << 32) + num, "032b")

def complement_to_int(bin_str):
    num = int(bin_str, 2)
    return num if bin_str[0] == '0' else num - (1 << len(bin_str))

def int_to_hex(num):
    return f"0x{format(num & 0xFFFFFFFF, '08x')}"

def show_registers(pc, registers):
    pc_bin = f"0b{convert_to_binary(pc)}"
    regs_bin = " ".join([f"0b{convert_to_binary(registers[f'r{i}'])}" for i in range(32)])
    return f"{pc_bin} {regs_bin}"

def reset_registers():
    global REGISTER_STATE
    REGISTER_STATE = {f"r{i}": "0" for i in range(32)}
    REGISTER_STATE["r1"] = "0"
    REGISTER_STATE["r2"] = "0"
    REGISTER_STATE["r10"] = "5"
    REGISTER_STATE["r14"] = "0"

def arithmetic_add(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[rd] = str(int(REGISTER_STATE[rs1]) + int(REGISTER_STATE[rs2]))
    REGISTER_STATE["r0"] = "0"

def arithmetic_sub(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[rd] = str(int(REGISTER_STATE[rs1]) - int(REGISTER_STATE[rs2]))
    REGISTER_STATE["r0"] = "0"

def arithmetic_mul(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[rd] = str(int(REGISTER_STATE[rs1]) * int(REGISTER_STATE[rs2]))
    REGISTER_STATE["r0"] = "0"

def reverse_bits(inst):
    rs1 = REGISTER_MAP[inst[12:17]]
    rd = REGISTER_MAP[inst[20:25]]
    reversed_bits = convert_to_binary(int(REGISTER_STATE[rs1]))[::-1]
    REGISTER_STATE[rd] = str(complement_to_int(reversed_bits))
    REGISTER_STATE["r0"] = "0"

def set_less_than(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    REGISTER_STATE[rd] = "1" if int(REGISTER_STATE[rs1]) < int(REGISTER_STATE[rs2]) else "0"
    REGISTER_STATE["r0"] = "0"

def shift_right_logical(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    shift = min(int(REGISTER_STATE[rs2]), 31)
    REGISTER_STATE[rd] = str(int(REGISTER_STATE[rs1]) >> shift)
    REGISTER_STATE["r0"] = "0"

def bitwise_or(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    result = int(REGISTER_STATE[rs1]) | int(REGISTER_STATE[rs2])
    REGISTER_STATE[rd] = str(result)
    REGISTER_STATE["r0"] = "0"

def bitwise_and(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    result = int(REGISTER_STATE[rs1]) & int(REGISTER_STATE[rs2])
    REGISTER_STATE[rd] = str(result)
    REGISTER_STATE["r0"] = "0"

def add_immediate(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    imm = complement_to_int(inst[0:12])
    REGISTER_STATE[rd] = str(int(REGISTER_STATE[rs1]) + imm)
    REGISTER_STATE["r0"] = "0"

def load_word(inst):
    rd = REGISTER_MAP[inst[20:25]]
    rs1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:12])
    addr = int_to_hex(int(REGISTER_STATE[rs1]) + offset)
    REGISTER_STATE[rd] = MEMORY_DATA.get(addr, STACK_DATA.get(addr, "0"))
    REGISTER_STATE["r0"] = "0"

def jump_and_link_reg(pc, inst):
    rd = REGISTER_MAP[inst[20:25]]
    REGISTER_STATE[rd] = str(pc + 4)
    REGISTER_STATE["r0"] = "0"

def calculate_jalr_target(pc, inst):
    rs1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:12])
    target = int(REGISTER_STATE[rs1]) + offset
    return target & ~1

def store_word(inst):
    rs2 = REGISTER_MAP[inst[7:12]]
    rs1 = REGISTER_MAP[inst[12:17]]
    offset = complement_to_int(inst[0:7] + inst[20:25] + "0")
    addr = int_to_hex(int(REGISTER_STATE[rs1]) + offset)
    if addr in MEMORY_DATA:
        MEMORY_DATA[addr] = REGISTER_STATE[rs2]
    else:
        STACK_DATA[addr] = REGISTER_STATE[rs2]
    REGISTER_STATE["r0"] = "0"

def branch_equal(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    return pc + (offset if REGISTER_STATE[rs1] == REGISTER_STATE[rs2] else 4)

def branch_not_equal(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    return pc + (offset if REGISTER_STATE[rs1] != REGISTER_STATE[rs2] else 4)

def branch_less_than(pc, inst):
    offset = complement_to_int(inst[0] + inst[24] + inst[1:7] + inst[20:24] + "0")
    rs1 = REGISTER_MAP[inst[12:17]]
    rs2 = REGISTER_MAP[inst[7:12]]
    return pc + (offset if int(REGISTER_STATE[rs1]) < int(REGISTER_STATE[rs2]) else 4)

def jump_and_link(pc, inst):
    offset = complement_to_int(inst[0] + inst[12:18] + inst[11] + inst[1:11] + "0")
    rd = REGISTER_MAP[inst[20:25]]
    REGISTER_STATE[rd] = str(pc + 4)
    REGISTER_STATE["r0"] = "0"
    return pc + offset

def execute_program(instructions, inst_mem):
    pc = 0
    if not instructions or instructions[-1] != "00000000000000000000000001100011":
        execution_trace.append("Error: Missing halt instruction")
        return

    for _ in range(10000):
        if pc not in inst_mem:
            break
            
        inst = inst_mem[pc]
        if inst == "00000000000000000000000001100011":  # halt
            execution_trace.append(show_registers(pc + 4, REGISTER_STATE))
            break
            
        op = decode_operation(pc, inst_mem)
        if op == -1:
            execution_trace.append(f"Error: Invalid instruction at PC {pc}")
            break

        handlers = {
            "add": (lambda: arithmetic_add(inst), lambda: pc + 4),
            "sub": (lambda: arithmetic_sub(inst), lambda: pc + 4),
            "mul": (lambda: arithmetic_mul(inst), lambda: pc + 4),
            "rst": (reset_registers, lambda: pc + 4),
            "rvrs": (lambda: reverse_bits(inst), lambda: pc + 4),
            "slt": (lambda: set_less_than(inst), lambda: pc + 4),
            "srl": (lambda: shift_right_logical(inst), lambda: pc + 4),
            "or": (lambda: bitwise_or(inst), lambda: pc + 4),
            "and": (lambda: bitwise_and(inst), lambda: pc + 4),
            "addi": (lambda: add_immediate(inst), lambda: pc + 4),
            "lw": (lambda: load_word(inst), lambda: pc + 4),
            "jalr": (lambda: jump_and_link_reg(pc, inst), lambda: calculate_jalr_target(pc, inst)),
            "sw": (lambda: store_word(inst), lambda: pc + 4),
            "beq": (None, lambda: branch_equal(pc, inst)),
            "bne": (None, lambda: branch_not_equal(pc, inst)),
            "blt": (None, lambda: branch_less_than(pc, inst)),
            "jal": (None, lambda: jump_and_link(pc, inst)),
            "halt": (None, None)
        }
        
        action, next_pc = handlers.get(op, (None, None))
        if action: 
            action()
        
        if next_pc is None:  # halt
            execution_trace.append(show_registers(pc + 4, REGISTER_STATE))
            break
            
        pc = next_pc()
        execution_trace.append(show_registers(pc, REGISTER_STATE))

def write_output(output_path):
    with open(output_path, "w") as f:
        f.write("\n".join(execution_trace) + "\n")
        for addr in sorted(MEMORY_DATA):
            f.write(f"{addr}:0b{convert_to_binary(MEMORY_DATA[addr])}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python Simulator.py <input_file> <output_file>")
        sys.exit(1)
        
    instructions = load_instructions(sys.argv[1])
    if not all(len(inst) == 32 for inst in instructions):
        execution_trace.append("Error: All instructions must be 32 bits")
    else:
        inst_mem = create_instruction_memory(instructions)
        execute_program(instructions, inst_mem)
    write_output(sys.argv[2])