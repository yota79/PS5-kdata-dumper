import re
import sys

KERNEL_BASE = 0xFFFFFFFF80000000

# Pattern avanzati per catturare tutte le varianti presenti nel dump exhaustive
GADGET_PATTERNS = {
    "GAD_ADD_RSP_28_POP_RBP_RET": [
        r"add\s+rsp,\s*(?:0x)?(?:28h?|[0-9a-fA-F]+)\s*;\s*(?:pop\s+rbp\s*;\s*)?ret",
        r"add\s+rsp,.*pop\s+rbp.*ret",
        r"add\s+rsp,.*ret"
    ],
    "GAD_IRETQ": [
        r"\biretq\b", 
        r"\biret\b"
    ],
    "GAD_POP_RAX_RET": [r"pop\s+rax.*ret"],
    "GAD_POP_RDI_RET": [r"pop\s+rdi.*ret"],
    "GAD_POP_RSI_RET": [r"pop\s+rsi.*ret"],
    "GAD_POP_RDX_RET": [r"pop\s+rdx.*ret"],
    "GAD_POP_RCX_RET": [r"pop\s+rcx.*ret"],
    "GAD_POP_RSP_RET": [r"pop\s+rsp.*ret"],
    "GAD_WRMSR_RET": [
        r"wrmsr\s*;\s*ret", 
        r"\bwrmsr\b"
    ],
}

def is_valid_kernel_text_addr(val):
    return 0xFFFFFFFF80000000 <= val <= 0xFFFFFFFF82FFFFFF

def parse_gadgets(file_path):
    found_offsets = {}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Errore: File '{file_path}' non trovato.")
        sys.exit(1)

    for key, patterns in GADGET_PATTERNS.items():
        for pattern in patterns:
            if key in found_offsets:
                break
            for line in lines:
                parts = line.split(":", 1)
                if len(parts) < 2:
                    continue
                
                addr_str = parts[0].strip()
                instruction = parts[1].strip()
                clean_instr = re.sub(r'\s+', ' ', instruction).strip()

                if re.search(pattern, clean_instr, re.IGNORECASE):
                    try:
                        addr_val = int(addr_str, 16)
                        if addr_val < KERNEL_BASE:
                            addr_val += KERNEL_BASE
                            
                        if is_valid_kernel_text_addr(addr_val):
                            found_offsets[key] = (f"0x{addr_val:016X}", instruction)
                            break
                    except ValueError:
                        continue

    print("\n/* Risultati ROP Gadget Estratti (.text) - Completi */\n")
    for key in GADGET_PATTERNS.keys():
        if key in found_offsets:
            full_addr, instruction = found_offsets[key]
            print(f"    .{key} = ({full_addr} - KERNEL_TEXT), // {instruction}")
        else:
            print(f"    // .{key} = NOT FOUND")

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "ropgadget_exhaustive.txt"
    parse_gadgets(filename)
