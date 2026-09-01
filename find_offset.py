import re
import sys

# Indirizzo base di partenza del kernel (0xFFFFFFFF80000000)
KERNEL_BASE = 0xFFFFFFFF80000000

GADGET_PATTERNS = {
    "GAD_ADD_RSP_28_POP_RBP_RET": [
        r"add\s+rsp,?\s*(0x0*28|28h).*,?\s*pop\s+rbp.*ret",
        r"add\s+rsp,?\s*(0x0*28|28h).*ret",
        r"pop\s+rdi\s*;\s*pop\s+rsi\s*;\s*pop\s+rdx\s*;\s*pop\s+rcx\s*;\s*pop\s+rbx\s*;\s*ret"
    ],
    "GAD_IRETQ": [r"\biretq\b", r"\biret\b"],
    "GAD_POP_RAX_RET": [r";\s*pop\s+rax\s*;\s*ret$", r"pop\s+rax.*ret"],
    "GAD_POP_RDI_RET": [r";\s*pop\s+rdi\s*;\s*ret$", r"pop\s+rdi.*ret"],
    "GAD_POP_RSI_RET": [r";\s*pop\s+rsi\s*;\s*ret$", r"pop\s+rsi.*ret"],
    "GAD_POP_RDX_RET": [r";\s*pop\s+rdx\s*;\s*ret$", r"pop\s+rdx.*ret"],
    "GAD_POP_RCX_RET": [r";\s*pop\s+rcx\s*;\s*ret$", r"pop\s+rcx.*ret"],
    "GAD_POP_RSP_RET": [r";\s*pop\s+rsp\s*;\s*ret$", r"pop\s+rsp.*ret"],
    "GAD_WRMSR_RET": [r"\bwrmsr\b"],
}

def convert_to_kernel_addr(hex_str):
    """ Converte un offset relativo o indirizzo in formato 0xFFFFFFFF8xxxxxxx """
    val = int(hex_str, 16)
    if val < 0xFFFFFFFF80000000:
        val += KERNEL_BASE
    return f"0x{val:016X}"

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
            for line in lines:
                if re.search(pattern, line, re.IGNORECASE):
                    addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)
                    if addr_match:
                        found_offsets[key] = (addr_match.group(1), line)
                        break
            if key in found_offsets:
                break

    print("\n/* Risultati convertiti nel formato (0xFFFFFFFF8xxxxxxx - KERNEL_TEXT) */\n")
    for key in GADGET_PATTERNS.keys():
        if key in found_offsets:
            raw_addr, raw_line = found_offsets[key]
            full_addr = convert_to_kernel_addr(raw_addr)
            instruction = raw_line.split(":", 1)[-1].strip()
            print(f"    .{key} = ({full_addr} - KERNEL_TEXT), // {instruction}")
        else:
            print(f"    // .{key} = NOT FOUND")

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "ropgadget_full.txt"
    parse_gadgets(filename)
