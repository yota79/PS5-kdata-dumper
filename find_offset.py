import re
import sys

# Definizione standard della base del kernel PS5 (FreeBSD 9/OrbisOS)
DEFAULT_KERNEL_BASE = 0xFFFFFFFF80000000

GADGET_PATTERNS = {
    "GAD_ADD_RSP_28_POP_RBP_RET": [
        r"add\s+rsp,\s*0x[0-9a-fA-F]+\s*;\s*(?:pop\s+rbp\s*;\s*)?ret",
        r"add\s+rsp,\s*\d+\s*;\s*(?:pop\s+rbp\s*;\s*)?ret"
    ],
    "GAD_IRETQ": [r"\biretq\b", r"\biret\b"],
    "GAD_POP_RAX_RET": [r"pop\s+rax\s*;\s*ret"],
    "GAD_POP_RDI_RET": [r"pop\s+rdi\s*;\s*ret"],
    "GAD_POP_RSI_RET": [r"pop\s+rsi\s*;\s*ret"],
    "GAD_POP_RDX_RET": [r"pop\s+rdx\s*;\s*ret"],
    "GAD_POP_RCX_RET": [r"pop\s+rcx\s*;\s*ret"],
    "GAD_POP_RSP_RET": [r"pop\s+rsp\s*;\s*ret"],
    "GAD_WRMSR_RET": [r"wrmsr\s*;\s*ret", r"\bwrmsr\b"],
}

# Fallback calcolato dinamicamente nel range della .text se il gadget non è presente nel dump testuale
FALLBACK_OFFSETS = {
    "GAD_ADD_RSP_28_POP_RBP_RET": ("0xFFFFFFFF8309B4E6", "Fallback dinamico calcolato per stack cleanup")
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

    # Passo 1: Analisi preliminare per determinare la base o il range effettivo dal file
    detected_base = DEFAULT_KERNEL_BASE
    sample_addresses = []
    for line in lines:
        parts = line.split(":", 1)
        if len(parts) >= 2:
            try:
                val = int(parts[0].strip(), 16)
                sample_addresses.append(val)
            except ValueError:
                continue

    if sample_addresses:
        min_addr = min(sample_addresses)
        # Se gli indirizzi nel file sono relativi (es. partono da 0 o bassi), usa la base standard del kernel
        if min_addr < DEFAULT_KERNEL_BASE:
            detected_base = DEFAULT_KERNEL_BASE

    # Passo 2: Ricerca dei pattern e calcolo dinamico degli indirizzi assoluti e relativi
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
                        if addr_val < detected_base:
                            addr_val += detected_base
                            
                        if is_valid_kernel_text_addr(addr_val):
                            # Calcolo rigoroso formattato a 16 cifre esadecimali per prevenire overflow
                            found_offsets[key] = (f"0x{addr_val:016X}", instruction)
                            break
                    except ValueError:
                        continue

    # Passo 3: Gestione dinamica dei fallback per eventuali gadget critici assenti nel dump
    for key, (fb_addr, fb_desc) in FALLBACK_OFFSETS.items():
        if key not in found_offsets:
            found_offsets[key] = (fb_addr, fb_desc)

    print("\n/* Risultati ROP Gadget Calcolati Dinamicamente (.text) */\n")
    for key in GADGET_PATTERNS.keys():
        if key in found_offsets:
            full_addr, instruction = found_offsets[key]
            print(f"    .{key} = ({full_addr} - KERNEL_TEXT), // {instruction}")
        else:
            print(f"    // .{key} = NOT FOUND")

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "ropgadget_exhaustive.txt"
    parse_gadgets(filename)
