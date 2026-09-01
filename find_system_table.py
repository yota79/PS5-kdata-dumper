import struct
import struct
import sys

# Base virtuale della sezione dati calcolata per il tuo dump 7.01.01
KERNEL_DATA_BASE = 0xFFFFFFFF83709406

def search_tables(file_path):
    print(f"[*] Apertura di {file_path}...")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Errore: {e}")
        return

    file_size = len(data)
    print(f"[+] Dimensione: {file_size / (1024*1024):.2f} MB\n")

    print("=" * 60)
    print(" RISULTATI E CONVERSIONE AUTOMATICA IN OFFSET KERNEL")
    print("=" * 60)

    # 1. Ricerca IDT
    print("[*] Scansione candidati .IDT...")
    idt_candidates = []
    for off in range(0, file_size - 0x1000, 16):
        match_count = 0
        for i in range(8):
            entry = off + (i * 16)
            if entry + 16 > file_size:
                break
            attr = data[entry + 5]
            if attr in [0x8E, 0xEE, 0x8F]:
                match_count += 1
        if match_count >= 6:
            idt_candidates.append(off)

    if idt_candidates:
        # Prendi il primo blocco stabile trovato
        best_idt = idt_candidates[0]
        virtual_addr = KERNEL_DATA_BASE + best_idt
        print(f"[+] .IDT trovato a file offset: 0x{best_idt:X}")
        print(f"    -> Formato pronto per la struct:")
        print(f"    .IDT = (0x{virtual_addr:X} - KERNEL_TEXT),")
    else:
        print("[-] Nessun IDT chiaro trovato.")

    # 2. Ricerca strutturata per COMMON_TSS o STOPPED_CPUS nel dump
    # Cerchiamo blocchi di puntatori candidati con scansione più elastica
    print("\n[*] Scansione blocchi di puntatori (Candidati TSS / STOPPED_CPUS)...")
    matches_found = 0
    for off in range(0, file_size - 64, 8):
        ptrs = struct.unpack("<4Q", data[off:off+32])
        # Filtra sequenze di puntatori che puntano alla memoria virtuale del kernel
        if all(0xFFFFFFFF80000000 <= p <= 0xFFFFFFFF89FFFFFF for p in ptrs):
            v_addr = KERNEL_DATA_BASE + off
            print(f"[+] Possibile blocco a File Offset 0x{off:X}:")
            print(f"    -> (0x{v_addr:X} - KERNEL_TEXT)")
            matches_found += 1
            if matches_found >= 5: # Mostra solo i primi 5 per pulizia
                break

    print("=" * 60)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "kdump_fw_70101.bin"
    search_tables(target)
