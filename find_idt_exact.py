import struct
import sys

def find_idt(file_path):
    print(f"[*] Apertura di {file_path}...")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as f_err:
        print(f"[-] Errore: {f_err}")
        return

    file_size = len(data)
    print(f"[+] Dimensione: {file_size / (1024*1024):.2f} MB\n")

    print("=" * 60)
    print(" RICERCA PRECISA IDT (Interrupt Descriptor Table)")
    print("=" * 60)

    idt_candidates = []
    
    # L'IDT è una tabella di descrittori. Su x86_64, i gate di interrupt 
    # hanno tipicamente i byte di attributo impostati a 0x8E (presente, DPL 0, Interrupt Gate).
    for off in range(0, file_size - 0x1000, 16):
        match_count = 0
        # Controlliamo i primi 16 gate consecutivi (struttura tipica IDT)
        for i in range(16):
            entry_off = off + (i * 16)
            if entry_off + 16 > file_size:
                break
            
            # Leggi gli attributi del gate (offset 5 del descrittore a 16 byte)
            attr = data[entry_off + 5]
            # 0x8E = Interrupt Gate attivo, 0xEE = Interrupt Gate utente
            if attr in [0x8E, 0xEE, 0x8F]:
                match_count += 1
                
        # Se troviamo una sequenza molto forte di interrupt gates validi
        if match_count >= 12: 
            idt_candidates.append(off)

    if idt_candidates:
        best_match = idt_candidates[0]
        print(f"[+] Trovato IDT valido a File Offset: 0x{best_match:X}")
        
        # Con la base fissa della famiglia 7.01 (0xFFFFFFFF83CDFDF0 si trova a offset noto nel binario)
        # Calcoliamo l'indirizzo virtuale preciso usando la base conosciuta della 7.01
        # IDT_BASE (7.01) = 0xFFFFFFFF83CDFDF0
        # Sottraendo l'offset del file della 7.01 originale otteniamo la base dati esatta.
        # Per comodità, stampiamo direttamente l'indirizzo basato sull'allineamento standard:
        
        # Indirizzo virtuale corretto calcolato sulla base della 7.01
        # (La distanza tra l'inizio del file e l'IDT rimane costante se la sezione dati non è shiftata)
        base_diff = 0xFFFFFFFF83CDFDF0 - 0x7795F0 # (usando l'offset della 7.01 originale)
        virtual_addr = base_diff + best_match
        
        print(f"    -> Formato pronto per la struct:")
        print(f"    .IDT = (0x{virtual_addr:X} - KERNEL_TEXT),")
    else:
        print("[-] IDT non trovata con i filtri attuali.")

    print("=" * 60)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "kdump_fw_70101.bin"
    find_idt(target)
