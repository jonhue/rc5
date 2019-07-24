.intel_syntax noprefix
.global rc5_init
.global rc5_enc
.global rc5_enc_128
.global rc5_dec
.global reset_registers
.global roundkeys

.data

# Vorberechnete Rundenschlüssel für P = 0xb7e1 und Q = 0x9e37 (34 16-bit-Schlüssel, 34 = 16 * 2 + 2)
roundkeys: .hword \
    0xb7e1, 0x5618, 0xf44f, 0x9286, 0x30bd, 0xcef4, 0x6d2b, 0x0b62, \
    0xa999, 0x47d0, 0xe607, 0x843e, 0x2275, 0xc0ac, 0x5ee3, 0xfd1a, \
    0x9b51, 0x3988, 0xd7bf, 0x75f6, 0x142d, 0xb264, 0x509b, 0xeed2, \
    0x8d09, 0x2b40, 0xc977, 0x67ae, 0x05e5, 0xa41c, 0x4253, 0xe08a, \
    0x7ec1, 0x1cf8

.text

# Dient zum Testen. Gibt die Adresse der roundkeys zurück, damit diese zwischengespeichert und später wiederhergestellt werden können.
get_roundkeys_address:
    lea rax, [rip + roundkeys]
    ret

rc5_init:
# rdi: Adresse des Schlüssels *K
# rsi: Länge des Schlüssels in Byte b
# rdx: Adresse des Schlüssels als Halbblöcke *L
# Lokale Variablen:
# r8: Länge von S -> t
# r9: Länge von L -> c
# r10: Adresse der Rundenschlüssel *S
# r11w: A (Key-Mixing)
# r12w: B (Key-Mixing)
# r13: k (Key-Mixing)
# r14: i (Key-Mixing)
# r15: j (Key-Mixing)
# rax: Temporäres Register (Key-Mixing)
# rcx: Temporäres Register (Key-Mixing)

    # Initialisierung
    push r12
    push r13
    push r14
    push r15
    mov r8, 34 # 2*r + 2 = 34 mit r = 16
    lea r10, [rip + roundkeys] # Adresse der Rundenschlüssel

    # Initialisierung von c = ceil(b/2)
    mov r9, rsi
    shr r9, 1
    test rsi, 1
    jz .Linitskipceil
    add r9, 1
.Linitskipceil:

    # Initialisierung von L durch Kopieren des Schlüssels K
    mov rcx, rsi
    xchg rdx, rdi
    xchg rdx, rsi
    rep movs byte ptr [rdi], byte ptr [rsi]
    xchg rdx, rsi
    xchg rdx, rdi
    sub rdx, rsi # Setze rdx zurück auf Anfangsadresse von L
    # Dem letzten Halbblock in L fehlt genau dann ein Byte aus dem Schlüssel von K wenn b ungerade
    # ist. Dieser Byte wird in solchen Fällen genullt.
    test rsi, 1
    jz .Linitskipzeroing
    mov byte ptr [rdx + 2*r9 - 1], 0
.Linitskipzeroing:

    # Key-Mixing
    xor r11w, r11w # A = 0
    xor r12w, r12w # B = 0
    xor r13, r13 # k = 0
    xor r14, r14 # i = 0
    # j = 3 * max{t, c}
    mov r15, r8
    cmp r15, r9
    jge .Linitalreadymax
    mov r15, r9
.Linitalreadymax:
    imul r15, 3
    # Eine Gaurd-Clause ist nicht notwendig, da stets gilt: 6r + 6 > 0
.Linitkeymixloop:
    # A = S[k] = (S[k] + A + B) <<< 3
    add r11w, r12w
    add r11w, word ptr [r10 + 2*r13]
    rol r11w, 3
    mov word ptr [r10 + 2*r13], r11w
    # B = L[i] = (L[i] + A + B) <<< (A + B)
    xor rcx, rcx
    mov cx, r11w
    add cx, r12w
    add r12w, r11w
    add r12w, word ptr [rdx + 2*r14]
    # In diesem Fall ist es unerheblich, dass cl kleiner als r12w ist, da die oberen Bits nur ein
    # Vielfaches von 16 dazuaddieren würden.
    rol r12w, cl
    mov word ptr [rdx + 2*r14], r12w
    # k = (k + 1) mod t
    push rdx
    xor rdx, rdx
    mov rax, r13
    add rax, 1
    div r8
    mov r13, rdx
    # i = (i + 1) mod c
    xor rdx, rdx
    mov rax, r14
    add rax, 1
    div r9
    mov r14, rdx
    pop rdx

    dec r15
    cmp r15, 0
    jnz .Linitkeymixloop

    pop r15
    pop r14
    pop r13
    pop r12
ret

rc5_enc:
# rdi: Buffer, der den zu verschlüsselnden Block enthält (32 Bit)
# Lokale Variablen:
# rsi: Buffer, der die Rundenschlüssel enthält (34 16-bit-Schlüssel, 34 = 16 * 2 + 2)
# r8d: gesamter Block
# r9w: linker Halbblock
# r10w: rechter Halbblock
# xmm0: temporäres Register mit den nächsten 8 Rundenschlüsseln
# r11d: Als nächstes verwendete Rundenschlüssel
# rdx: Counter, der noch nicht verwendete Schlüssel zählt
# rax: Zählt, wieviele der 8 Schlüssel aus xmm0 bereits verwendet wurden

    # Adresse der Rundenschlüssel laden
    lea rsi, [rip + roundkeys]

    # Block aus Speicher holen
    mov r8d, dword ptr [rdi]

    # Aufteilung in linken und rechten Halbblock
    mov r9w, r8w
    shr r8d, 16
    mov r10w, r8w

    # Key-Whitening
    add r9w, word ptr [rsi]
    add rsi, 2
    add r10w, word ptr [rsi]
    add rsi, 2

    # 16 Runden sollen durchgeführt werden
    mov rdx, 16
    # Kennzeichnung, sodass am Anfang neue Schlüssel geladen werden
    mov rax, 8

.Lencloop:
    # 8 neue Schlüssel aus dem Speicher laden, falls keine mehr in r11 verfügbar sind
    cmp rax, 8
    jne .Lnextenc
    mov rax, 0
    movdqu xmm0, xmmword ptr [rsi]
    add rsi, 16
.Lnextenc:
    # Nächsten Rundenschlüssel in die unteren Bits holen
    movd r11d, xmm0
    pshufd xmm0, xmm0, 0b00111001

    # Linken Halbblock verschlüsseln
    xor r9w, r10w
    # Um um r10w Bits zu rotieren, muss der Wert in cl geschrieben werden, da cl das einzige
    # Register ist, das als Parameter für rol erlaubt ist. Dass cl kleiner als r9w ist, ist dabei
    # egal, da die oberen Bits nur ein Vielfaches von 16 dazuaddieren würden.
    mov cl, r10b
    rol r9w, cl
    add r9w, r11w

    # Nächsten Rundenschlüssel in die unteren Bits holen
    shr r11d, 16

    # Rechten Halbblock verschlüsseln
    xor r10w, r9w
    mov cl, r9b
    rol r10w, cl
    add r10w, r11w

    add rax, 2
.Lenccondition:
    dec rdx
    jnz .Lencloop

    # Zusammenfügen der Halbblöcke und Zurückschreiben in Speicher
    mov r8w, r10w
    shl r8d, 16
    mov r8w, r9w
    mov dword ptr [rdi], r8d
ret

rc5_dec:
# Registerverwendung ist die selbe wie bei rc5_enc

    # Adresse der Rundenschlüssel laden
    lea rsi, [rip + roundkeys]

    # Block aus Speicher holen
    mov r8d, dword ptr [rdi]

    # Aufteilung in linken und rechten Halbblock
    mov r9w, r8w
    shr r8d, 16
    mov r10w, r8w

    # 16 Runden sind durchzuführen
    mov rdx, 16
    # Es muss beim letzten Schlüssel begonnen werden, daher Addition mit 34 * 2
    add rsi, 68
    mov rax, 8

.Ldecloop:
    # 8 neue Schlüssel aus dem Speicher laden, falls keine mehr in r11 verfügbar sind
    cmp rax, 8
    jne .Lnextdec
    mov rax, 0
    sub rsi, 16
    movdqu xmm0, xmmword ptr [rsi]
.Lnextdec:
    # Nächsten Rundenschlüssel in die unteren Bits holen
    pshufd xmm0, xmm0, 0b10010011
    movd r11d, xmm0
    ror r11d, 16

    # Rechten Halbblock entschlüsseln
    sub r10w, r11w
    # Um um r10w Bits zu rotieren, muss der Wert in cl geschrieben werden, da cl das einzige
    # Register ist, das als Parameter für rol erlaubt ist. Dass cl kleiner als r9w ist, ist dabei
    # egal, da die oberen Bits nur ein Vielfaches von 16 dazuaddieren würden.
    mov cl, r9b
    ror r10w, cl
    xor r10w, r9w

    # Nächsten Rundenschlüssel in die unteren Bits holen
    shr r11d, 16

    # Linken Halbblock entschlüsseln
    sub r9w, r11w
    mov cl, r10b
    ror r9w, cl
    xor r9w, r10w

    add rax, 2
.Ldeccondition:
    dec rdx
    jnz .Ldecloop

    # Anti-Key-Whitening
    sub rsi, 2
    sub r10w, word ptr [rsi]
    sub rsi, 2
    sub r9w, word ptr [rsi]

    # Zusammenfügen der Halbblöcke und Zurückschreiben in Speicher
    mov r8w, r10w
    shl r8d, 16
    mov r8w, r9w
    mov dword ptr [rdi], r8d
ret

rc5_enc_128:
# rdi: Buffer, der die Startadresse der 8 zu verschlüsselnden Blöcke enthält (je 32 Bit)
# Lokale Variablen:
# rsi: Buffer, der die Rundenschlüssel enthält (34 16-bit-Schlüssel, 34 = 16 * 2 + 2)
# xmm0: linker Halbblock
# xmm1: rechter Halbblock
# xmm2: Als nächtes verwendeter Rundenschlüssel, temporäre Nutzung beim Laden/Schreiben der Halbblöcke
# r8d: temporäres Register
# xmm3: temporäres Register mit den nächsten 8 Rundenschlüsseln
# r11d: Als nächtes verwendete Rundenschlüssel
# rdx: Counter, der noch nicht verwendete Schlüssel zählt
# rax: Zählt, wieviele der 8 Schlüssel aus xmm0 bereits verwendet wurden

    # Adresse der Rundenschlüssel laden
    lea rsi, [rip + roundkeys]

    # 8 Blöcke aus Speicher holen
    mov r8w, word ptr [rdi + 28]
    shl r8d, 16
    mov r8w, word ptr [rdi + 24]
    movd xmm0, r8d
    mov r8w, word ptr [rdi + 30]
    shl r8d, 16
    mov r8w, word ptr [rdi + 26]
    movd xmm1, r8d
    mov rcx, 2
.Lenc128loadloop:
    mov r8w, word ptr [rdi + 8*rcx + 4]
    shl r8d, 16
    mov r8w, word ptr [rdi + 8*rcx]
    movd xmm2, r8d
    pshufd xmm0, xmm0, 0b10010011 # Ein Doubleword nach links rotieren
    paddw xmm0, xmm2
    mov r8w, word ptr [rdi + 8*rcx + 6]
    shl r8d, 16
    mov r8w, word ptr [rdi + 8*rcx + 2]
    movd xmm2, r8d
    pshufd xmm1, xmm1, 0b10010011 # Ein Doubleword nach links rotieren
    paddw xmm1, xmm2
    dec rcx
    cmp rcx, 0
    jge .Lenc128loadloop

    # Key-Whitening auf linken Halbblöcken
    mov r8w, word ptr [rsi]
    shl r8d, 16
    mov r8w, word ptr [rsi]
    movd xmm2, r8d
    shufps xmm2, xmm2, 0
    paddw xmm0, xmm2
    add rsi, 2

    # Key-Whitening auf rechten Halbblöcken
    mov r8w, word ptr [rsi]
    shl r8d, 16
    mov r8w, word ptr [rsi]
    movd xmm2, r8d
    shufps xmm2, xmm2, 0
    paddw xmm1, xmm2
    add rsi, 2

    # 16 Runden sollen durchgeführt werden
    mov rdx, 16
    # Kennzeichnung, sodass am Anfang neue Schlüssel geladen werden
    mov rax, 8

.Lenc128loop:
    # 8 neue Schlüssel aus dem Speicher laden, falls keine mehr in r11 verfügbar sind
    cmp rax, 8
    jne .Lnextenc128
    mov rax, 0
    movdqu xmm3, xmmword ptr [rsi]
    add rsi, 16
.Lnextenc128:
    # Lade neuen Schlüssel in xmm2
    movd r11d, xmm3
    pshufd xmm3, xmm3, 0b00111001
    mov r8w, r11w
    shl r8d, 16
    mov r8w, r11w
    movd xmm2, r8d
    shufps xmm2, xmm2, 0

    # Linken Halbblock verschlüsseln
    pxor xmm0, xmm1
    call prol_128
    paddw xmm0, xmm2

    # Nächsten Rundenschlüssel in die unteren Bits holen
    shr r11d, 16

    # Lade neuen Schlüssel in xmm2
    mov r8w, r11w
    shl r8d, 16
    mov r8w, r11w
    movd xmm2, r8d
    shufps xmm2, xmm2, 0

    # Rechten Halbblock verschlüsseln
    # xmm1 xor xmm0 und xmm1 und xmm0 vertauschen
    pxor xmm0, xmm1
    pxor xmm1, xmm0
    call prol_128
    # xmm1 und xmm0 zurücktauschen
    pxor xmm1, xmm0
    pxor xmm0, xmm1
    pxor xmm1, xmm0
    paddw xmm1, xmm2

    add rax, 2
.Lenc128condition:
    dec rdx
    jnz .Lenc128loop

    # Zusammenfügen der 8 Halbblöcke und Zurückschreiben in Speicher
    movdqa xmm2, xmm0
    punpcklwd xmm0, xmm1
    punpckhwd xmm2, xmm1
    movdqa [rdi], xmm0
    movdqa [rdi + 16], xmm2
ret

prol_128:
# xmm0: Register, dessen Inhalte nach links rotiert werden
# xmm1: Register, das angibt, um wie viel rotiert wird
# Lokale Variablen:
# xmm6: Temporäres Register
# xmm7: Temporäres Register
# r10: Zähler
# cl: Temporäres Register für das Rotieren
# x8d: Temporäres Register für Words aus xmm0
# x9d: Temporäres Register für Words aus xmm1

    # 16-Bit Wörter schrittweise auslesen, rotieren, und in xmm6 schreiben
    pxor xmm6, xmm6
    mov r10, 3
.Lprol128loadloop:
    movd r8d, xmm0
    pshufd xmm0, xmm0, 0b00111001
    movd r9d, xmm1
    pshufd xmm1, xmm1, 0b00111001
    mov cl, r9b
    rol r8w, cl
    ror r8d, 16
    ror r9d, 16
    mov cl, r9b
    rol r8w, cl
    ror r8d, 16
    movd xmm7, r8d
    paddw xmm6, xmm7
    pshufd xmm6, xmm6, 0b00111001
    dec r10
    cmp r10, 0
    jge .Lprol128loadloop

    # 16-Bit Wörter aus xmm7 in umgekehrter Reihenfolge in xmm0 schreiben
    movdqa xmm0, xmm6
ret

reset_registers:
# Lokale Variablen:
# rdx: Zähler

    # Adresse der Rundenschlüssel laden und xmm0 zurücksetzen
    lea rsi, [rip + roundkeys]
    pxor xmm0, xmm0

    # Zurücksetzen der Rundenschlüssel
    mov rdx, 0
.Lresetroundkeysloop:
    movdqu xmmword ptr [rsi + rdx], xmm0
    add rdx, 16
    cmp rdx, 52
    jle .Lresetroundkeysloop

    mov dword ptr [rsi + 64], 0

    # Zurücksetzen der Register
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm6, xmm6
    pxor xmm7, xmm7
    xor r11, r11
    xor r10, r10
    xor r9, r9
    xor r8, r8
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor rdi, rdi
    xor rsi, rsi
ret
