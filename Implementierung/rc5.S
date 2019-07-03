.intel_syntax noprefix
.global rc5_init
.global rc5_enc
.global rc5_dec

.text

rc5_init:
ret

rc5_enc:
# rdi: Buffer, der den zu verschlüsselnden Block enthält (32 Bit)
# rsi: Buffer, der die Rundenschlüssel enthält (34 16-bit-Schlüssel, 34 = 16 * 2 + 2)
# Lokale Variablen:
# r8d: gesamter Block
# r9w: linker Halbblock
# r10w: rechter Halbblock
# r11: temporäres Register mit den nächsten 4 Rundenschlüsseln
# r11w: Als nächtes verwendeter Rundenschlüssel
# edx: Counter, der noch nicht verwendete Schlüssel zählt
# rax: Zählt, wieviele der 4 Schlüssel aus r11 bereits verwendet wurden

    # Block aus Speicher holen
    mov r8d, dword ptr [rdi]

    # Key-Whitening auf ganzem Block
    add r8d, dword ptr [rsi]
    add rsi, 4

    # Aufteilung in linken und rechten Halbblock
    mov r10w, r8w
    shr r8d, 16
    mov r9w, r8w

    # 16 Runden sollen durchgeführt werden
    mov edx, 16
    # Kennzeichnung, sodass am Anfang neue Schlüssel geladen werden
    mov rax, 4

.Lencloop:
    # 4 neue Schlüssel aus dem Speicher laden, falls keine mehr in r11 verfügbar sind
    cmp rax, 4
    jne .Lnextenc
    mov rax, 0
    mov r11, qword ptr [rsi]
    add rsi, 8
.Lnextenc:
    # Linken Halbblock verschlüsseln
    xor r9w, r10w
    # Um um r10w Bits zu rotieren, muss der Wert in cl geschrieben werden, da cl das einzige Register ist, das als Parameter für rol erlaubt ist.
    # Dass cl kleiner als r9w ist, ist dabei egal, da die oberen Bits nur ein Vielfaches von 16 dazuaddieren würden.
    mov cl, r10b
    rol r9w, cl
    add r9w, r11w

    # Nächsten Rundenschlüssel in die unteren Bits holen
    shr r11, 16

    # Rechten Halbblock verschlüsseln
    xor r10w, r9w
    mov cl, r9b
    rol r10w, cl
    add r10w, r11w

    # Nächsten Rundenschlüssel in die unteren Bits holen
    shr r11, 16

    add rax, 2
.Lenccondition:
    dec edx
    jnz .Lencloop

    # Zusammenfügen der Halbblöcke und Zurückschreiben in Speicher
    mov r8w, r9w
    shl r8d, 16
    mov r8w, r10w
    mov dword ptr [rdi], r8d
ret



rc5_dec:
# Registerverwendung ist die selbe wie bei rc5_enc

    # Block aus Speicher holen
    mov r8d, dword ptr [rdi]

    # Aufteilung in linken und rechten Halbblock
    mov r10w, r8w
    shr r8d, 16
    mov r9w, r8w

    # 16 Runden sind durchzuführen
    mov edx, 16
    # Es muss beim letzten Schlüssel begonnen werden, daher Addition mit 34 * 2
    add rsi, 68
    mov rax, 4

.Ldecloop:
    # 4 neue Schlüssel aus dem Speicher laden, falls keine mehr in r11 verfügbar sind
    cmp rax, 4
    jne .Lnextdec
    mov rax, 0
    sub rsi, 8
    mov r11, qword ptr [rsi]
.Lnextdec:
    # Nächsten Rundenschlüssel in die unteren Bits holen
    rol r11, 16

    # Rechten Halbblock entschlüsseln
    sub r10w, r11w
    # Um um r10w Bits zu rotieren, muss der Wert in cl geschrieben werden, da cl das einzige Register ist, das als Parameter für rol erlaubt ist.
    # Dass cl kleiner als r9w ist, ist dabei egal, da die oberen Bits nur ein Vielfaches von 16 dazuaddieren würden.
    mov cl, r9b
    ror r10w, cl
    xor r10w, r9w

    # Nächsten Rundenschlüssel in die unteren Bits holen
    rol r11, 16

    # Linken Halbblock entschlüsseln
    sub r9w, r11w
    mov cl, r10b
    ror r9w, cl
    xor r9w, r10w

    add rax, 2
.Ldeccondition:
    dec edx
    jnz .Ldecloop

    # Zusammenfügen der Halbblöcke
    mov r8w, r9w
    shl r8d, 16
    mov r8w, r10w

    # Anti-Key-Whitening auf ganzem Block
    sub r8d, dword ptr [rsi - 4]

    # Zurückschreiben in Speicher
    mov dword ptr [rdi], r8d
ret
