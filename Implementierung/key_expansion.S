.intel_syntax noprefix
.global key_expansion

.text

key_expansion:
# rdi: Adresse der Rundenschlüssel *S
# Lokale Variablen:
# ax: Temporäres Register
# rcx: Temporärer Zähler

    mov word ptr [rdi], 0xb7e1 # Setze den ersten Wert aus S auf P
    mov rcx, 1
    # Eine Gaurd-Clause ist nicht notwendig, da mit r > 0 stets gilt: 1 < 2r + 2
.Lkeyexploop:
    mov ax, word ptr [rdi + 2*rcx - 2] # Lade den vorherigen Schlüssel aus S in ax
    add ax, 0x9e37 # Addiere Q zu ax
    mov word ptr [rdi + 2*rcx], ax # Speichere ax in S
    inc rcx
    cmp rcx, 34 # 2*r + 2 = 34 mit r = 16
    jne .Lkeyexploop

ret