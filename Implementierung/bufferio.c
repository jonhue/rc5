#include <errno.h>
#include "bufferio.h"

void fclose_keep_errno(FILE *file);

/**
 * Liest die Datei in path in buffer. Falls buffer NULL ist, gibt die Funktion die Dateigröße
 * zurück.
 * @param path Der Pfad zur Datei, die gelesen werden soll.
 * @param buffer Der Buffer in dem die Datei gespeichert werden soll. Wenn NULL, gibt die Funktion
 * die Dateigröße in Bytes zurück.
 * @param size Die Größe des Buffers.
 * @return Gibt die Dateigröße in Bytes zurück wenn buffer NULL ist, ansonsten wird 0
 * zurückgegeben. Falls ein Fehler auftritt, wird -1 zurückgegeben.
 */
long read_file(const char *restrict path, void *restrict buffer, size_t size) {
    // Öffne Datei, r = read mode
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }

    if (buffer == NULL) {
        // Springe zum Dateiende, um Dateigröße herauszufinden
        if (fseek(file, 0, SEEK_END)) {
            // Schließe Datei und behalte ursprünglichen errno
            fclose_keep_errno(file);
            return -1;
        }

        // "File position indicator" am Ende der Datei, ftell() gibt also Dateigröße in Bytes zurück
        size = ftell(file);
        if (size == -1u) {
            fclose_keep_errno(file);
            return -1;
        }

        if (fclose(file)) {
            return -1;
        }

        return size;
    }

    // Lies kompletten Dateiinhalt in den allokierten Speicher
    if (fread(buffer, 1, size, file) != size) {
        fclose(file);
        // Setze errno manuell, da fread() errno nicht setzt
        errno = EIO;
        return -1;
    }

    return fclose(file);
}

/**
 * Speichert buffer an den angegeben Pfad.
 * @param path Der Pfad an den buffer gespeichert werden soll.
 * @param buffer Der Buffer, der die zu speichernden Daten enthält.
 * @param size Die Größe des Buffers
 * @return Gibt 0 zuück wenn erfolgreich, ansonsten -1.
 *
 */
int write_file(const char *restrict path, const void *restrict buffer, size_t size) {
    // Öffne Datei, w = write mode
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }

    // Schreibe den kompletten buffer in die Datei
    if (fwrite(buffer, 1, size, file) != size) {
        fclose(file);
        errno = EIO;
        return -1;
    }

    return fclose(file);
}

/**
 * Helfermethode, die eine Datei schließt und dabei den Wert von errno beibehält. Hilfreich falls
 * fclose(file) aufgrund eines vorangeganenen Fehlers aufgerufen werden soll, aber fclose nicht
 * den Fehlercode überschreiben soll, falls auch in dieser es zu einem Fehler kommt.
 *
 * @param file Die zu schließende Datei.
 */
void fclose_keep_errno(FILE *file) {
    int tmp = errno;
    fclose(file);
    errno = tmp;
}
