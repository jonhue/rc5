  #include <stdint.h>

  #ifndef RFC2040_H
  #define RFC2040_H

  // Referenzimplementierung aus RFC2040, siehe https://tools.ietf.org/html/rfc2040.
  // Author: Ronald Rivest
  // Die Implementierung wurde angepasst, um statt 64 Bit eine Blockgröße von 32 Bit zu unterstützen.
  // Änderungen am Original sind durch Kommentare hervorgehoben, die mit EDIT anfangen.

  /* Definitions for RC5 as a 64 bit block cipher. */
  /* The "unsigned int" will be 32 bits on all but */
  /* the oldest compilers, which will make it 16 bits. */
  /* On a DEC Alpha "unsigned long" is 64 bits, not 32. */
  // EDIT: Wortgröße sind 16 Bit
  #define RC5_WORD     uint16_t
  #define W            (16)
  #define WW           (W / 8)
  #define ROT_MASK     (W - 1)
  #define BB           ((2 * W) / 8) /* Bytes per block */
  /* Define macros used in multiple procedures. */
  /* These macros assumes ">>" is an unsigned operation, */
  /* and that x and s are of type RC5_WORD. */
  #define SHL(x,s)    ((RC5_WORD)(((RC5_WORD) (x))<<((s)&ROT_MASK)))
  #define SHR(x,s,w)  ((RC5_WORD)(((RC5_WORD) (x))>>((w)-((s)&ROT_MASK))))
  #define ROTL(x,s,w) ((RC5_WORD)(SHL((x),(s))|SHR((x),(s),(w))))

  #define RC5_FIRST_VERSION 1

  #define P16  0xb7e1
  #define Q16  0x9e37
  #define P32  0xb7e15163
  #define Q32  0x9e3779b9
  #define P64  0xb7e151628aed2a6b
  #define Q64  0x9e3779b97f4a7c15
  #if W == 16
  #define Pw   P16 /* Select 16 bit word size */
  #define Qw   Q16
  #endif
  #if W == 32
  #define Pw   P32 /* Select 32 bit word size */
  #define Qw   Q32
  #endif
  #if W == 64
  #define Pw   P64 /* Select 64 bit word size */
  #define Qw   Q64
  #endif

  #define BLOCK_LENGTH      (4 /* bytes */)
  #define MAX_KEY_LENGTH    (64 /* bytes */)
  #define MAX_PLAIN_LENGTH  (249999996 /* bytes */)
  #define MAX_CIPHER_LENGTH (MAX_PLAIN_LENGTH + BLOCK_LENGTH)
  #define MAX_ROUNDS        (20)
  #define MAX_S_LENGTH      (2 * (MAX_ROUNDS + 1))

  typedef struct test_vector
  {
    int padding_mode;
    int rounds;
    char    keytext[2*MAX_KEY_LENGTH+1];
    int key_length;
    char    key[MAX_KEY_LENGTH];
    char    ivtext[2*BLOCK_LENGTH+1];
    int iv_length;
    char    iv[BLOCK_LENGTH];
    char    plain[MAX_PLAIN_LENGTH];
    char    plaintext[2*MAX_PLAIN_LENGTH+1];
    int plain_length;
    char    cipher[MAX_CIPHER_LENGTH];
    char    ciphertext[2*MAX_CIPHER_LENGTH+1];
    int cipher_length;
    RC5_WORD    S[MAX_S_LENGTH];
    //EDIT *pKey *pAlg hinzugefügt, um von perf.c ein cleanup durchzuführen
    void *pKey;
    void *pAlg;
  } test_vector;

  /* Definition of the RC5 CBC algorithm object.
   */
  typedef struct rc5CBCAlg
  {
    int          Pad;   /* 1 = RC5-CBC-Pad, 0 = RC5-CBC. */
    int          R;     /* Number of rounds. */
    RC5_WORD        *S;     /* Expanded key. */
    char    I[BB]; /* Initialization vector. */
    char    chainBlock[BB];
    char    inputBlock[BB];
    int          inputBlockIndex; /* Next inputBlock byte. */
  } rc5CBCAlg;

  /* Definition of RC5 user key object. */
  typedef struct rc5UserKey
  {
    int          keyLength; /* In Bytes. */
    char   *keyBytes;
  } rc5UserKey;

  void run_rfc2040_test(test_vector* ptv, int destroy);

  rc5UserKey *RC5_Key_Create ();

  void RC5_Key_Destroy(
    rc5UserKey      *pKey);

  int RC5_Key_Set (
    rc5UserKey  *pKey,
    int          keyLength,
    char   *keyBytes);

  void RC5_Key_Expand (
    int      b,
    char        *K,
    int      R,
    RC5_WORD *S);

  void RC5_Block_Encrypt (
    RC5_WORD    *S,
    int  R,
    char    *in,
    char    *out);

  rc5CBCAlg *RC5_CBC_Create (
    int      Pad,
    int      R,
    int      Version,
    int      bb,
    char     *I);

  void RC5_CBC_Destroy (
    rc5CBCAlg   *pAlg);

  int RC5_CBC_SetIV (
    rc5CBCAlg   *pAlg,
    char        *I);

  int RC5_CBC_Encrypt_Init (
    rc5CBCAlg       *pAlg,
    rc5UserKey  *pKey);

  int RC5_CBC_Encrypt_Update (
    rc5CBCAlg   *pAlg,
    int          N,
    char        *P,
    int         *pCipherLen,
    int          maxCipherLen,
    char        *C);

  int RC5_CBC_Encrypt_Final (
    rc5CBCAlg   *pAlg,
    int         *pCipherLen,
    int          maxCipherLen,
    char        *C);

  #endif