  #include "rfc2040.h"
  #include <stdlib.h>

  // Referenzimplementierung aus RFC2040, siehe https://tools.ietf.org/html/rfc2040
  // Author: Ronald Rivest
  // Die Implementierung wurde angepasst, um statt 64 Bit eine Blockgröße von 32 Bit zu unterstützen.
  // Änderungen am Original sind durch Kommentare hervorgehoben, die mit EDIT anfangen.

  void run_rfc2040_test(ptv, destroy)
    test_vector *ptv;
    int destroy;
  {
    rc5UserKey  *pKey;
    rc5CBCAlg       *pAlg;
    int          numBytesOut;

    pKey = RC5_Key_Create ();
    RC5_Key_Set (pKey, ptv->key_length, ptv->key);

    pAlg = RC5_CBC_Create (ptv->padding_mode,
                    ptv->rounds,
                    RC5_FIRST_VERSION,
                    BB,
                    ptv->iv);
    (void) RC5_CBC_Encrypt_Init (pAlg, pKey);
    ptv->cipher_length = 0;
    (void) RC5_CBC_Encrypt_Update (pAlg,
                    ptv->plain_length, ptv->plain,
                    &(numBytesOut),
                    MAX_CIPHER_LENGTH - ptv->cipher_length,
                    &(ptv->cipher[ptv->cipher_length]));
                    ptv->cipher_length += numBytesOut;
    (void) RC5_CBC_Encrypt_Final (pAlg,
                    &(numBytesOut),
                    MAX_CIPHER_LENGTH - ptv->cipher_length,
                    &(ptv->cipher[ptv->cipher_length]));
    ptv->cipher_length += numBytesOut;
    if (destroy) {
      RC5_Key_Destroy (pKey);
      RC5_CBC_Destroy (pAlg);
    }
  }

  /* Allocate and initialize an RC5 user key.
   * Return 0 if problems.
   */
  rc5UserKey *RC5_Key_Create ()
  {
    rc5UserKey *pKey;

    pKey = (rc5UserKey *) malloc (sizeof(*pKey));
    if (pKey != ((rc5UserKey *) 0))
    {
        pKey->keyLength = 0;
        pKey->keyBytes = (char *) 0;
    }
    return (pKey);
  }

  /* Zero and free an RC5 user key.
   */
  void RC5_Key_Destroy (pKey)
    rc5UserKey      *pKey;
  {
    char   *to;
    int          count;

    if (pKey == ((rc5UserKey *) 0))
        return;
    if (pKey->keyBytes == ((char *) 0))
        return;
    to = pKey->keyBytes;
    for (count = 0 ; count < pKey->keyLength ; count++)
        *to++ = (char) 0;
    free (pKey->keyBytes);
    pKey->keyBytes = (char *) 0;
    pKey->keyLength = 0;
    free (pKey);
  }

  /* Set the value of an RC5 user key.
   * Copy the key bytes so the caller can zero and
   * free the original.
   * Return zero if problems
   */
  int RC5_Key_Set (pKey, keyLength, keyBytes)
    rc5UserKey  *pKey;
    int          keyLength;
    char   *keyBytes;
  {
    char   *keyBytesCopy;
    char   *from, *to;
    int          count;

    keyBytesCopy = (char *) malloc (keyLength);
    if (keyBytesCopy == ((char *) 0))
        return (0);
    from = keyBytes;
    to = keyBytesCopy;
    for (count = 0 ; count < keyLength ; count++)
        *to++ = *from++;
    pKey->keyLength = count;
    pKey->keyBytes = keyBytesCopy;
    return (1);
  }

  /* Expand an RC5 user key.
   */
  void RC5_Key_Expand (b, K, R, S)
    int      b; /* Byte length of secret key */
    char        *K; /* Secret key */
    int      R; /* Number of rounds */
    RC5_WORD *S;    /* Expanded key buffer, 2*(R+1) words */
  {
    int i, j, k, LL, t, T;
    RC5_WORD    L[256/WW];  /* Based on max key size */
    RC5_WORD    A, B;

    /* LL is number of elements used in L. */
    LL = (b + WW - 1) / WW;
    for (i = 0 ; i < LL ; i++)  {
        L[i] = 0;
    }
    for (i = 0 ; i < b ; i++)  {
        //EDIT: Modulo 2 statt modulo 4
        t = (K[i] & 0xFF) << (8*(i%2)); /* 0, 8 */
        L[i/WW] = L[i/WW] + t;
    }

    T = 2*(R+1);
    S[0] = Pw;
    for (i = 1 ; i < T ; i++)  {
        S[i] = S[i-1] + Qw;
    }

    i = j = 0;
    A = B = 0;
    if (LL > T)
        k = 3 * LL; /* Secret key len > expanded key. */
    else
        k = 3 * T;  /* Secret key len < expanded key. */
    for ( ; k > 0 ; k--)  {
        A = ROTL(S[i] + A + B, 3, W);
        S[i] = A;
        B = ROTL(L[j] + A + B, A + B, W);
        L[j] = B;
        i = (i + 1) % T;
        j = (j + 1) % LL;
    }
    return;
  }

  void RC5_Block_Encrypt (S, R, in, out)
    RC5_WORD    *S;
    int  R;
    char    *in;
    char    *out;
  {
    int  i;
    RC5_WORD    A, B;

    //EDIT: Halbblöcke sind 16 statt 32 Bit groß.
    A  =  in[0] & 0xFF;
    A += (in[1] & 0xFF) << 8;
    B  =  in[2] & 0xFF;
    B += (in[3] & 0xFF) << 8;

    A = A + S[0];
    B = B + S[1];
    for (i = 1 ; i <= R ; i++) {
        A = A ^ B;
        A = ROTL(A, B, W) + S[2*i];
        B = B ^ A;
        B = ROTL(B, A, W) + S[(2*i)+1];
    }

    //EDIT: Halbblöcke sind 16 statt 32 Bit groß.
    out[0] = (A >>  0) & 0xFF;
    out[1] = (A >>  8) & 0xFF;
    out[2] = (B >>  0) & 0xFF;
    out[3] = (B >>  8) & 0xFF;
    return;
  }

  /* Allocate and initialize the RC5 CBC algorithm object.
   * Return 0 if problems.
   */
  rc5CBCAlg *RC5_CBC_Create (Pad, R, Version, bb, I)
    int      Pad;       /* 1 = RC5-CBC-Pad, 0 = RC5-CBC. */
    int      R;         /* Number of rounds. */
    int      Version;   /* RC5 version number. */
    int      bb;        /* Bytes per RC5 block == IV len. */
    char     *I;        /* CBC IV, bb bytes long. */
  {
    rc5CBCAlg    *pAlg;
    int           index;

    if ((Version != RC5_FIRST_VERSION) ||
        (bb != BB) ||   (R < 0) || (255 < R))
        return ((rc5CBCAlg *) 0);
    pAlg = (rc5CBCAlg *) malloc (sizeof(*pAlg));
    if (pAlg == ((rc5CBCAlg *) 0))
        return ((rc5CBCAlg *) 0);
    pAlg->S = (RC5_WORD *) malloc (BB * (R + 1));
    if (pAlg->S == ((RC5_WORD *) 0))    {
        free (pAlg);
        return ((rc5CBCAlg *) 0);
    }
    pAlg->Pad = Pad;
    pAlg->R = R;
    pAlg->inputBlockIndex = 0;
    for (index = 0 ; index < BB ; index++)
        pAlg->I[index] = I[index];
    return (pAlg);
  }

  /* Zero and free an RC5 algorithm object.
   */
  void RC5_CBC_Destroy (pAlg)
    rc5CBCAlg   *pAlg;
  {
    RC5_WORD    *to;
    int      count;

    if (pAlg == ((rc5CBCAlg *) 0))
        return;
    if (pAlg->S == ((RC5_WORD *) 0))
        return;
    to = pAlg->S;
    for (count = 0 ; count < (1 + pAlg->R) ; count++)
    {
        *to++ = 0;  /* Two expanded key words per round. */
        *to++ = 0;
    }
   free (pAlg->S);
    for (count = 0 ; count < BB ; count++)
    {
        pAlg->I[count] = (char) 0;
        pAlg->inputBlock[count] = (char) 0;
        pAlg->chainBlock[count] = (char) 0;
    }
    pAlg->Pad = 0;
    pAlg->R = 0;
    pAlg->inputBlockIndex = 0;
    free (pAlg);
  }

  /* Setup a new initialization vector for a CBC operation
   * and reset the CBC object.
   * This can be called after Final without needing to
   * call Init or Create again.
   * Return zero if problems.
   */
  int RC5_CBC_SetIV (pAlg, I)
    rc5CBCAlg   *pAlg;
    char        *I;     /* CBC Initialization vector, BB bytes. */
  {
    int     index;

    pAlg->inputBlockIndex = 0;
    for (index = 0 ; index < BB ; index++)
    {
        pAlg->I[index] = pAlg->chainBlock[index] = I[index];
        pAlg->inputBlock[index] = (char) 0;
    }
    return (1);
  }

  /* Initialize the encryption object with the given key.
   * After this routine, the caller frees the key object.
   * The IV for this CBC object can be changed by calling
   * the SetIV routine.  The only way to change the key is
   * to destroy the CBC object and create a new one.
   * Return zero if problems.
   */
  int RC5_CBC_Encrypt_Init (pAlg, pKey)
    rc5CBCAlg       *pAlg;
    rc5UserKey  *pKey;
  {
    if ((pAlg == ((rc5CBCAlg *) 0)) ||
        (pKey == ((rc5UserKey *) 0)))
        return (0);
    RC5_Key_Expand (pKey->keyLength, pKey->keyBytes,
                    pAlg->R, pAlg->S);
    return (RC5_CBC_SetIV(pAlg, pAlg->I));
  }

  /* Encrypt a buffer of plaintext.
   * The plaintext and ciphertext buffers can be the same.
   * The byte len of the ciphertext is put in *pCipherLen.
   * Call this multiple times passing successive
   * parts of a large message.
   * After the last part has been passed to Update,
   * call Final.
   * Return zero if problems like output buffer too small.
   */
  int RC5_CBC_Encrypt_Update (pAlg, N, P,
                              pCipherLen, maxCipherLen, C)
    rc5CBCAlg   *pAlg;      /* Cipher algorithm object. */
    int          N;         /* Byte length of P. */
    char        *P;         /* Plaintext buffer. */
    int         *pCipherLen;/* Gets byte len of C. */
    int          maxCipherLen;  /* Size of C. */
    char        *C;         /* Ciphertext buffer. */
  {
    int      plainIndex, cipherIndex, j;

    /* Check size of the output buffer. */
    if (maxCipherLen < (((pAlg->inputBlockIndex+N)/BB)*BB))
    {
        *pCipherLen = 0;
        return (0);
    }

    plainIndex = cipherIndex = 0;
    while (plainIndex < N)
    {
        if (pAlg->inputBlockIndex < BB)
        {
            pAlg->inputBlock[pAlg->inputBlockIndex]
                    = P[plainIndex];
            pAlg->inputBlockIndex++;
            plainIndex++;
        }
        if (pAlg->inputBlockIndex == BB)
        {   /* Have a complete input block, process it. */
            pAlg->inputBlockIndex = 0;
            for (j = 0 ; j < BB ; j++)
            {   /* XOR in the chain block. */
                pAlg->inputBlock[j] = pAlg->inputBlock[j]
                                 ^ pAlg->chainBlock[j];
            }
            RC5_Block_Encrypt(pAlg->S, pAlg->R,
                             pAlg->inputBlock,
                             pAlg->chainBlock);
            for (j = 0 ; j < BB ; j++)
            {   /* Output the ciphertext. */
                C[cipherIndex] = pAlg->chainBlock[j];
                cipherIndex++;
            }
        }
    }
    *pCipherLen = cipherIndex;
    return (1);
  }

  /* Produce the final block of ciphertext including any
   * padding, and then reset the algorithm object.
   * Return zero if problems.
   */
  int RC5_CBC_Encrypt_Final (pAlg, pCipherLen, maxCipherLen, C)
    rc5CBCAlg   *pAlg;
    int         *pCipherLen;    /* Gets byte len of C. */
    int          maxCipherLen;  /* Len of C buffer. */
    char        *C;             /* Ciphertext buffer. */
  {
    int     cipherIndex, j;
    int     padLength;

    /* For non-pad mode error if input bytes buffered. */
    *pCipherLen = 0;
    if ((pAlg->Pad == 0) && (pAlg->inputBlockIndex != 0))
        return (0);

    if (pAlg->Pad == 0)
        return (1);
    if (maxCipherLen < BB)
        return (0);

    padLength = BB - pAlg->inputBlockIndex;
    for (j = 0 ; j < padLength ; j++)
    {
        pAlg->inputBlock[pAlg->inputBlockIndex]
               = (char) padLength;
        pAlg->inputBlockIndex++;
    }
    for (j = 0 ; j < BB ; j++)
    {   /* XOR the chain block into the plaintext block. */
        pAlg->inputBlock[j] = pAlg->inputBlock[j]
                             ^ pAlg->chainBlock[j];
    }
    RC5_Block_Encrypt(pAlg->S, pAlg->R,
                      pAlg->inputBlock, pAlg->chainBlock);
    cipherIndex = 0;
    for (j = 0 ; j < BB ; j++)
    {   /* Output the ciphertext. */
        C[cipherIndex] = pAlg->chainBlock[j];
        cipherIndex++;
    }
    *pCipherLen = cipherIndex;

    /* Reset the CBC algorithm object. */
    return (RC5_CBC_SetIV(pAlg, pAlg->I));
  }