/*
CRYPTOGRAPHY COURSE FIng - UdelaR
Daniel Susviela
*/

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// sha function encryption uses openssl
void sha1Encrypt(char mess1[], unsigned char *res) {
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;

  OpenSSL_add_all_digests();

  md = EVP_get_digestbyname("SHA1");

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, mess1, strlen(mess1));
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);

  for (int i = 0; i < 20; i++) {
    res[i] = md_value[i];
  }
}

int main(int argc, unsigned char **argv) {
  if (argc != 3) {
    printf("Cantidad de parametros invalidos \n");
    printf("uso: ./hmac [string] [key] \n");
    return -1;
  }
  // obtain parameters from I/O
  unsigned char *text = argv[1];
  int textLen = strlen(text);
  unsigned char *k = argv[2];
  int b = strlen(k);
  unsigned char k0[19];

  /* for debugging purposes only */
  for (int i = 0; i < textLen; i++) {
    printf("%02x", text[i]);
  }
  printf("\n");
  printf("\n");

  // se obtiene la clave k0
  if (b == 20) {
    strcpy(k0, k);
  } else if (b < 20) {
    int charsFromKey = 0;
    int indexToFind = b - 1;
    for (int i = 19; i >= 0; i -= 1) {
      if (charsFromKey < b) {
        k0[i] = k[indexToFind];
        indexToFind -= 1;
        charsFromKey += 1;
      } else {
        k0[i] = 0;
      }
    }
  } else {
    unsigned char kAux[19];
    sha1Encrypt(k, kAux);
    strcpy(k0, kAux);
  }

  /* for debugging purposes only */
  for (int i = 0; i < 20; i++) {
    printf("%02x", k0[i]);
  }
  printf("\n");

  // calculo de s1 y s2
  unsigned char s1[19];
  unsigned char s2[19];
  for (int i = 0; i < 20; i++) {
    s1[i] = k0[i] ^ 0x36;  // 0x36 es la rep hexadecimal de ipad
    s2[i] = k0[i] ^ 0x5C;  // 0x36 es la rep hexadecimal de opad
  }

  /* for debugging purposes only */
  for (int i = 0; i < 20; i++) {
    printf("%02x", s1[i]);
  }
  printf("\n");
  for (int i = 0; i < 20; i++) {
    printf("%02x", s2[i]);
  }
  printf("\n");

  // calcular T'
  int auxLen = textLen + 20;
  unsigned char auxText[auxLen];
  strcpy(auxText, s1);
  strcat(auxText, text);
  printf("\n");
  /* for debugging purposes only */
  for (int i = 0; i < auxLen; i++) {
    printf("%02x", auxText[i]);
  }
  printf("\n");

  // se obtiene el resultado

  // imprimir resultado
  /*printf("El valor de HMAC es: ");
  for (int i = 0; i < resLen; i++)
    printf("%02x", res[i]);
  printf("\n"); */
}