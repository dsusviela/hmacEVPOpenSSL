/*
CRYPTOGRAPHY COURSE FIng - UdelaR
Daniel Susviela
*/

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_byte_as_bits(char val) {
  for (int i = 7; 0 <= i; i--) {
    printf("%c", (val & (1 << i)) ? '1' : '0');
  }
}

// sha function encryption uses openssl
unsigned int sha1Hash(char mess1[], unsigned char *res) {
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;
  int len = strlen(mess1);
  printf("\n");
  printf("-----------");
  printf("\n");
  for (int i = 0; i < len; i++) {
    print_byte_as_bits(mess1[i]);
  }
  printf("\n");
  printf("-----------");
  printf("\n");

  OpenSSL_add_all_digests();

  printf("\n");
  printf("---abri tranqui los digest--------");
  printf("\n");

  md = EVP_get_digestbyname("SHA1");
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, mess1, strlen(mess1));
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);

  for (int i = 0; i < md_len; i++) {
    res[i] = md_value[i];
  }
  return md_len;
}

int main(int argc, void **argv) {
  if (argc != 3) {
    printf("Cantidad de parametros invalidos \n");
    printf("uso: ./hmac [string] [key] \n");
    return -1;
  }
  // obtain parameters from I/O
  unsigned char *text = argv[1];
  int textLen = strlen(text);
  char *k = argv[2];
  int b = strlen(k);
  unsigned char *k0 = (unsigned char *)malloc(19);

  /* for debugging purposes only */
  printf("rep text: ");
  for (int i = 0; i < textLen; i++) {
    printf("%02x", text[i]);
  }
  printf("\n");
  printf("rep key: ");
  for (int i = 0; i < b; i++) {
    printf("%02x", k[i]);
  }
  printf("\n");
  unsigned char auxTest[19];
  unsigned int topeAuxTest = sha1Hash(k, auxTest);
  for (int i = 0; i < topeAuxTest; i++) {
    printf("%02x", auxTest[i]);
  }
  printf("\n");
  printf("%d", topeAuxTest);
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
    unsigned char *kAux = (unsigned char *)malloc(19);
    sha1Hash(k, kAux);
    strcpy(k0, kAux);
  }

  /* for debugging purposes only */
  for (int i = 0; i < 20; i++) {
    printf("%02x", k0[i]);
  }
  printf("\n");

  // calculo de s1 y s2
  unsigned char *s1 = (unsigned char *)malloc(19);
  unsigned char *s2 = (unsigned char *)malloc(19);
  for (int i = 0; i < 20; i++) {
    s1[i] = k0[i] ^ 0x36;  // 0x36 es la rep hexadecimal de ipad
    s2[i] = k0[i] ^ 0x5C;  // 0x5C es la rep hexadecimal de opad
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
  printf("\n");

  // calcular T'
  // primero concatenar
  int auxLen = textLen + 19;
  unsigned char *concatenatedTextAndS1 = (unsigned char *)malloc(auxLen);
  strcpy(concatenatedTextAndS1, s1);
  strcat(concatenatedTextAndS1, text);
  /* for debugging purposes only */
  for (int i = 0; i < auxLen; i++) {
    printf("%02x", concatenatedTextAndS1[i]);
  }
  printf("\n");

  // ahora si calcular el hash
  unsigned char *tPrime = (unsigned char *)malloc(19);
  unsigned int tPrimeSize = sha1Hash(concatenatedTextAndS1, tPrime);
  for (int i = 0; i < tPrimeSize; i++) {
    printf("%02x", tPrime[i]);
  }
  printf("\n");

  // se obtiene el resultado
  int auxLen2 = strlen(s2) + strlen(tPrime) - 2;  // notar que tPrime len es 20, idem s2
  unsigned char *concatenatedTextprimeAndS2 = (unsigned char *)malloc(auxLen2);
  strcpy(concatenatedTextprimeAndS2, s2);
  strcat(concatenatedTextprimeAndS2, tPrime);
  /* for debugging purposes only */
  for (int i = 0; i < auxLen2; i++) {
    print_byte_as_bits(concatenatedTextprimeAndS2[i]);
  }
  printf("\n");
  printf("asjkhdasjk");
  printf("\n");
  unsigned char *res = (unsigned char *)malloc(19);
  unsigned int resSize = sha1Hash(concatenatedTextprimeAndS2, res);
  //imprimir resultado
  printf("El valor de HMAC es: ");
  for (int i = 0; i < resSize; i++) {
    printf("%02x", res[i]);
  }
  printf("\n");
  for (int i = 0; i < resSize; i++) {
    print_byte_as_bits(res[i]);
  }
  printf("\n");
}