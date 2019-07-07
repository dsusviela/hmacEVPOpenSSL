/*
CRIPTOGRAFIA FIng - UdelaR
Daniel Susviela
*/

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// funcion auxiliar usada en el debugging
void print_byte_as_bits(char val) {
  for (int i = 7; 0 <= i; i--) {
    printf("%c", (val & (1 << i)) ? '1' : '0');
  }
}

// hash de SHA1
unsigned int sha1Hash(char mess1[], int len, unsigned char *res) {
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;
  /* 
  salida para debug

  printf("\n");
  printf("-----------");
  printf("\n");
  for (int i = 0; i < len; i++) {
    print_byte_as_bits(mess1[i]);
  }
  printf("\n");
  printf("-----------");
  printf("\n");
  printf("\n");

  printf("buscando el hash sha1");
  printf("\n");
  printf("\n");
  */

  md = EVP_get_digestbyname("SHA1");  // obtiene el hash sha
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, mess1, len);           // lo hashea
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);  // se obtiene el resultado

  /* 
  printf("Hash finished");
  printf("\n");
  */
  for (int i = 0; i < md_len; i++) {
    res[i] = md_value[i];  // guardar el resultado en res
    //printf("%02x", md_value[i]);
  }
  //printf("\n");
  //printf("\n");

  return md_len;  //devolver el largo
}

int main(int argc, unsigned char **argv) {
  if (argc != 3) {
    printf("Cantidad de parametros invalidos \n");
    printf("uso: ./hmac [string] [key] \n");
    return -1;
  }
  OpenSSL_add_all_digests();  // necesario una vez sola para el openssl
  // obtener los parametros
  unsigned char *text = argv[1];
  int textLen = strlen(text);
  unsigned char *k = argv[2];
  int keyLen = strlen(k);
  unsigned char *k0 = (unsigned char *)malloc(64);

  /* para debugear 
  printf("rep text: ");
  for (int i = 0; i < textLen; i++) {
    printf("%02x", text[i]);
  }
  printf("\n");
  printf("rep key: ");
  for (int i = 0; i < keyLen; i++) {
    printf("%02x", k[i]);
  }
  printf("\n");
  printf("\n");
  */

  // se obtiene la clave k0
  if (keyLen == 64) {  // largo deseado
    strcpy(k0, k);
  } else if (keyLen < 64) {  // mas chico
    int charsFromKey = 0;
    for (int i = 0; i < 64; i += 1) {
      if (charsFromKey <= keyLen) {
        k0[i] = k[charsFromKey];
        charsFromKey += 1;
      } else {
        k0[i] = 0;
      }
    }
  } else {  // mas grande
    unsigned char *kAux = (unsigned char *)malloc(64);
    memset(kAux, 0, 64);  // se hashea y se agregan 0s
    sha1Hash(k, 20, kAux);
    strcpy(k0, kAux);
  }

  /*  para debugear  
  printf("k0 result: ");
  for (int i = 0; i < 63; i++) {
    printf("%02x", k0[i]);
  }
  printf("\n");
  */

  // calculo de s1 y s2
  unsigned char *s1 = (unsigned char *)malloc(64);
  unsigned char *s2 = (unsigned char *)malloc(64);
  for (int i = 0; i < 64; i++) {
    s1[i] = k0[i] ^ 0x36;  // 0x36 es la rep hexadecimal de ipad
    s2[i] = k0[i] ^ 0x5C;  // 0x5C es la rep hexadecimal de opad
  }

  /*  para debugear   
  printf("s1 res: ");
  for (int i = 0; i < 64; i++) {
    printf("%02x", s1[i]);
  }
  printf("\n");
  printf("s2 res: ");
  for (int i = 0; i < 64; i++) {
    printf("%02x", s2[i]);
  }
  printf("\n");
  printf("\n");
  */

  // calcular T'
  // primero concatenar
  int auxLen = textLen + 64;
  unsigned char *concatenatedTextAndS1 = (unsigned char *)malloc(auxLen);
  strcpy(concatenatedTextAndS1, s1);

  /* 
  para debugear
  printf("PREVIO AL concat s1 y text en bits: ");
  for (int i = 0; i < auxLen; i++) {
    print_byte_as_bits(concatenatedTextAndS1[i]);
  }
  printf("\n");
  */
  strcat(concatenatedTextAndS1, text);
  /* para debugear 
  printf("s1 concat text: ");
  for (int i = 0; i < auxLen; i++) {
    printf("%02x", concatenatedTextAndS1[i]);
  }
  printf("\n");
  printf("s1 concat text en bits: ");
  for (int i = 0; i < auxLen; i++) {
    print_byte_as_bits(concatenatedTextAndS1[i]);
  }
  printf("\n");
  */

  // ahora si calcular el hash
  unsigned char tPrime[EVP_MAX_MD_SIZE];
  unsigned int tPrimeSize = sha1Hash(concatenatedTextAndS1, auxLen, tPrime);
  /* para debuggear
  printf("tprime: ");
  for (int i = 0; i < tPrimeSize; i++) {
    printf("%02x", tPrime[i]);
  }
  printf("\n");
  */

  // se obtiene el resultado
  int auxLen2 = 64 + tPrimeSize;
  unsigned char *concatenatedTextprimeAndS2 = (unsigned char *)malloc(auxLen2);
  strcpy(concatenatedTextprimeAndS2, s2);
  strcat(concatenatedTextprimeAndS2, tPrime);

  /* for debugging purposes only 
  printf("tprime and s2: ");
  for (int i = 0; i < auxLen2; i++) {
    printf("%02x", concatenatedTextprimeAndS2[i]);
  }
  printf("\n");
  printf("tprime and s2 bits: ");
  for (int i = 0; i < auxLen2; i++) {
    print_byte_as_bits(concatenatedTextprimeAndS2[i]);
  }
  printf("\n");
  printf("last hash: ");
  printf("\n");
  */

  unsigned char res[EVP_MAX_MD_SIZE];
  unsigned int resSize = sha1Hash(concatenatedTextprimeAndS2, auxLen2, res);
  //imprimir resultado
  printf("El valor de HMAC es: ");
  for (int i = 0; i < resSize; i++) {
    printf("%02x", res[i]);
  }
  printf("\n");
  printf("Su valor en bianrio es: ");
  for (int i = 0; i < resSize; i++) {
    print_byte_as_bits(res[i]);
  }
  printf("\n");
}