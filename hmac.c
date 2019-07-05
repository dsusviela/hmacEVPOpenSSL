/*
CRYPTOGRAPHY COURSE FIng - UdelaR
Daniel Susviela
*/

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// case for different errors
void handleError() {
}

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Cantidad de parametros invalidos \n");
    printf("uso: ./hmac [string] [key] \n");
    return -1;
  }
  // obtain parameters from I/O
  char *text = argv[1];
  int textLen = strlen(text);
  char *k = argv[2];
  int b = strlen(k);

  printf("\n");
  printf("%s", k);
  printf("\n");
  printf("%s", text);
  printf("\n");

  // init of variables for implementation
  EVP_MD_CTX *mdContex = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *key0 = NULL;
  unsigned char res[EVP_MAX_MD_SIZE];
  int resLen = 0;

  OpenSSL_add_all_digests();

  if (!(mdContex = EVP_MD_CTX_create()))
    handleError();

  if (!(md = EVP_get_digestbyname("SHA1")))
    handleError();

  if (!(key0 = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, k, b)))
    handleError();

  if (1 != EVP_DigestSignInit(mdContex, NULL, md, NULL, key0))
    handleError();

  /* Call update with the text */
  if (1 != EVP_DigestSignUpdate(mdContex, text, textLen))
    handleError();

  if (1 != EVP_DigestSignFinal(mdContex, res, &resLen))
    handleError();

  printf("El valor de HMAC es: ");
  for (int i = 0; i < resLen; i++)
    printf("%02x", res[i]);
  printf("\n");
}