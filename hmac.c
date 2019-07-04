#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  EVP_MD_CTX* mdctx = NULL;
  const EVP_MD* md = NULL;
  EVP_PKEY* pkey = NULL;

  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len = 0;

  char message[] =
      "Now is the time for all good men to "
      "come to the aide of their country\n";

  OpenSSL_add_all_digests();

  if (!(mdctx = EVP_MD_CTX_create()))
    handleError();

  if (!(md = EVP_get_digestbyname("SHA1")))
    handleError();

  if (!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, "password", strlen("password"))))
    handleError();

  if (1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey))
    handleError();

  /* Call update with the message */
  if (1 != EVP_DigestSignUpdate(mdctx, message, strlen(message)))
    handleError();

  if (1 != EVP_DigestSignFinal(mdctx, md_value, &md_len))
    handleError();

  printf("HMAC is: ");
  for (int i = 0; i < md_len; i++)
    printf("%02x", md_value[i]);
  printf("\n");
}