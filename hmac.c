/*
CRYPTOGRAPHY COURSE FIng - UdelaR
Daniel Susviela
*/

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// case for different errors
void exception(int id) {
  switch (id) {
    case 1: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo la creacion del contexto \n");
      break;
    }
    case 2: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo la busqueda de SHA1 en la libreria openssl \n");
      break;
    }
    case 3: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo la creacion de la clave en la libreria openssl");
      break;
    }
    case 4: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo la inicializacion del digest");
      break;
    }
    case 5: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo fallo el update del digest \n");
      break;
    }
    case 6: {
      printf("ERROR DE EJECUCION --------\n");
      printf("Fallo la obtencion del resultado del digest \n");
      break;
    }
    default:
      break;
  }
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

  // init of variables for implementation
  EVP_MD_CTX *mdContex = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *key0 = NULL;
  unsigned char res[EVP_MAX_MD_SIZE];
  size_t resLen = 0;

  OpenSSL_add_all_digests();

  // creates a context.
  // se crea un contexto de evp API alto nivel
  if (!(mdContex = EVP_MD_CTX_create()))
    exception(1);

  // se carga el digest SHA1
  if (!(md = EVP_get_digestbyname("SHA1")))
    exception(2);

  // se obtiene la clave y se indica que se trata de un HMAC
  if (!(key0 = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, k, b)))
    exception(3);

  // se inicializa un digest HMAC con el hash SHA1 que fue llamado anteriormente
  if (1 != EVP_DigestSignInit(mdContex, NULL, md, NULL, key0))
    exception(4);

  // se hace update con el texto para que se procese el mismo
  if (1 != EVP_DigestSignUpdate(mdContex, text, textLen))
    exception(5);

  // se obtiene el resultado del digest
  if (1 != EVP_DigestSignFinal(mdContex, res, &resLen))
    exception(6);

  // imprimir resultado
  printf("El valor de HMAC es: ");
  for (int i = 0; i < resLen; i++)
    printf("%02x", res[i]);
  printf("\n");
}