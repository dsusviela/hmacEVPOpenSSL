# Compila el main
Programa: 
	gcc -I/usr/local/ssl/include/ -L/usr/local/ssl/lib/ -o hmac hmac.c -lcrypto
#Limpia los .o
clean: 
	rm -f Programa *.o