//gcc -m32 -z execstack -fno-stack-protector -g bof.c -o bof
#include <stdio.h>
 
#define BUFLEN 16
#define CHANGEDATA 1337
 
void win(){
        printf("Successfully redirected execution!");
}
 
void vulnerable(){
        int changeme = CHANGEDATA;
        char buffer[BUFLEN]; //Variables local to a function are stored on the stack.
 
        printf("changeme: %d\n", changeme);
 
	//loop until first character is a null byte or newline
        while(buffer[0] != 0 && buffer[0] != '\n'){

		gets(buffer); //easy buffer overflow, most dangerous function in all of C. Only newlines are bad here.
                puts(buffer);
                printf("Did you change the data?: %d\n", changeme);

                if(changeme == CHANGEDATA){
                        puts("Nope.");
                } else {
                        puts("Data changed!");
                }
        }
}
 
int main(){
        printf("Ready to exploit a vulnerability?");
        vulnerable();
}