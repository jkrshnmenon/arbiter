#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *foo(char *input) {
	int x = strlen(input);
	char *p = (char *)malloc(x);
	return p;
}


int main() {
	char *ptr = foo("AAAAAAA");
	return 0;
}

