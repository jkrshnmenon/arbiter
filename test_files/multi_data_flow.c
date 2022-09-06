#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *multi_data_flow(char *input) {
	int x = strlen(input);
	char *p = (char *)malloc(x);
	memcpy(p, input, x);
	return p;
}


int main() {
	char *ptr = multi_data_flow("AAAAAAA");
	return 0;
}

