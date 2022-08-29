#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *single_func_data_flow(char *input) {
	int x = strlen(input);
	char *p = (char *)malloc(x);
	return p;
}


int main() {
	char *ptr = single_func_data_flow("AAAAAAA");
	return 0;
}

