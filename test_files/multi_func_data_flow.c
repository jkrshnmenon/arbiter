
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *multi_func_data_flow_sink(int sz) {
	char *p = (char *)malloc(sz);
	return p;
}


char *multi_func_data_flow_source(char *input) {
	int x = strlen(input);
	char *p = multi_func_data_flow_sink(x);
	return p;
}


int main() {
	char *ptr = multi_func_data_flow_source("AAAAAAA");
	return 0;
}
