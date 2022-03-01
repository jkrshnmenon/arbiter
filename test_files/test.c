#include <stdio.h>

int target_sink(int arg) {
    // do something important with arg
    return arg++;
}


void init_param(int *arg) {
    // initialize an argument passed as parameter
    *arg = 10;
    return;
}


int init_return_value() {
    // return a value when called
    return 10;
}


int entry_to_sink(int arg) {
    // data flow to be analyzed is from function entrypoint
    // (function argument in this case) to the sink.
    int tmp = arg + 10;
    return target_sink(tmp);
}


int source_param_to_sink() {
    // data flow to be analyzed is from argument passed to init_param
    // to the sink
    int arg = 0;
    init_param(&arg);
    int tmp = arg + 10;
    return target_sink(tmp);

}


int source_return_to_sink() {
    // data flow to be analyzed is from return value of init_return_value
    // to the sink
    int arg = init_return_value();
    int tmp = arg + 10;
    return target_sink(tmp);
}

int main() {
    return 0;
}