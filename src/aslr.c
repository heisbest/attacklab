#include <stdio.h>

int main() {
  int i = 42,j=43,p=44;         // This local variable is stored on the stack.
  printf("%p\n%p\n%p\n", &i,&j,&p); // Print the address of i.
  return 0;
}