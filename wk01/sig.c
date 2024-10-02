#include <stdlib.h>
#include <stdio.h>

void fillPointer(char* p)
{
  printf("%s", p);
  *p = 'A';
}

int main(void)
{
  char* pointer = 0;
  fillPointer(pointer);
}
