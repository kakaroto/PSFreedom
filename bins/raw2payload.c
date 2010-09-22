/* raw2payload. Convert our raw PPC code into a fancy C header */

#include <stdio.h>
#include <string.h>

static const char header[] = \
  "#ifndef __%s__\n" \
  "#define __%s__\n\n" \
  "static const u8 %s[] = {\n ";

static const char footer[] = "\n};\n\n#endif\n";

int main(int argc, char **argv)
{
  char buf[256];
  FILE *fi, *fo;
  int i, idx, r;

  if (argc < 4) {
    fprintf(stderr, "Usage: %s <raw> <c header> <array name>\n", argv[0]);
    return -1;
  }

  fi = fopen(argv[1], "r");
  if (fi == NULL) {
    perror(argv[1]);
    return -2;
  }

  fo = fopen(argv[2], "w");
  if (fo == NULL) {
    perror(argv[2]);
    return -3;
  }

  fprintf(fo, header, argv[3], argv[3], argv[3]);

  idx = 0;
  while ((r = fread(buf, 1, sizeof(buf), fi)) > 0) {
    for (i = 0; i < r; i++) {
      fprintf(fo, " 0x%.2x,", buf[i] & 0xff);
      if (++idx % 8 == 0)
	fprintf(fo, "\n ");
    }
  }

  fprintf(fo, "%s", footer);

  fclose(fi);
  fclose(fo);
  fprintf(stdout, "Header %s generated.\n", argv[3]);
  return 0;
}
