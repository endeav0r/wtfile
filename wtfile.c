#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#define DISASM_SIZE 1024
#define DISASM_LIMIT (1024*512)
#define LIMIT_INT_SIZE 4096


struct _wtfile_writer {
    char * filename;
    FILE * fh;
};


#define endian32swap(XX) (  (XX >> 24) \
                           | ((XX >> 8) & 0xff00) \
                           | ((XX << 8) & 0xff0000) \
                           | ((XX << 24) & 0xff000000))

#define endian64swap(XX) (  (XX >> 54) \
                           | ((XX >> 40) & 0xff00) \
                           | ((XX >> 24) & 0xff0000) \
                           | ((XX >> 8)  & 0xff000000) \
                           | ((XX << 8)  & 0xff00000000) \
                           | ((XX << 24) & 0xff0000000000) \
                           | ((XX << 40) & 0xff000000000000) \
                           | ((XX << 54) & 0xff00000000000000))


struct _wtfile_writer * wtfile_writer_open (const char * filename) {
    struct _wtfile_writer * ww = (struct _wtfile_writer *) malloc(sizeof(struct _wtfile_writer));
    ww->filename = strdup(filename);
    ww->fh = fopen(filename, "wb");
    if (ww->fh == NULL) {
        fprintf(stderr, "error opening %s for writing\n", filename);
        exit(-1);
    }

    return ww;
}


void wtfile_writer_close (struct _wtfile_writer * ww) {
    free(ww->filename);
    fclose(ww->fh);
    free(ww);
}


void wtfile_writer_write (struct _wtfile_writer * ww,
                          const unsigned char * buf,
                          size_t size) {
    size_t bytes_written = fwrite(buf, 1, size, ww->fh);
    if (bytes_written != size) {
        fprintf(stderr, "error writing 0x%x bytes to %s\n", size, ww->filename);
        exit(-1);
    }
}


void check32le (const unsigned char * buf, size_t size) {
    unsigned int i;

    if (size > LIMIT_INT_SIZE)
        size = LIMIT_INT_SIZE;

    struct _wtfile_writer * ww = wtfile_writer_open("check32le.txt");

    char tmp[64];
    for (i = 0 ; i <= size - 4; i += 4) {
        uint32_t uint32 = *((uint32_t *) &(buf[i]));
        snprintf(tmp, 64, "%04x\t%08x\n", i, uint32);
        wtfile_writer_write(ww, tmp, strlen(tmp));
    }

    wtfile_writer_close(ww);
}


void check32be (const unsigned char * buf, size_t size) {
    unsigned int i;

    if (size > LIMIT_INT_SIZE)
        size = LIMIT_INT_SIZE;

    struct _wtfile_writer * ww = wtfile_writer_open("check32be.txt");

    char tmp[64];
    for (i = 0; i <= size - 4; i += 4) {
        uint32_t uint32 = *((uint32_t *) &(buf[i]));
        uint32 = endian32swap(uint32);
        snprintf(tmp, 64, "%04x\t%08x\n", i, uint32);
        wtfile_writer_write(ww, tmp, strlen(tmp));
    }

    wtfile_writer_close(ww);
}


void check64le (const unsigned char * buf, size_t size) {
    unsigned int i;

    if (size > LIMIT_INT_SIZE)
        size = LIMIT_INT_SIZE;

    struct _wtfile_writer * ww = wtfile_writer_open("check64le.txt");

    char tmp[64];
    for (i = 0; i <= size - 8; i += 8) {
        uint64_t uint64 = *((uint64_t *) &(buf[i]));
        snprintf(tmp, 64, "%04x\t%016llx\n", i, uint64);
        wtfile_writer_write(ww, tmp, strlen(tmp));
    }

    wtfile_writer_close(ww);
}


void check64be (const unsigned char * buf, size_t size) {
    unsigned int i;

    if (size > LIMIT_INT_SIZE)
        size = LIMIT_INT_SIZE;

    struct _wtfile_writer * ww = wtfile_writer_open("check64be.txt");

    char tmp[64];
    for (i = 0; i <= size - 8; i += 8) {
        uint64_t uint64 = *((uint64_t *) &(buf[i]));
        uint64 = endian64swap(uint64);
        snprintf(tmp, 64, "%04x\t%016llx\n", i, uint64);
        wtfile_writer_write(ww, tmp, strlen(tmp));
    }

    wtfile_writer_close(ww);
}


struct _capstone_op {
    unsigned int arch;
    unsigned int mode;
    char * description;
};


struct _capstone_op capstone_ops [] = {
    {CS_ARCH_ARM, CS_MODE_ARM, "ARM - ARM MODE"},
    {CS_ARCH_ARM, CS_MODE_THUMB, "ARM - THUMB MODE"},
    {CS_ARCH_ARM64, CS_MODE_ARM, "ARM64 - ARM MODE"},
    {CS_ARCH_MIPS, CS_MODE_MIPS32, "MIPS - MIPS32 MODE"},
    {CS_ARCH_MIPS, CS_MODE_MIPS64, "MIPS - MIPS64 MODE"},
    {CS_ARCH_MIPS, CS_MODE_MIPS32R6, "MIPS - MIPS32R6 MODE"},
    {CS_ARCH_X86, CS_MODE_16, "X86 - 16BIT MODE"},
    {CS_ARCH_X86, CS_MODE_32, "X86 - 32BIT MODE"},
    {CS_ARCH_X86, CS_MODE_64, "X86 - 64BIT MODE"},
    {CS_ARCH_PPC, CS_MODE_32, "PPC - 32BIT MODE"},
    {CS_ARCH_PPC, CS_MODE_64, "PPC - 64BIT MODE"},
    {-1, -1, NULL}
};


void check_disassembly (const unsigned char * buf, size_t size) {
    unsigned int i;

    struct _wtfile_writer * ww = wtfile_writer_open("disassembly.txt");

    if (size < DISASM_SIZE)
        return;

    for (i = 0; capstone_ops[i].description != NULL; i++) {
        struct _capstone_op * cop = &capstone_ops[i];

        csh handle;
        cs_insn * insn;
        size_t count;

        if (cs_open(cop->arch, cop->mode, &handle) != CS_ERR_OK) {
            fprintf(stderr,
                    "error opening %s in capstone, results may be incomplete\n",
                    cop->description);
            continue;
        }

        size_t offset = 0;
        for (offset = 0; offset < size - DISASM_SIZE; offset++) {
            if (offset > DISASM_LIMIT)
                break;
            count = cs_disasm(handle, &(buf[offset]), DISASM_SIZE, 0, 0, &insn);
            if (count > (DISASM_SIZE / 8)) {
                char tmp[4096];
/*************************** RESET INDENT *******************************/
uint32_t t;
t = snprintf(tmp, 4096, "--------------------------------------\n");
t += snprintf(&(tmp[t]), 4096 - t,
             "Possible disassembly for %s starting at 0x%x, skipping 64 bytes\n",
             cop->description, offset);
unsigned int j;
for (j = 0; j < 4; j++) {
    t += snprintf(&(tmp[t]), 4096 - t, "%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
}
t += snprintf(&(tmp[t]), 4096 - t, "\n");

wtfile_writer_write(ww, tmp, strlen(tmp));
offset += 63;
            }
        }
    }
}


int main (int argc, char * argv []) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <filename>\n", argv[0]);
        return -1;
    }

    FILE * fh = fopen(argv[1], "rb");
    if (fh == NULL) {
        fprintf(stderr, "I can't open your file %s, stupid\n", argv[1]);
        return -1;
    }

    fseek(fh, 0, SEEK_END);
    size_t filesize = ftell(fh);
    fseek(fh, 0, SEEK_SET);

    unsigned char * buf = (unsigned char *) malloc(filesize);

    size_t bytes_read = fread(buf, 1, filesize, fh);

    if (bytes_read != filesize) {
        fprintf(stderr, "Some stupid error while reading your file %s\n", argv[1]);
        return -1;
    }

    fclose(fh);

    check32le(buf, filesize);
    check32be(buf, filesize);
    check64le(buf, filesize);
    check64be(buf, filesize);
    check_disassembly(buf, filesize);

    free(buf);

    return 0;
}
