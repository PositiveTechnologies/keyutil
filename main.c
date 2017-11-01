#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int clear_dump_data(unsigned char* mem, size_t memlen, BN_ULONG *d, size_t len)
{
    size_t off;
    if (len < 4) {
        return 0;
    }
    unsigned char *data = (unsigned char*)d;
    size_t blen = len * sizeof(BN_ULONG);

    off = 0;
    while (off + len < memlen) {
        if (memcmp(mem + off, data, blen)) {
            off++;
            continue;
        }
        printf("found match at 0x%lX\n", off);
        memset(mem + off, 0, blen);
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int fd;
    size_t dumplen;
    unsigned char *dump;
    const char *key;
    if (argc != 3) {
        printf("Usage: %s code.dump private.key\n", argv[0]);
        return 0;
    }
    fd = open(argv[1], O_RDWR, 0);
    if (fd == -1) {
        printf("Can not open dump file\n");
        return 1;
    }
    key = argv[2];

    dumplen = lseek(fd, 0, SEEK_END);

    if ((dump = mmap(NULL, dumplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        printf("Can not mmap dump file\n");
        close(fd);
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    FILE *fk = fopen(key, "r");
    if (fk == NULL) {
        printf("Can not open private key file\n");
        close(fd);
        return 1;
    }
    PEM_read_PrivateKey(fk, &pkey, NULL, NULL);
    fclose(fk);

    if (pkey) {
        switch (pkey->type) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA2: {
            printf("pkey RSA\n");
            RSA *rsa = pkey->pkey.rsa;
            clear_dump_data(dump, dumplen, rsa->n->d, rsa->n->top);
            clear_dump_data(dump, dumplen, rsa->e->d, rsa->e->top);
            clear_dump_data(dump, dumplen, rsa->d->d, rsa->d->top);
            clear_dump_data(dump, dumplen, rsa->p->d, rsa->p->top);
            clear_dump_data(dump, dumplen, rsa->q->d, rsa->q->top);
            clear_dump_data(dump, dumplen, rsa->dmp1->d, rsa->dmp1->top);
            clear_dump_data(dump, dumplen, rsa->dmq1->d, rsa->dmq1->top);
            clear_dump_data(dump, dumplen, rsa->iqmp->d, rsa->iqmp->top);
            printf("\n");
            break;
        }
        case EVP_PKEY_DSA:
        case EVP_PKEY_DSA1:
        case EVP_PKEY_DSA2:
        case EVP_PKEY_DSA3:
        case EVP_PKEY_DSA4: {
            printf("pkey DSA\n");
            DSA *dsa = pkey->pkey.dsa;
            clear_dump_data(dump, dumplen, dsa->p->d, dsa->p->top);
            clear_dump_data(dump, dumplen, dsa->q->d, dsa->q->top);
            clear_dump_data(dump, dumplen, dsa->g->d, dsa->g->top);
            clear_dump_data(dump, dumplen, dsa->pub_key->d, dsa->pub_key->top);
            clear_dump_data(dump, dumplen, dsa->priv_key->d, dsa->priv_key->top);
            clear_dump_data(dump, dumplen, dsa->kinv->d, dsa->kinv->top);
            clear_dump_data(dump, dumplen, dsa->r->d, dsa->r->top);
            break;
        }
        default:
            break;
        }
    }

    printf("exiting\n");
    EVP_cleanup();
    close(fd);
    return 0;
}
