/* vanitygen.c - Super Vanitygen - Vanity Bitcoin address generator */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "externs.h"

/* Number of secp256k1 operations per batch */
#define STEP 3072
#define BIG_STEP STEP*600000
#define THREADS_NUM 4
#define ADDRESS_NUM 2
#define ERROR_CREATE_THREAD     -11

#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"

#include "ripemd.h"


#define MY_VERSION "0.3"

const char fname_result[] = "found.txt";

const char *adr_to_find[] = {"1LzhS3k3e9Ub8i2W1V8xQFdB8n2MYCHPCa", "17aPYR1m6pVAacXg1PTDDU7XafvK1dxvhi"};

/* Global command-line settings */

/* Per-thread hash counter */
static uint64_t *thread_count;

//static unsigned long *thread_bytes;
//static uint64_t *thread_count2;

typedef struct {
    uint64_t *thread_count;
    int thread_num;
    int sock;
    unsigned int start_dbyte;
}   thread_struct_t;

static uint8_t *pattern_to_find[ADDRESS_NUM];

/* Socket pair for sending up results */
static int sock[2];

/* Static Functions */
static void manager_loop(int threads);
static void announce_result(int found, const uint8_t result[52]);
void *engine(void *args_);
static bool verify_key(const uint8_t result[52]);

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a);
static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b);
static void test_secp_lib();
//sup

void printScalar(secp256k1_scalar *scalar) {
    uint32_t *p=(uint32_t *)scalar->d;
    //sprintf(buf + strlen(buf), "%016lx%016lx%016lx%016lx", p[3],p[2],p[1],p[0]);
    //sprintf(buf + strlen(buf), "%016lx", p[0]);
    printf("Scalar hex %016lx\n", p[0]);
}
/*
secp256k1_scalar getRandomScalar8BytesVoid(void) {
    secp256k1_scalar scalar;
    uint64_t d = (uint64_t)(rand() & 0xFFFF) | (uint64_t)(rand() & 0xFFFF) << 16 | (uint64_t)(rand() & 0xFFFF) << 32 | (uint64_t)(rand() & 0xFFFF) << 48;
    memset(&scalar, 0, sizeof(scalar));
    memcpy(&scalar, &d, sizeof(d));
    return scalar;
}

secp256k1_scalar getRandomScalar8BytesU16(uint16_t setWord) {
    secp256k1_scalar scalar;
    uint16_t *s;
    uint64_t d = (uint64_t)(rand() & 0xFFFF) | (uint64_t)(rand() & 0xFFFF) << 16 | (uint64_t)(rand() & 0xFFFF) << 32 | (uint64_t)(rand() & 0xFFFF) << 48;
    memset(&scalar, 0, sizeof(scalar));
    memcpy(&scalar, &d, sizeof(d));
    s = (uint16_t *)scalar.d;
    s[3] = setWord;
    return scalar;
}
*/
void randScalar7Bytes(secp256k1_scalar *scalar, uint8_t b6, uint8_t b5, uint8_t b4) {
    uint8_t *p = (uint8_t *)scalar->d;
    memset(scalar, 0, sizeof(secp256k1_scalar));
    p[4] = b4;
    //p[5] = rand() & 0xFF;
    p[5] = b5;
    p[6] = b6;
    //scalartohex(buf, scalar);
    
}

// 5 bytes 3,5MH/s -> 314146 seconds -> 5235 mins -> 87 Hours -> 4 days
// 6 bytes -> 80421421 seconds -> 22339 hours -> 930 days


static bool add_prefix2(const char *prefix, uint8_t *pattern)
{
  /* Determine range of matching public keys */
  size_t pattern_sz=25;
  size_t b58sz=strlen(prefix);
  uint8_t pattern1[32];
  int j;

  if(!b58tobin(pattern1, &pattern_sz, prefix, b58sz)) {
    fprintf(stderr, "Error: Address '%s' contains an invalid character.\n",
            prefix);
    return 0;
  }

  printf("add prefix %s and its pattern ", prefix);
  for(j=1;j < 21;j++) printf("%02x", pattern1[j]);
  printf("\n");
  memcpy(pattern, pattern1+1, 20);
  
  return 1;
}

/**** Main Program ***********************************************************/

#define parse_arg()     \
  if(argv[i][j+1])      \
    arg=&argv[i][j+1];  \
  else if(i+1 < argc)   \
    arg=argv[++i];      \
  else                  \
    goto no_arg

static secp256k1_context *sec_ctx;
static secp256k1_scalar scalar_key, scalar_one={{1}}, scalar_step, scalar_bigstep;
static secp256k1_gej temp_offset;
static secp256k1_ge offset;

pthread_mutex_t mutex;

// Main program entry.
//
int main(int argc, char *argv[])
{
  int threads = THREADS_NUM;
  unsigned int start_dbyte = 0;
  int i, status;// ncpus=get_num_cpus(), threads=ncpus;
  char *arg;
  
      for (i = 1; i < argc; i++) {
            if (argv[i][0] != '-') break;
            switch (argv[i][1]) {
            case 't':
                i++;
                arg = strdup(argv[i]);
                threads = atoi(arg);
                free(arg);
                break;
            case 's':
                i++;
                arg = strdup(argv[i]);
                start_dbyte = 0xFFFFFF & atoi(arg);
                free(arg);
                break;
            default:
                goto end_arg;
            }
            continue;
        end_arg: break;
    }
    
    if (threads < 1 || threads > 4) threads = THREADS_NUM;
    if (start_dbyte == 0) {
        srand(time(NULL));
        start_dbyte = rand() & 0xFFFFFF;
    }
    printf("Starting arguments: threads %d, byte %04x\n", threads, start_dbyte);
    
    

  
  pthread_t pthreads[threads];
  thread_struct_t *args;

  args = (thread_struct_t *) malloc (sizeof(thread_struct_t) * threads);
  // Convert specified prefixes into a global list of public key byte patterns.
  
  for(i=0;i < ADDRESS_NUM; i++) {
    pattern_to_find[i] = (uint8_t*) malloc(sizeof(uint8_t) * 21);
    if(!add_prefix2(adr_to_find[i], pattern_to_find[i])) {
      goto error1;
    }
  }
  
  // Create memory-mapped area shared between all threads for reporting hash
  // counts.
  thread_count=mmap(NULL, threads*sizeof(uint64_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS/*|MAP_LOCKED*/, -1, 0);
  if(thread_count == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  //thread_count2=mmap(NULL, threads*sizeof(uint64_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS/*|MAP_LOCKED*/, -1, 0);
  //thread_bytes=mmap(NULL, threads*sizeof(uint64_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS/*|MAP_LOCKED*/, -1, 0);
  
  /* Create anonymous socket pair for children to send up solutions */
  if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sock)) {
    perror("socketpair");
    return 1;
  }

  /* Ignore signals */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  
  //one context for all threads
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_scalar_set_int(&scalar_step, STEP);
  secp256k1_scalar_set_int(&scalar_bigstep, BIG_STEP);
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &temp_offset, &scalar_one);
  secp256k1_ge_set_gej_var(&offset, &temp_offset);
  
  test_secp_lib();
  
  randScalar7Bytes(&scalar_key, (start_dbyte >> 16) & 0xFF, (start_dbyte >> 8) & 0xFF, (start_dbyte) & 0xFF);

  pthread_mutex_init(&mutex, NULL);
  for(i=0;i < threads;i++) {
    args[i].thread_num = i;
    args[i].thread_count = thread_count;
    args[i].sock = sock[1];
    args[i].start_dbyte = start_dbyte;
    status = pthread_create(&pthreads[i], NULL, engine, (void *)&args[i]);
    if (status != 0) {
        printf("main error: can't create thread, status = %d\n", status);
        exit(ERROR_CREATE_THREAD);
    }
  }


  manager_loop(threads);
  
  printf("Exit\n");
  
    /* Close the write end of the socketpair */
  close(sock[1]);
  close(sock[0]);
  
error1:
    for(i=0; i< ADDRESS_NUM;i++)
        free(pattern_to_find[i]);
  free(args);
  pthread_mutex_destroy(&mutex);
  return 1;
}

void *engine(void *args_)
{

  thread_struct_t *args = (thread_struct_t *)args_;
  secp256k1_gej base[STEP];
  secp256k1_ge rslt[STEP];
  secp256k1_scalar this_scalar_key;
  int thread = args->thread_num;
  int count_for_reset = 0;

  uint8_t sha_block[SHA256_DIGEST_LENGTH+1], result[52], *pubkey=result+32;
  uint64_t *key=(uint64_t *)result;
  int i, k;//, fd, len;
  int j;

  /* Main Loop */
  rekey:
  printf("\r");  // This magically makes the loop faster by a smidge
  /* Create group elements for both the random private key and the value 1 */
  count_for_reset = 0;
  
  pthread_mutex_lock(&mutex);
  secp256k1_scalar_clear(&this_scalar_key);
  secp256k1_scalar_add(&this_scalar_key, &scalar_key, &this_scalar_key);
  secp256k1_scalar_add(&scalar_key, &scalar_key, &scalar_bigstep);
  pthread_mutex_unlock(&mutex);
  
  for(k=0;k < STEP;k++) secp256k1_gej_clear(&base[k]);
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &base[0], &this_scalar_key);
  printf("Key in thread %d: ", thread);
  
  printScalar(&this_scalar_key);
  
  while(1) {
    for(k=1;k < STEP;k++)
      my_secp256k1_gej_add_ge_var(&base[k], &base[k-1], &offset);
    my_secp256k1_ge_set_all_gej_var(rslt, base);
  
    for(k=0;k < STEP;k++) {
      thread_count[thread]++;
      //thread_count2[thread]++;

      /* Extract the 33-byte compressed public key from the group element */
      sha_block[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02);
      secp256k1_fe_get_b32(sha_block+1, &rslt[k].x);

       /* Hash public key */
      HASH160(sha_block, pubkey);

      for(i=0;i < ADDRESS_NUM; i++) {
        if(0 == memcmp(pattern_to_find[i], pubkey, 15)) {
            secp256k1_scalar val1, val2;
            secp256k1_scalar_set_int(&val1, k);
            if (secp256k1_scalar_add(&val2, &this_scalar_key, &val1))
                printf("\nOverflow \n");
            secp256k1_scalar_get_b32((uint8_t*) key, &val2);
            printf("\nPrivate key found ");
            for(j=24;j < 32;j++) printf("%02x", result[j]);
            printf(" >>> ");
            for(;j < 52;j++) printf("%02x", result[j]);
            printf("\n");
            
            if(write(args->sock, result, 52) != 52)
                return NULL;
            
            goto rekey;
        }
      }
      
      count_for_reset++;
    }
    
    my_secp256k1_gej_add_ge_var(&base[0], &base[k-1], &offset);

    /* Increment privkey by STEP */
    if (secp256k1_scalar_add(&this_scalar_key, &this_scalar_key, &scalar_step)) {
        printf("\nOverflow \n");
        goto rekey;
    }
    
    if (count_for_reset >= BIG_STEP)
        goto rekey;
  }
  return NULL;
}

// Parent process loop, which tracks hash counts and announces new results to
// standard output.
//
#define MAX_COUNT_TRIGGER 0xFFFFFFFFUL
static void manager_loop(int threads)
{

  fd_set readset;
  struct timeval tv={1, 0};
  char msg[256];
  uint8_t result[52];
  uint64_t prev=0, last_result=0, count, avg, count_avg[8];
  int i, ret, len, found=0, count_index=0, count_max=0;

  FD_ZERO(&readset);

  while(1) {
    /* Wait up to 1 second for hashes to be reported */
    FD_SET(sock[0], &readset);
    if((ret=select(sock[0]+1, &readset, NULL, NULL, &tv)) == -1) {
      perror("select");
      return;
    }

    if(ret) {
      /* Read the (PrivKey,PubKey) tuple from the socket */
      if((len=read(sock[0], result, 52)) != 52) {
        /* Datagram read wasn't 52 bytes; ignore message */
        if(len != -1)
          continue;

        /* Something went very wrong if this happens; exit */
        perror("read");
        return;
      }

      /* Verify we received a valid (PrivKey,PubKey) tuple */
      if(!verify_key(result))
        continue;

      announce_result(++found, result);

      /* Reset hash count */
      for(i=0,count=0;i < threads;i++)
        count += thread_count[i];
      last_result=count;
      continue;
    }

    /* Reset the select() timer */
    tv.tv_sec=1, tv.tv_usec=0;

    /* Collect updated hash counts */
    for(i=0,count=0;i < threads;i++)
      count += thread_count[i];
    count_avg[count_index]=count-prev;
    if(++count_index > count_max)
      count_max=count_index;
    if(count_index == NELEM(count_avg))
      count_index=0;
    prev=count;
    count -= last_result;

    /* Average the last 8 seconds */
    for(i=0,avg=0;i < count_max;i++)
      avg += count_avg[i];
    avg /= count_max;

    sprintf(msg, "[%llu Kkey/s][Total %llu]", (avg+500)/1000, count);

    /* Display match count */
    if(found) {
        sprintf(msg+strlen(msg), "[Found %d]", found);
    }
    
    //for(i=0; i < threads; i++) {
      //if (thread_count2[i] > MAX_COUNT_TRIGGER) {
          //thread_count2[i] -= MAX_COUNT_TRIGGER;
          //printf("\nTriggered bytes %06lx\n", thread_bytes[i]);
          //thread_bytes[i]++;
      //}
    //}

    printf("\r%-78.78s", msg);
    fflush(stdout);
  }
}

static void announce_result(int found, const uint8_t result[52])
{
  uint8_t pub_block[RIPEMD160_DIGEST_LENGTH + 5] = {0,},checksum[SHA256_DIGEST_LENGTH], wif[35];
  int j;
  char buf[512];
  FILE *fp;
  
  memset(buf, 0, 256);

  printf("\n");

  /* Display matching keys in hexadecimal */
  sprintf(buf + strlen(buf),"Private match: ");
  for(j=0;j < 32;j++)
      sprintf(buf + strlen(buf), "%02x", result[j]);
  sprintf(buf + strlen(buf), "\nPublic match:  ");
  for(j=0;j < 20;j++)
      sprintf(buf + strlen(buf), "%02x", result[j+32]);

  /* Convert Public Key to Compressed WIF */
  memcpy(pub_block+1, result+32, 20);
  /* Compute checksum and copy first 4-bytes to end of public key */
  SHA256(pub_block, RIPEMD160_DIGEST_LENGTH + 1, checksum);
  SHA256(checksum, SHA256_DIGEST_LENGTH, checksum);
  memcpy(pub_block+21, checksum, 4);
  b58enc(wif, pub_block, sizeof(pub_block));

  sprintf(buf + strlen(buf), "\nAddress:       %s\n---\n", wif);
  printf("%s", buf);

  if ((fp=fopen(fname_result, "a+"))==NULL) {
    printf("Cannot open file %s\n", fname_result);
    exit (1);
  }
  fprintf(fp, "%s", buf);
  fclose(fp);
}


/**** Hash Engine ************************************************************/

// Per-thread entry point.
//


// Returns 1 if the private key (first 32 bytes of 'result') correctly produces
// the public key (last 20 bytes of 'result').
//
static bool verify_key(const uint8_t result[52])
{
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar;
  secp256k1_gej gej;
  secp256k1_ge ge;
  uint8_t sha_block[SHA256_DIGEST_LENGTH+1], rmd_block[SHA256_DIGEST_LENGTH], pubkey[20];
  int ret, overflow;

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  /* Copy private key to secp256k1 scalar format */
  secp256k1_scalar_set_b32(&scalar, result, &overflow);
  if(overflow) {
    secp256k1_context_destroy(sec_ctx);
    return 0;  /* Invalid private key */
  }

  /* Create a group element for the private key we're verifying */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &gej, &scalar);

  /* Convert to affine coordinates */
  secp256k1_ge_set_gej_var(&ge, &gej);

  /* Extract the 33-byte compressed public key from the group element */
  sha_block[0]=(secp256k1_fe_is_odd(&ge.y) ? 0x03 : 0x02);
  secp256k1_fe_get_b32(sha_block+1, &ge.x);

  /* Hash public key */
  SHA256(sha_block, sizeof(sha_block), rmd_block);
  RIPEMD160(rmd_block, sizeof(rmd_block), pubkey);
  

  /* Verify that the hashed public key matches the result */
  ret=!memcmp(pubkey, result+32, 20);

  secp256k1_context_destroy(sec_ctx);
  return ret;
}


/**** libsecp256k1 Overrides *************************************************/

static void my_secp256k1_fe_inv_all_gej_var(secp256k1_fe *r,
                                            const secp256k1_gej *a)
{
  secp256k1_fe u;
  int i;

  r[0]=a[0].z;

  for(i=1;i < STEP;i++)
    secp256k1_fe_mul(&r[i], &r[i-1], &a[i].z);

  secp256k1_fe_inv_var(&u, &r[--i]);

  for(;i > 0;i--) {
    secp256k1_fe_mul(&r[i], &r[i-1], &u);
    secp256k1_fe_mul(&u, &u, &a[i].z);
  }

  r[0]=u;
}

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a)
{
  static secp256k1_fe azi[STEP];
  int i;

  my_secp256k1_fe_inv_all_gej_var(azi, a);

  for(i=0;i < STEP;i++)
    secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[i]);
}

static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b)
{
  /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
  secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
  secp256k1_fe_sqr_inner(z12.n, a->z.n);
  u1 = a->x; 
  secp256k1_fe_normalize_weak(&u1);
  secp256k1_fe_mul_inner(u2.n, b->x.n, z12.n);
  s1 = a->y; 
  secp256k1_fe_normalize_weak(&s1);
  secp256k1_fe_mul_inner(s2.n, b->y.n, z12.n);
  secp256k1_fe_mul_inner(s2.n, s2.n, a->z.n);
  h.n[0] = 0xFFFFEFFFFFC2FULL * 4 - u1.n[0];  h.n[1] = 0xFFFFFFFFFFFFFULL * 4 - u1.n[1];  h.n[2] = 0xFFFFFFFFFFFFFULL * 4 - u1.n[2];  h.n[3] = 0xFFFFFFFFFFFFFULL * 4 - u1.n[3];  h.n[4] = 0x0FFFFFFFFFFFFULL * 4 - u1.n[4];
  h.n[0] += u2.n[0];  h.n[1] += u2.n[1];  h.n[2] += u2.n[2];  h.n[3] += u2.n[3];  h.n[4] += u2.n[4];
  i.n[0] = 0xFFFFEFFFFFC2FULL * 4 - s1.n[0];  i.n[1] = 0xFFFFFFFFFFFFFULL * 4 - s1.n[1];  i.n[2] = 0xFFFFFFFFFFFFFULL * 4 - s1.n[2];  i.n[3] = 0xFFFFFFFFFFFFFULL * 4 - s1.n[3];  i.n[4] = 0x0FFFFFFFFFFFFULL * 4 - s1.n[4];
  i.n[0] += s2.n[0];  i.n[1] += s2.n[1];  i.n[2] += s2.n[2];  i.n[3] += s2.n[3];  i.n[4] += s2.n[4];
  secp256k1_fe_sqr_inner(i2.n, i.n);
  secp256k1_fe_sqr_inner(h2.n, h.n);
  secp256k1_fe_mul_inner(h3.n, h.n, h2.n);
  secp256k1_fe_mul_inner(r->z.n, a->z.n, h.n);
  secp256k1_fe_mul_inner(t.n, u1.n, h2.n);
  r->x = t;
  r->x.n[0] *= 2; r->x.n[1] *= 2; r->x.n[2] *= 2; r->x.n[3] *= 2; r->x.n[4] *= 2;
  r->x.n[0] += h3.n[0];  r->x.n[1] += h3.n[1]; r->x.n[2] += h3.n[2];  r->x.n[3] += h3.n[3];  r->x.n[4] += h3.n[4];
  r->x.n[0] = 0xFFFFEFFFFFC2FULL * 8 - r->x.n[0];  r->x.n[1] = 0xFFFFFFFFFFFFFULL * 8 - r->x.n[1];  r->x.n[2] = 0xFFFFFFFFFFFFFULL * 8 - r->x.n[2];  r->x.n[3] = 0xFFFFFFFFFFFFFULL * 8 - r->x.n[3];  r->x.n[4] = 0x0FFFFFFFFFFFFULL * 8 - r->x.n[4];
  r->x.n[0] += i2.n[0];  r->x.n[1] += i2.n[1]; r->x.n[2] += i2.n[2];  r->x.n[3] += i2.n[3];  r->x.n[4] += i2.n[4];
  r->y.n[0] = 0xFFFFEFFFFFC2FULL * 12 - r->x.n[0];  r->y.n[1] = 0xFFFFFFFFFFFFFULL * 12 - r->x.n[1];  r->y.n[2] = 0xFFFFFFFFFFFFFULL * 12 - r->x.n[2];  r->y.n[3] = 0xFFFFFFFFFFFFFULL * 12 - r->x.n[3];  r->y.n[4] = 0x0FFFFFFFFFFFFULL * 12 - r->x.n[4];
  r->y.n[0] += t.n[0];  r->y.n[1] += t.n[1]; r->y.n[2] += t.n[2];  r->y.n[3] += t.n[3];  r->y.n[4] += t.n[4];
  secp256k1_fe_mul_inner(r->y.n, r->y.n, i.n);
  secp256k1_fe_mul_inner(h3.n, h3.n, s1.n);
  h3.n[0] = 0xFFFFEFFFFFC2FULL * 2 - h3.n[0];  h3.n[1] = 0xFFFFFFFFFFFFFULL * 2 -h3.n[1];  h3.n[2] = 0xFFFFFFFFFFFFFULL * 2 - h3.n[2];  h3.n[3] = 0xFFFFFFFFFFFFFULL * 2 - h3.n[3];  h3.n[4] = 0x0FFFFFFFFFFFFULL * 2 - h3.n[4];
  r->y.n[0] += h3.n[0];  r->y.n[1] += h3.n[1]; r->y.n[2] += h3.n[2];  r->y.n[3] += h3.n[3];  r->y.n[4] += h3.n[4];
}

static void test_secp_lib() {
    /* test secp lib */
  secp256k1_gej base[STEP];
  secp256k1_ge rslt[STEP];
  
  int j, k;
  secp256k1_scalar test_key = { 0, };
  uint8_t *test_p = (uint8_t *)test_key.d, test_sha[33];
  test_p[0] = 0x34; test_p[1] = 0x12;
  
  //test_p[6]=0x6a;  test_p[5]=0xbe;  test_p[4]=0x1f;  test_p[3]=0x9b;  test_p[2]=0x67;  test_p[1]=0xe1;  test_p[0]=0x12;
  
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &base[0], &test_key);
  for(k=1;k < STEP;k++)
      my_secp256k1_gej_add_ge_var(&base[k], &base[k-1], &offset);
  my_secp256k1_ge_set_all_gej_var(rslt, base);
  
      printf("---------\nTested keys : \n");
      
      printScalar(&test_key);
      
  for(k=0;k < 5;k++) {
    test_sha[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02);
    secp256k1_fe_get_b32(test_sha+1, &rslt[k].x);
    printf("%d : ", k);
    for(j=0;j < 33;j++) printf("%02x", test_sha[j]);
  
  unsigned char rmd_block[21], chksum[32], rmd_text[64] = { 0, }, buffer[26] = { 0, };
	HASH160(test_sha, rmd_block);
	buffer[0] = 0;
	memcpy(buffer + 1, rmd_block, 20);
	HASH256(buffer, chksum);
	memcpy(buffer + 21, chksum, 4);
	b58enc(rmd_text, buffer, 25);
	printf("-> %s\n", rmd_text);
  }
  printf("---------\n");
  
  
  /* end test */
  
}
