#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include <malloc.h>
#include "midstate.c"

typedef struct block_header {
  unsigned int    version;
  unsigned char   prev_block[32];
  unsigned char   merkle_root[32];
  unsigned int    timestamp;
  unsigned int    bits;
  unsigned int    nonce;
} block_header;

typedef struct job{
  unsigned int job_id;
  unsigned int version;
  unsigned int bits;
  unsigned int ntime;
  char* coinb1;
  unsigned int extranonce;
  char* coinb2;
  char prevhash [SHA256_BLOCK_SIZE];
  unsigned int merkle_count;
  char (*merkle_branch)[SHA256_BLOCK_SIZE];
}job;


void hexdump(unsigned char* data, int len)
{
  int c;
  c=0;
  while(c < len)
    {
      printf("%.2x", data[c++]);
    }
  printf("\n");
}

/* very very slow */
void byte_swap(unsigned char* data, int len) {
  int c;
  unsigned char tmp[len];
  c=0;
  while(c<len)
    {
      tmp[c] = data[len-(c+1)];
      c++;
    }
  c=0;
  while(c<len)
    {
      data[c] = tmp[c];
      c++;
    }
}

char *bin2hex(const unsigned char *p, size_t len)
{
  int i;
  char *s = (char *)malloc((len * 2) + 1);
  if (!s)
    return NULL;

  for (i = 0; i < len; i++)
    sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

  return s;
}

void hex2bin(unsigned char* dest, unsigned char* src)
{
  unsigned char bin;
  int c, pos;
  char buf[3];
  pos=0;
  c=0;
  buf[2] = 0;
  while(c < strlen(src))
    {
      buf[0] = src[c++];
      buf[1] = src[c++];
      dest[pos++] = (unsigned char)strtol(buf, NULL, 16);
    }
}


void init_job(job* job,unsigned int job_id,char prevhash[64],char *coinb1,char *coinb2,int merkle_count,char **merkle_branches,unsigned int version,unsigned int bits,unsigned int ntime) {
  job->job_id = job_id;
  hex2bin(job->prevhash,prevhash);
  job->version = version;
  job->bits = bits;
  job->ntime = ntime;
  int coinb1_len = strlen(coinb1);
  int coinb2_len = strlen(coinb2);
  job->coinb1 = (char *)malloc(coinb1_len/2);
  job->coinb2 = (char *)malloc(coinb2_len/2);
  job->extranonce = 0;
  hex2bin(job->coinb1,coinb1);
  hex2bin(job->coinb2,coinb2);
  job->merkle_count = merkle_count;
  int i;
  job->merkle_branch = malloc(merkle_count*sizeof *job->merkle_branch);
  for(i=0;i<merkle_count;i++) {
    hex2bin(job->merkle_branch[i],merkle_branches[i]);
  }
}

void free_job(job* job) {
  free(job->coinb1);
  free(job->coinb2);
  free(job->merkle_branch);
}

void dump_job(job job) {
  printf("Dumping Job...\n");
  printf("Merkle Count:%d\n",job.merkle_count);
  int i;
  printf("Merkle Branches:\n");
  for(i=0;i<job.merkle_count;i++){
    hexdump(job.merkle_branch[i],32);
  }
  printf("Coinbase 1:");
  hexdump(job.coinb1,58);
  printf("Coinbase 2:");
  hexdump(job.coinb2,51);
  printf("Dumping Job End\n");
  printf("===============\n");
}

/* double hash */
void dhash(char *data,int len,char *output){
  SHA256_CTX ctx1,ctx2;
  char buf1[SHA256_BLOCK_SIZE];
  char buf2[SHA256_BLOCK_SIZE];
  sha256_init(&ctx1);
  sha256_update(&ctx1,data,len);
  sha256_final(&ctx1,buf1);
  sha256_init(&ctx2);
  sha256_update(&ctx2,buf1,SHA256_BLOCK_SIZE);
  sha256_final(&ctx2,buf2);
  memcpy(output,buf2,SHA256_BLOCK_SIZE);
}

void getwork(job* job) {
  printf("Getwork Start\n");
  
  /* build coinbase */
  unsigned int extranonce = job->extranonce++;
  char nonce_bytes[4];
  nonce_bytes[0] = (extranonce >> 24) & 0xFF;
  nonce_bytes[1] = (extranonce >> 16) & 0xFF;
  nonce_bytes[2] = (extranonce >> 8) & 0xFF;
  nonce_bytes[3] = extranonce & 0xFF;
  char *coinbase = (char *)malloc(58+sizeof(int)+51);
  memcpy(coinbase,job->coinb1,58);
  memcpy(coinbase+58,nonce_bytes,4);
  memcpy(coinbase+62,job->coinb2,51);
  printf("Extranonce: ");
  hexdump(nonce_bytes,4);
  printf("Coinbase: ");
  hexdump(coinbase,113);

  /* build merkle_root */
  char* init_hash = (char *)malloc(SHA256_BLOCK_SIZE);
  dhash(coinbase,113,init_hash);
  printf("Coinbase_Hash: ");
  hexdump(init_hash,SHA256_BLOCK_SIZE);
  
  char* merkle_root=(char *)malloc(SHA256_BLOCK_SIZE);
  char* input = (char *)malloc(SHA256_BLOCK_SIZE*2);
  memcpy(input,init_hash,SHA256_BLOCK_SIZE);
  int i;
  for(i=0;i<job->merkle_count;i++){
    memcpy(input+SHA256_BLOCK_SIZE,job->merkle_branch[i],SHA256_BLOCK_SIZE);
    dhash(input,SHA256_BLOCK_SIZE*2,merkle_root);
    memcpy(input,merkle_root,SHA256_BLOCK_SIZE);
  };

  printf("Merkle_Root: ");
  hexdump(merkle_root,SHA256_BLOCK_SIZE);

  /* build blockheader */
  block_header header;
  header.version = 2;
  memcpy(header.prev_block,job->prevhash,SHA256_BLOCK_SIZE);
  memcpy(header.merkle_root,merkle_root,SHA256_BLOCK_SIZE);
  header.bits = job->bits;
  header.timestamp = job->ntime;
  header.nonce = 0;
  printf("Block_Header: ");
  hexdump((unsigned char*)&header,80);

  /* build midstate */
  char* midstate_input = (char *)malloc(64);
  memcpy(midstate_input,&header,64);
  sha256_state_t state;
  state = midstate(midstate_input);
  printf("Midstate: ");
  hexdump(state.byte,SHA256_BLOCK_SIZE);

  printf("GetWork End\n");
  printf("============\n");
}
  
void main() {
  job job;
  int job_id = 1;
  char prevhash[]="0000000000000000000000000000000000000000000000000000000000000000";
  char *merkles[] = {"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","5a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"};
  char coinb1[] = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008";
  char coinb2[] = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000";
  int version = 2;
  int bits = 486604799;
  int ntime = (unsigned)(time(NULL));
  init_job(&job,job_id,prevhash,coinb1,coinb2,2,merkles,2,bits,ntime);
  dump_job(job);
  getwork(&job);
  getwork(&job);
  getwork(&job);
  free_job(&job);
}
