
//#include "printf.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
/* Typedef */

typedef int boolean;
//typedef void* MemoryAdr;
/* Variable */

#define FAST_MAX_SIZE 0x7F

#define FASTBIN_NUMBER 7
#define SMALLBIN_NUMBER 1000//이것도 일단 24개로
//#define SMALLBIN_NUMBER 24
#define LARGEBIN_NUMBER 100 //일단 100개로
//#define SMALLBIN_MAX 0x200
#define SMALLBIN_MAX 0x3f00

#define DEFAULT_SIZE 0x260000
//#define DEFAULT_SIZE 0x1300000

#define TRUE 1
#define FALSE 0

#define PREV_INUSE 0x1

#define prev_inuse(p) ((p)->size & PREV_INUSE)

#define IS_MMAPPED 0x2

#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)

#define NON_MAIN_ARENA 0x4

#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

#define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)

#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) (((MemoryAdr)( ((char*)(p)) + ((p)->size & ~SIZE_BITS) ))

/* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) (((MemoryAdr)( ((char*)(p)) - ((p)->prev_size) ))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((MemoryAdr)(((char*)(p)) + (s)))

/* extract p's inuse bit */
#define inuse(p) \
((((MemoryAdr)(((char*)(p))+((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p) \
((MemoryAdr)(((char*)(p)) + ((p)->size & ~SIZE_BITS)))->size |= PREV_INUSE

#define clear_inuse(p) \
((MemoryAdr)(((char*)(p)) + ((p)->size & ~SIZE_BITS)))->size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s) \
(((MemoryAdr)(((char*)(p)) + (s)))->size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s) \
(((MemoryAdr)(((char*)(p)) + (s)))->size |= PREV_INUSE)

/* need security check routine! */
#define unlink(P, BK, FD){  \
        FD = P->fd;         \
        BK = P->bk;         \
        FD->bk = BK;        \
        BK->fd = FD;        \
}

/* Structure  */

typedef struct _MallInfoA {
        int ordblks; /* number of free chunks */
        int unsortedbin_number;
        int smallbin_number;
        int largebin_number;
        int fastbin_number; /* number of fastbin blocks */
        int uordblks; /* total allocated space */
        int fordblks; /* total free space */
        int first;
}MallInfoA;

//extern MallInfoA mallinfoA;

/*그냥 캐스팅 용도로만 사용할까*/
typedef struct _Malloc_Chunk {
        long long int prev_size;           /* Size of previous chunk (if free).  */
        long long int size;                /* Size in bytes, including overhead. */
        struct _Malloc_Chunk* fd;    /* double links -- used only if free. */
        struct _Malloc_Chunk* bk;
        /*아 할필요가 없구나 그냥 size만 입력하면 되니까*/
}Malloc_Chunk;

typedef Malloc_Chunk* MemoryAdr;

typedef struct _Malloc_State {
        long long int max_fast;
        MemoryAdr top;
        Malloc_Chunk* fastbin[FASTBIN_NUMBER];
        Malloc_Chunk* unsortedbin;
        Malloc_Chunk* smallbin[SMALLBIN_NUMBER];
        Malloc_Chunk* largebin[LARGEBIN_NUMBER];
        Malloc_Chunk* unsortedbin_head;
        Malloc_Chunk* smallbin_head[SMALLBIN_NUMBER];
        Malloc_Chunk* largebin_head;
}Malloc_State;

MallInfoA mallinfoA = {0, 0, 0, 0, 0, 0, 0, 0};
Malloc_State malloc_state;

//typeef Malloc_Chunk* MemorAdr;

//extern Malloc_State malloc_state;

/* malloc  Function */
MemoryAdr myalloc(size_t size);
boolean check_first_allocate();
int init_Malloc(boolean init);
void malloc_error(const char* ErrMsg, boolean exist);
int make_align(size_t size);
boolean find_fastbin_chunk(MemoryAdr* chunk_address, size_t size);
boolean find_unsortedbin_chunk(MemoryAdr* chunk_address, size_t size);
boolean find_smallbin_chunk(MemoryAdr* chunk_address, size_t size);
int division_TopChunk(MemoryAdr* chunk_address, size_t size);
boolean check_top_chunk_size(size_t size);


int set_inuse_bit(MemoryAdr* chunk_address);
int clear_inuse_bit_at_offset(MemoryAdr freed_chunk, size_t size);
int clear_inuse_bit(MemoryAdr chunk_address);
/* free Function */
void myfree(void* chunk);
void set_fastbin(MemoryAdr freed_chunk, size_t size);
void set_unsortedbin(MemoryAdr freed_chunk, size_t size);
void set_smallbin(MemoryAdr freed_chunk, size_t size);
boolean check_mmap_syscall(MemoryAdr freed_chunk);
boolean check_prev_inuse(MemoryAdr freed_chunk);

/* realloc Fcuntion*/
void* myrealloc(void* chunk, size_t size);
/*
function set_smallbin();
function
*/
/* DEBUG */
void debug_search_list();
//void DebugMode(void* arg);



/* realloc함수는 free하고 malloc 한다.*/

void* myrealloc(void* chunk, size_t size)
{
  //printf("[DEBUG] Realloc Brain Pack input pointer and size : %p %lx\n", chunk, size);
  if(__builtin_expect(size == 0 || chunk == NULL, 0)){
    malloc_error("realloc error", FALSE);
    //printf("[DEBUG] REALLOC Brian Pack input NULL\n");
    return myalloc(size);

  }
  myfree(chunk);
  //printf("[DEBUG] OHH!\n");
  return myalloc(size);
}



//size에 AMP bit 포함시켜야 함
/*메모리 할당중 bin에 없을 경우 top chunk의 주소값을 슬쩍하며 top chunk의 size와 주소값을 변경 */
// 만약 top chunk가 모자르다면 이 것도 추가해야 하네
//printf("[CHECK] 1 step\n");
MemoryAdr myalloc(size_t size)
{
  //printf("[DEBUG] Brian Pack input size : %lx\n", size);
 	MemoryAdr chunk_address = NULL;
  size = make_align(size);
  //printf("[DEBUG] Malloc Brain Pack input size : %lx\n", size);
	if(!check_first_allocate()){
        //printf("[DEBUG] check first allocate!\n");
        /* if first call malloc */
        init_Malloc(TRUE);
        //printf("[DEBUG] initial malloc\n");
        /* Top chunk 분할 */
        division_TopChunk(&chunk_address, size); //이중 포인터로 넘겨야 함.
        //printf("[DEBUG] division_TopChunk\n");
        /* 바로 메모리 할당 하면 됨 (fastbin 등 탐색 ㄴㄴ)*/
    }
    else{
      //check fastbin or unsorted bin or small bin
      //find fastbin chunk
      if(size >= 0x20 && size <= FAST_MAX_SIZE){
        if(!find_fastbin_chunk(&chunk_address, size)){ //return 0, don't exist chunk
          //printf("[DEBUG] failed fastbin chunk!\n");
          //top chunk 부족한감
          if(!check_top_chunk_size(size)){
            init_Malloc(FALSE);
          }
          //printf("[DEBUG] OK1\n");
          division_TopChunk(&chunk_address, size);
          //printf("[DEBUG] OK2 : %p\n", chunk_address);
        }
      }
      // find unsortedbin chunk
      else if(FAST_MAX_SIZE<size && size <= SMALLBIN_MAX){
        //debug_search_list();
        //printf("[CHECK] 1 step\n");
      //debug_search_list();
        if(!find_unsortedbin_chunk(&chunk_address, size)){ //return 0 don't exist chunk
          //printf("[CHECK] 2 step\n");
          //printf("[DEBUG] : failed unsortedbin!\n");
          //printf("[DEBUG] OK I will take this size : %ld\n", size);
          if(!find_smallbin_chunk(&chunk_address, size)){
              //printf("[CHECK] 3 step\n");
              //printf("[DEBUG] OK!\n");
              //top chunk가 부족한감
              if(!check_top_chunk_size(size)){
                //printf("[CHECK] 4 step\n");
                init_Malloc(FALSE);
                //printf("[CHECK] 8 step\n");
              }
              division_TopChunk(&chunk_address, size);
              //printf("[CHECK] 5 step\n");
                // top chunk 분할
          }
        }
        //printf("[DEBUG] : returning pointer : %p\n", chunk_address);
        //printf("[CHECK] 6 step\n");
      }
      //other size
      else{
        //printf("[DEBUG] OK Other size\n");
        if(!check_top_chunk_size(size)){
          init_Malloc(FALSE);
        }
        division_TopChunk(&chunk_address, size);
      }
    }
    //set_inuse(chunk_address); //prev inuse bit set 여기 둬도 되는가
    MemoryAdr userspace = chunk_at_offset(chunk_address, 16);
    //printf("Test : %p\n", userspace);
    set_inuse_bit(&chunk_address);
    //printf("[DEBUG] chunk : %p\n", (chunk_address));
    //printf("[DEBUG] chunk size : %lld\n", (chunk_address->size));
    return (void*)userspace;
    //return (void*)chunk_at_offset(chunk_address, 16); //usersapce
    //return chunk_address+2; //userspace
}

boolean check_top_chunk_size(size_t size)
{
  if(__builtin_expect(malloc_state.top->size < (size*2), 0)){
    return 0;
  }
  return 1;
}

int division_TopChunk(MemoryAdr* chunk_address, size_t size)
{
  /* top chunk 분할  */
  size_t top_size = malloc_state.top->size;
  *chunk_address = malloc_state.top;
  (*chunk_address)->size = size;
  //printf("[DEBUG] : userspace addr %p\n", *chunk_address);
  //printf("[DEBUG] Top chunk ptr : %p and size : %lld\n", *chunk_address, (*chunk_address)->size);

  //printf("[DEBUG] division chunk address -> size : %lld\n", (*chunk_address)->size);
  //set_inuse(*chunk_address);
  //printf("[DEBUG] Top chunk ptr : %p and size : %lld\n", *chunk_address, (*chunk_address)->size);
  top_size -= size;
  //printf("[DEBUG] test case top : %p, size : %lx\n",malloc_state.top, size);
  malloc_state.top = chunk_at_offset(malloc_state.top, size);

  malloc_state.top->size = top_size;
  //printf("[DEBUG] Top Chunk Pointer and Size is : %p %lld\n", malloc_state.top ,malloc_state.top->size);
  //printf("[DEBUG] Test1\n");

  //printf("[DEBUG] Top chunk ptr : %p and size : %lld\n", malloc_state.top, malloc_state.top->size);
  //malloc_state.top += (size/8);
  /*printf("[DEBUG] : top -> %p\n",malloc_state.top); */
  //malloc_state.top->size = top_size;
  return 0;
}

/*
free시 fastbin에 넣는 프로토콜
if(fastbin[index] == NULL)
A->fd = NULL;
fastbin[index] =A; (1)
B->fd = A;
fastbin[index] = B; (2)
*/
//bin에 대한 초기화나 음 .. free할 때 어떻게 bin에 넣을것인가등 프로토콜이 있어야 할텐데
/* LIFO 방식  리스트의 원소를 어떻게 제거하지
   그냥 대입하는 방식으로 제거하지.
*/
boolean find_fastbin_chunk(MemoryAdr* chunk_address, size_t size)
{
  int index = (size/16)-2;
  //printf("[DEBUG] index : %d\n", index);
  //Malloc_Chunk* curr = fastbin[index];
  if(malloc_state.fastbin[index] != NULL){
    if(__builtin_expect(malloc_state.fastbin[index]->size != size, 0)){
      malloc_error("fastbin size is not equal!", FALSE);
    }
      //printf("[DEBUG] fastbin chunk addrss : %p\n", malloc_state.fastbin[index]);
      *chunk_address = malloc_state.fastbin[index];
      malloc_state.fastbin[index] = malloc_state.fastbin[index]->fd;
      mallinfoA.fastbin_number -= 1;
      mallinfoA.ordblks -=1;
      (*chunk_address)->size = size;
      //set_inuse(*chunk_address);//////////////////////////////////////
      return 1;
  }
  else{ //if not found
    return 0;
  }
}
/*
  free함수가 unsortedbin에 넣는 과정은 chunk_at_offset
  ** mallinfo.unsortedbin_number+=1;
  int size = chunksize(freed_chunk)
  if(chunk_at_offset(freed_chunk, size) != mallinfo.top){
    clear_inuse_bit_at_offset(freed_chunk, size);
  }
  if(unsortedbin == NULL){
    malloc_state->unsortedbin_head = (Malloc_Chunk*)freed_chunk;
    (Malloc_Chunk*)freed_chunk->fd = (Malloc_Chunk*)freed_chunk;
    (Malloc_Chunk*)freed_chunk->bk = (Malloc_Chunk*)freed_chunk;
  }
  else{
    (Malloc_Chunk*)freed_chunk->fd = malloc_state->unsortedbin;
    (Malloc_Chunk*)freed_chunk->bk = malloc_state->unsortedbin_head;
    malloc_state->unsortedbin_head->fd = freed;
    malloc_state->unsortedbin->bk = freed;
  }
  malloc_state->unsortedbin = (Malloc_Chunk*)freed_chunk;
  ...
*/
/*
만약 while문을 돌리면서 unsortedbin의 끝은 어떻게 파악할 것인가?
if curr-> unsortedbin의 개수로?
*/
/* 한번의 재사용 기회가 끝나면 적절한 bin으로 이동한다.  */

void debug_search_list()
{
  Malloc_Chunk* curr =malloc_state.unsortedbin_head;
  //printf("[DEBUG] unsortedbin number : %d\n", mallinfoA.unsortedbin_number);
  for(int index=0;index<mallinfoA.unsortedbin_number;index++){
    //printf("[DEBUG] Unsortedbin Addr : %p\n", curr);
    curr  = curr->bk;
  }
}

boolean find_unsortedbin_chunk(MemoryAdr* chunk_address, size_t size)
{
  Malloc_Chunk* fwd; //temp fd
  Malloc_Chunk* bkd; //temp bk
  Malloc_Chunk* curr = malloc_state.unsortedbin_head;

  int count = mallinfoA.unsortedbin_number;
  //printf("[DEBUG] unsortedbin_number : %d\n", mallinfoA.unsortedbin_number);
  for(int index=0; index<count;index++){
    if(chunksize(curr) == size){
      if(curr == malloc_state.unsortedbin_head){ //빠져나가는 쪽이 head라면
        if(malloc_state.unsortedbin_head->bk == malloc_state.unsortedbin_head){
          //printf("[DEBUG] SAME!\n");
          malloc_state.unsortedbin_head = NULL; //만약 하나의 chunk가 남았다면 unlink 노필ㅇ
          malloc_state.unsortedbin = NULL;
          (*chunk_address) = curr;
          mallinfoA.unsortedbin_number-=1;
          mallinfoA.ordblks -=1;
          return 1;
        }
        malloc_state.unsortedbin_head = curr->bk; //head가 빠져나간다면 ???
      }
      (*chunk_address) = curr;
      //debug_search_list();
      unlink(curr, fwd, bkd); //get OUT! 만약 head가 빠져나간다면?
      mallinfoA.unsortedbin_number-=1;
      //debug_search_list();
      mallinfoA.ordblks -=1;
      return 1;
    }
    else{
      if(chunksize(curr) >= 0x80 && chunksize(curr) <= SMALLBIN_MAX){ //smallbin
        //printf("[DEBUG] set smallbin!\n");
        if(curr ==malloc_state.unsortedbin_head){
          if(malloc_state.unsortedbin_head->bk == malloc_state.unsortedbin_head){
            malloc_state.unsortedbin_head = NULL;
            malloc_state.unsortedbin = NULL;
            set_smallbin(curr, chunksize(curr));
          }
        }
        else{
          unlink(curr, fwd, bkd)
          set_smallbin(curr, chunksize(curr));
        }
        mallinfoA.unsortedbin_number -=1;
      }
      else{ //largebin
        //set_largebin();
        //mallinfoA.unsortedbin_number -=1;
      }
    }
    curr = curr->bk;
  }
  return 0;
}

boolean find_smallbin_chunk(MemoryAdr* chunk_address, size_t size)
{
  Malloc_Chunk* fwd;
  Malloc_Chunk* bkd;
  int index = (size/16) - 8;
  //printf("[DEBUG] index : %d\n", index);
  if(malloc_state.smallbin[index] == NULL){
    return 0;
  }
  else{
    //printf("[DEBUG] smallbin[0] : %p and size : %lld compare : %ld\n", malloc_state.smallbin[index], chunksize(malloc_state.smallbin[index]), size);
    if(__builtin_expect(chunksize(malloc_state.smallbin[index]) != size, 0)){
      malloc_error("smallbin size is non equal!", FALSE);
    }
    //chunk가 혼자인가도 검사
    if(malloc_state.smallbin[index]->fd == malloc_state.smallbin[index]){
      (*chunk_address) = malloc_state.smallbin[index];
      malloc_state.smallbin[index] = NULL;
    }
    else{
      (*chunk_address) = malloc_state.smallbin[index];
      unlink(malloc_state.smallbin[index], fwd, bkd);
      malloc_state.smallbin[index] = malloc_state.smallbin[index]->bk;
    }
    mallinfoA.ordblks -= 1;
  }
  //printf("[DEBUG] fine smallbin %p\n", *chunk_address);
  //smallbin의 경우 순회할 필요 없이 그냥 바로 크기에 맞는거 찾아서 unlink때리면 안되나?
  return 1;
}


/* mallinfo.uordblks는 top chunk떄문에 처음이 아니라면 1 이상의 값을 가지고 있을 것이다. */
boolean check_first_allocate()
{
  if(mallinfoA.first != 0){
    return TRUE; //None First
  }
  else{
    return FALSE; //first
  }
}
/* 할당된 개체들을 따로 관리할 필요는 없는건가  관리를 한다면 어떻게 관리 할 것인가*/
/* 따로 관리가 필요할까 그때 그때 할당된 메모리를 반환하면 사용자가 알아서 해결하지 않을 까 */
int init_Malloc(boolean init)
{
  /*allocate top chunk*/
  malloc_state.top = sbrk(DEFAULT_SIZE);
  if(__builtin_expect(malloc_state.top == (void*)-1, 0)){ //참이라면
    malloc_error("sbrk() system call Failed" ,FALSE);
  }
  malloc_state.top->size += DEFAULT_SIZE;
  //printf("[DEBUG] initial top chunk address : %p\n", malloc_state.top);
  /*init mallinfo */
  mallinfoA.uordblks += DEFAULT_SIZE;
  /*init bins*/
  if(init == TRUE){ //top chunk의 추가적인 할당이 아닌 아예 초기 할당일시
    malloc_state.max_fast = FAST_MAX_SIZE;
    for(int i=0;i<FASTBIN_NUMBER;i++){
      malloc_state.fastbin[i] = NULL;
    }
    for(int i=0;i<SMALLBIN_NUMBER;i++){
      malloc_state.smallbin[i] = NULL;
      malloc_state.smallbin_head[i]= NULL;
    }
    for(int i=0;i<LARGEBIN_NUMBER;i++){
      malloc_state.largebin[i] = NULL;
    }
    malloc_state.unsortedbin = NULL;
    malloc_state.unsortedbin_head = NULL;

    malloc_state.largebin_head = NULL;
    mallinfoA.first = 1;
  }
  return 0;
}
/* set inuse bit on chunk size */
int set_inuse_bit(MemoryAdr* chunk_address)
{
    (*chunk_address)->size |= PREV_INUSE;
    return 0;
}

int make_align(size_t size)
{
  /* 16 byte align */
  if(__builtin_expect(size < 0,0)){
    malloc_error("malloc size error", FALSE);
  }
  if(size == 0){
    size = 0x20;
    return size;
  }
  int check = size % 16;
  if(check > 0){
    size = size - check + 16 + 16;
  }
  else{
    size +=16;
  }
  return size;
}

void malloc_error(const char* ErrMsg, boolean exist)
{
  if(exist){ //if errno is exist
    //printf("[Error]");
	  //perror("[Error]:\n");
  }
  else{
    //printf("[Error]: %s\n", ErrMsg);
  }
  //exit(1);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
일단 free할때 fastbin인지 확인한 다음 fastbin 이라면 fastbin에 맞게 free한다.
만약 fastbin이 아니라면 prev_inuse 비트를 확인한다. 만약 prev_inuse비트가 꺼져 있다면 unlink를 통해 청크 병합
아니라면 unsortedbin에 넣는다.
prev_size도 설정해야함
*/

void myfree(void* chunk) //userspace address, 실제 주소를 구해야함.
{
  //printf("[DEBUG] Free Brain Pack input pointer : %p\n", chunk);
  MemoryAdr freed_chunk = (MemoryAdr)chunk;
  if(__builtin_expect(freed_chunk == NULL || freed_chunk == (void*)0, 0)){
    //printf("[DEBUG] FREE Brian Pack input NULL\n");
    return;
  }
  freed_chunk = chunk_at_offset(freed_chunk, -16); //get real address of chunk
  size_t size = chunksize(freed_chunk);
  //printf("[DEBUG] freed chunk size : %ld\n", size);
  if(0x20 <= size && size <= malloc_state.max_fast){
    /*fastbin*/
    set_fastbin(freed_chunk, size);
  }
  else{
    if(check_mmap_syscall(freed_chunk)){
      //um..
    }
    else{ //set previous bit
      if(chunk_at_offset(freed_chunk, size) != malloc_state.top){
        clear_inuse_bit_at_offset(freed_chunk, size);
        chunk_at_offset(freed_chunk, size)->prev_size = size;
      }
      //chunk consolidate backward
      if(!check_prev_inuse(freed_chunk)){
        //chunk consolidate
      }
      //chunk consolidate frontward
      //else if(!check_)
      else{
        //put unsorted bin
        set_unsortedbin(freed_chunk, size);
      }
    }

  }
  return;
}

boolean check_prev_inuse(MemoryAdr freed_chuck)
{
  return 1;
}

boolean check_mmap_syscall(MemoryAdr freed_chunk)
{
  return 0;
}

int clear_inuse_bit_at_offset(MemoryAdr freed_chunk, size_t size)
{
  MemoryAdr chunk = chunk_at_offset(freed_chunk, size);
  chunk->size &= ~(PREV_INUSE);
  return 0;
}

void set_unsortedbin(MemoryAdr freed_chunk, size_t size)
{

  if(malloc_state.unsortedbin == NULL){
    malloc_state.unsortedbin_head = freed_chunk;
    //printf("[DEBUG] SET! head : %lld\n", malloc_state.unsortedbin_head->size);
    freed_chunk->fd = freed_chunk;
    freed_chunk->bk = freed_chunk;
  }
  else{
    freed_chunk->fd = malloc_state.unsortedbin;
    freed_chunk->bk = malloc_state.unsortedbin_head;
    malloc_state.unsortedbin_head->fd = freed_chunk;
    malloc_state.unsortedbin->bk = freed_chunk;
  }
  malloc_state.unsortedbin = freed_chunk;
  mallinfoA.ordblks+=1;
  mallinfoA.unsortedbin_number+=1;
}
/* 여기서는 unsortedbin 에서 보내주는 거니까 ordblks를 증가시킬 필요는 없다.
  헤드가 필요 하겠지?
*/
void set_smallbin(MemoryAdr freed_chunk, size_t size)
{
  int index = (size/16) - 8;
  if(malloc_state.smallbin[index] == NULL){
    malloc_state.smallbin_head[index] = freed_chunk;
    freed_chunk->fd = freed_chunk;
    freed_chunk->bk = freed_chunk;
  }
  else{
    freed_chunk->fd = malloc_state.smallbin[index];
    freed_chunk->bk = malloc_state.smallbin_head[index];
    malloc_state.smallbin_head[index]->fd = freed_chunk;
    malloc_state.smallbin[index]->bk = freed_chunk;
  }
  malloc_state.smallbin[index] = freed_chunk;
}

int clear_inuse_bit(MemoryAdr chunk_address)
{
  chunk_address->size &=(~PREV_INUSE);
  return 0;
}

void set_fastbin(MemoryAdr freed_chunk, size_t size)
{
  int index = (size/16)-2;
  //printf("[DEBUG] freed_chunk->size : %lld\n",freed_chunk->size);
  clear_inuse_bit(freed_chunk);
  //printf("[DEBUG] freed_chunk->size : %lld\n",freed_chunk->size);
  if(malloc_state.fastbin[index] == NULL){
    freed_chunk->fd = NULL;
    malloc_state.fastbin[index] = freed_chunk;
  }
  else{
    freed_chunk->fd = malloc_state.fastbin[index];
    malloc_state.fastbin[index] = freed_chunk;
  }
  mallinfoA.ordblks+=1;
  mallinfoA.fastbin_number+=1;
  return;
}
