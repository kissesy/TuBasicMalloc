# tu malloc basic 
dlmalloc의 소스코드를 참고하여 만들어본 tu malloc함수입니다. 

```C
if(!check_first_allocate()){
    /* if first call malloc */
    init_Malloc(TRUE);
    /* Top chunk 분할 */
    division_TopChunk(&chunk_address, size); 
}
```
malloc함수를 처음 호출하는지 확인하고 sbrk 시스템콜을 호출하여 Top Chunk를 분할합니다.


```C
if(size >= 0x20 && size <= FAST_MAX_SIZE){
    if(!find_fastbin_chunk(&chunk_address, size)){ //return 0, don't exist chunk
        if(!check_top_chunk_size(size)){
        init_Malloc(FALSE);
        }
        division_TopChunk(&chunk_address, size);
    }
}
```
메모리 할당 요청시 사이즈를 확인하며 FASTBIN에 들어갈 사이즈라면 fastbin을 검색합니다. 

```C
else if(FAST_MAX_SIZE<size && size <= SMALLBIN_MAX){
    if(!find_unsortedbin_chunk(&chunk_address, size)){ //return 0 don't exist chunk
        if(!find_smallbin_chunk(&chunk_address, size)){
            if(!check_top_chunk_size(size)){
            init_Malloc(FALSE);
            }
            division_TopChunk(&chunk_address, size);
        }
    }
}
```
smallbin 사이즈라면 unsortedbin에서 먼저 청크를 찾습니다. 없다면 smallbin에서 찾습니다. 또한, 없다면 Topchunk에서 메모리를 분할합니다.

```C
set_inuse_bit(&chunk_address);
return (void*)userspace;
```
청크를 찾게된다면 in use비트인 P값을 써주고 반환합니다. 주의할점은 FASTBIN에 들어가는 Chunk는 해당 비트를 설정하지 않습니다.   


# Example
```C
#include <stdio.h>

int main(void)
{
	int* arr = (int*)myalloc(10);
	arr[0] = 32; 
	printf("arr's address is : %p\n", arr); 	
	myfree(arr); 
	printf("arr has free!\n"); 
	arr = (int*)myalloc(10); 
	printf("re alloc memory and, arr's address is : %p\n", arr); 
	return 0;
}
```
# Result
```Shell
➜  TuBasicMalloc git:(master) ✗ ./a.out
arr's address is : 0x584a7010
arr has free!
re alloc memory and, arr's address is : 0x584a7010
```