
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
