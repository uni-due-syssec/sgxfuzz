/*
 * This file is part of Redqueen.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KAFL_USER_H
#define KAFL_USER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef __MINGW64__
#include <sys/mman.h>
#endif

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else 
#include <stdint.h>
#endif

#define HYPERCALL_KAFL_RAX_ID				0x01f
#define HYPERCALL_KAFL_ACQUIRE				0
#define HYPERCALL_KAFL_GET_PAYLOAD			1
#define HYPERCALL_KAFL_GET_PROGRAM			2
#define HYPERCALL_KAFL_GET_ARGV				3
#define HYPERCALL_KAFL_RELEASE				4
#define HYPERCALL_KAFL_SUBMIT_CR3			5
#define HYPERCALL_KAFL_SUBMIT_PANIC			6
#define HYPERCALL_KAFL_SUBMIT_KASAN			7
#define HYPERCALL_KAFL_PANIC				8
#define HYPERCALL_KAFL_KASAN				9
#define HYPERCALL_KAFL_LOCK					10
#define HYPERCALL_KAFL_INFO					11
#define HYPERCALL_KAFL_NEXT_PAYLOAD			12
#define HYPERCALL_KAFL_PRINTF				13
#define HYPERCALL_KAFL_PRINTK_ADDR			14
#define HYPERCALL_KAFL_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE	16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE		17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT			20
#define HYPERCALL_KAFL_RANGE_SUBMIT		29
#define HYPERCALL_KAFL_REQ_STREAM_DATA		30
#define HYPERCALL_KAFL_PANIC_EXTENDED		32

#define HYPERCALL_KAFL_CREATE_TMP_SNAPSHOT 33
#define HYPERCALL_KAFL_DEBUG_TMP_SNAPSHOT 34 /* hypercall for debugging / development purposes */

#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36


/* hypertrash only hypercalls */
#define HYPERTRASH_HYPERCALL_MASK			0xAA000000

#define HYPERCALL_KAFL_NESTED_PREPARE		(0 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_CONFIG		(1 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_ACQUIRE		(2 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_RELEASE		(3 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_HPRINTF		(4 | HYPERTRASH_HYPERCALL_MASK)


#define PAYLOAD_SIZE						(128 << 10)				/* up to 128KB payloads */
#define PROGRAM_SIZE						(128 << 20)				/* kAFL supports 128MB programm data */
#define INFO_SIZE        					(128 << 10)				/* 128KB info string */
#define TARGET_FILE							"/tmp/fuzzing_engine"	/* default target for the userspace component */
#define TARGET_FILE_WIN						"fuzzing_engine.exe"	

#define HPRINTF_MAX_SIZE					0x1000					/* up to 4KB hprintf strings */


typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-sizeof(int32_t)];
} kAFL_payload;

typedef struct{
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges; 

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

/* Todo: Add support for hypercall return values */
#if defined(__i386__)
static inline uint32_t kAFL_hypercall(uint32_t ebx, uint32_t ecx){
	//printf("%s %x %x \n", __func__, rbx, rcx);
# ifndef __NOKAFL
	uint32_t eax = HYPERCALL_KAFL_RAX_ID;
    asm volatile(
			     "movl %1, %%ecx;"
				 "movl %2, %%ebx;"  
				 "movl %3, %%eax;"
				 "vmcall;" 
				 "movl %%eax, %0;"
				: "=a" (eax)
				: "r" (ecx), "r" (ebx), "r" (eax) 
				: "ecx", "ebx"
				);
# endif
	return eax;
} 
#elif defined(__x86_64__)

static inline uint64_t kAFL_hypercall(uint64_t rbx, uint64_t rcx){
# ifndef __NOKAFL
	uint64_t rax = HYPERCALL_KAFL_RAX_ID;
    asm volatile(
				 "movq %1, %%rcx;"
				 "movq %2, %%rbx;"  
				 "movq %3, %%rax;"
				 "vmcall;" 
				 "movq %%rax, %0;"
				: "=a" (rax)
				: "r" (rcx), "r" (rbx), "r" (rax)
				: "rcx", "rbx"
				);

# endif
	return rax;
}
#endif

uint8_t* hprintf_buffer = NULL; 

static inline uint8_t alloc_hprintf_buffer(void){
	if(!hprintf_buffer){
#ifdef __MINGW64__
		hprintf_buffer = (uint8_t*)VirtualAlloc(0, HPRINTF_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else 
		hprintf_buffer = mmap((void*)NULL, HPRINTF_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
		if(!hprintf_buffer){
			return 0;
		}
	}
	return 1; 
}

#ifdef __NOKAFL
int (*hprintf)(const char * format, ...) = printf;
#else
static void hprintf(const char * format, ...)  __attribute__ ((unused));

static void hprintf(const char * format, ...){
	va_list args;
	va_start(args, format);
	if(alloc_hprintf_buffer()){
		vsnprintf((char*)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
# if defined(__i386__)
		//printf("%s", hprintf_buffer);
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uint32_t)hprintf_buffer);
# elif defined(__x86_64__)
		printf("%s", hprintf_buffer);
		kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uint64_t)hprintf_buffer);
# endif
	}
	//vprintf(format, args);
	va_end(args);
}
#endif



typedef struct host_config_s{
  uint32_t bitmap_size;
  uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
  /* more to come */
} __attribute__((packed)) host_config_t;

typedef struct agent_config_s{
  uint8_t agent_timeout_detection;
  uint8_t agent_tracing;
  uint8_t agent_ijon_tracing;
	uint8_t padding_b;
	uint64_t trace_buffer_vaddr;
	uint64_t ijon_trace_buffer_vaddr;
  /* more to come */
} __attribute__((packed)) agent_config_t;

#define cpuid(in,a,b,c,d)\
  asm("cpuid": "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));
  
static int is_nyx_vcpu(void){
  unsigned long eax,ebx,ecx,edx;
  char str[8];
  cpuid(0x80000004,eax,ebx,ecx,edx);	

  for(int j=0;j<4;j++){
    str[j] = eax >> (8*j);
    str[j+4] = ebx >> (8*j);
  }

  return !memcmp(&str, "NYX vCPU", 8);
}

#endif
