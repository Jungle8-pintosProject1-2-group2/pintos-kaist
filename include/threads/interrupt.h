#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level
{
	INTR_OFF, /* Interrupts disabled. */
	INTR_ON	  /* Interrupts enabled. */
};

enum intr_level intr_get_level(void);
enum intr_level intr_set_level(enum intr_level);
enum intr_level intr_enable(void);
enum intr_level intr_disable(void);

// rsp 제외 모든 범용 레지스터의 데이터 저장 구조체
// 120 byte
/* Interrupt stack frame. */
struct gp_registers
{
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rbp;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rbx;
	uint64_t rax;
} __attribute__((packed));

// 192byte = 120 + 8*9(72) byte
struct intr_frame
{

	// 아래에서 나오는 ?s로 이름지어진 필드는 보통 세그먼트 레지스터

	/* Pushed by intr_entry in intr-stubs.S.
	   These are the interrupted task's saved registers. */
	// context 저장을 위한 120 byte짜리 구조체
	struct gp_registers R;

	// es가 16bit이기 때문에 64비트에서 패딩을 48비트 준다.
	// 세크먼트 레지스터 + 패딩
	uint16_t es;
	uint16_t __pad1;
	uint32_t __pad2;

	// 세크먼트 레지스터 + 패딩
	uint16_t ds;
	uint16_t __pad3;
	uint32_t __pad4;

	// 인터럽트 벡터 넘버
	/* Pushed by intrNN_stub in intr-stubs.S. */
	uint64_t vec_no; /* Interrupt vector number. */
					 /* Sometimes pushed by the CPU,
						otherwise for consistency pushed as 0 by intrNN_stub.
						The CPU puts it just under `eip', but we move it here. */
	// 에러 코드
	uint64_t error_code;
	/* Pushed by the CPU.
	   These are the interrupted task's saved registers. */

	// pc
	uintptr_t rip;

	// 세크먼트 레지스터 + 패딩
	uint16_t cs;
	uint16_t __pad5;
	uint32_t __pad6;

	// 플레그 레지스터
	uint64_t eflags;

	// 스택 포인터
	uintptr_t rsp;

	// 세크먼트 레지스터 + 패딩
	uint16_t ss;
	uint16_t __pad7;
	uint32_t __pad8;
} __attribute__((packed));

typedef void intr_handler_func(struct intr_frame *);

void intr_init(void);
void intr_register_ext(uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int(uint8_t vec, int dpl, enum intr_level,
					   intr_handler_func *, const char *name);
bool intr_context(void);
void intr_yield_on_return(void);

void intr_dump_frame(const struct intr_frame *);
const char *intr_name(uint8_t vec);

#endif /* threads/interrupt.h */
