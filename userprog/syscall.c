#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	// syscall 종류 확인
	uint64_t syscall_no = f->R.rax;
	switch (syscall_no)
	{
	case SYS_HALT: /* Halt the operating system. */
		halt();
		break;
	case SYS_EXIT: /* Terminate this process. */
		exit(f->R.rdi);
		break;
	case SYS_FORK: /* Clone current process. */
		break;
	case SYS_EXEC: /* Switch current process. */
		break;
	case SYS_WAIT: /* Wait for a child process to die. */
		break;
	case SYS_CREATE: /* Create a file. */
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE: /* Delete a file. */
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN: /* Open a file. */
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE: /* Obtain a file's size. */
		break;
	case SYS_READ: /* Read from a file. */
		break;
	case SYS_WRITE: /* Write to a file. */
		break;
	case SYS_SEEK: /* Change position in a file. */
		break;
	case SYS_TELL: /* Report current position in a file. */
		break;
	case SYS_CLOSE: /* Close a file. */
		break;
	default:
		break;
	}

	printf("system call!\n");
	thread_exit();
}
bool check_addr(intptr_t *addr)
{
	if (is_kernel_vaddr(addr) || addr == NULL || pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

void halt(void)
{
	power_off();
}
void exit(int status)
{
	// TODO : exit 상태 수정

	// 여기에 process_exit()포함되어 있음
	// 이건 추가로 context switching까지 포함
	thread_exit();
}
pid_t fork(const char *thread_name)
{
	pml4_for_each(thread_current()->pml4, (uintptr_t)stat_page, NULL);
}
int exec(const char *file);
int wait(pid_t);
bool create(const char *file, unsigned initial_size)
{
	check_addr(file);
	return filesys_create(file, initial_size);
}
bool remove(const char *file)
{
	check_addr(file);
	return filesys_remove(file);
}
int open(const char *file)
{
	struct file *a;
	check_addr(file);
	if (a = filesys_open(file))
	{
		// fileptr의 fd를 반환
	}
	return -1;
}
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static bool
stat_page(uint64_t *pte, void *va, void *aux)
{
	if (is_user_vaddr(va))
		printf("user page: %llx\n", va);
	if (is_writable(va))
		printf("writable page: %llx\n", va);
	return true;
}