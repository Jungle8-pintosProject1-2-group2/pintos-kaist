#include "userprog/syscall.h"
#include "userprog/process.h"
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
#include "include/lib/user/syscall.h"
#include "include/threads/vaddr.h"
// 필요한가
struct lock file_rw_lock;
void syscall_entry(void);
void syscall_handler(struct intr_frame *);
bool check_addr(intptr_t *);

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
	lock_init(&file_rw_lock);
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
		check_addr(f->R.rdi);
		f->R.rax = process_fork(f->R.rdi, f);
		break;
	case SYS_EXEC: /* Switch current process. */
		if (exec(f->R.rdi) == -1)
			exit(-1);
		break;
	case SYS_WAIT: /* Wait for a child process to die. */
		f->R.rax = process_wait(f->R.rdi);
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
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ: /* Read from a file. */
		if (f->R.rdi == 0)
			input_getc();
		else if (f->R.rdi == 1)
			exit(-1);
		else
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE: /* Write to a file. */
		// printf(f->R.rsi);
		if (f->R.rdi == 0)
			exit(-1);
		else if (f->R.rdi == 1)
			putbuf(f->R.rsi, f->R.rdx);
		else
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK: /* Change position in a file. */
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL: /* Report current position in a file. */
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE: /* Close a file. */
		break;
	default:
		break;
	}

	// printf("system call!\n");
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
	// TODO :
	// 1. 그동안 연 파일 다 닫기
	// 2. page_fault에 의한 exit의 경우 생각해서 다시 코딩
	struct thread *syscall_caller = thread_current();
	syscall_caller->exit_status = status;
	printf("%s: exit(%d)\n", syscall_caller->name, status);
	thread_exit();
}
tid_t fork(const char *thread_name); // in process.c - process_fork

int exec(const char *file)
{
	check_addr(file);
	return process_exec(file);
}
// int wait(pid_t pid)
// {
// 	return process_wait(pid);
// }
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
	check_addr(file);
	struct file *a;
	int out_fd = 0;
	struct file **fdt = thread_current()->fdt;

	// fd넣을 위치 찾기
	for (int i = 3; i < 192; i++)
	{
		if (fdt[i] == NULL)
			out_fd = i;
	}

	if (out_fd == 0)
		return -1;

	// 파일을 넣을 곳이 있고
	// 파일을 정상적으로 열었다면
	if (a = filesys_open(file))
	{
		fdt[out_fd] = a;
		return out_fd;
	}
	else
		return -1;
}

int filesize(int fd)
{
	if (!thread_current()->fdt[fd])
		return -1;
	return file_length(thread_current()->fdt[fd]);
}
int read(int fd, void *buffer, unsigned length)
{
	struct thread *t = thread_current();
	check_addr(buffer);
	if (!t->fdt[fd])
		return -1;
	lock_acquire(&file_rw_lock);
	int a = file_read(t->fdt[fd], buffer, length);
	lock_release(&file_rw_lock);
	return a;
}
int write(int fd, const void *buffer, unsigned length)
{
	check_addr(buffer);
	if (!thread_current()->fdt[fd])
		return -1;
	lock_acquire(&file_rw_lock);
	int a = file_write(thread_current()->fdt[fd], buffer, length);
	lock_release(&file_rw_lock);
	return a;
}

void seek(int fd, unsigned position)
{
	if (!thread_current()->fdt[fd])
		return -1;
	return file_seek(thread_current()->fdt[fd], position);
}
unsigned tell(int fd)
{
	if (!thread_current()->fdt[fd])
		return -1;
	return file_tell(thread_current()->fdt[fd]);
}
void close(int fd)
{
	if (fd < 192)
	{
		file_close(thread_current()->fdt[fd]);
		thread_current()->fdt[fd] = NULL;
	}
}
