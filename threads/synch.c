/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value)
{
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters); // 대기목록 초기화
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void sema_down(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0)
	{ // 세마포어의 value가 0인동안 반복 -> 세마포어의 value가 0이면 임계구역에 들어가기 위해 대기
		// list_push_back (&sema->waiters, &thread_current ()->elem); // 현재 세마포어를 대기목록에 추가 -> 해당 스레드가 세마포어를 기다리고 있다는 것을 나타냄
		list_insert_ordered(&sema->waiters, &thread_current()->elem, thread_compare_priority, 0);
		thread_block(); // 시그널을 받을때까지 대기!
	}
	sema->value--; // 세마포어의 값을 감소시켜서 세마포어가 현재 사용중임을 나타냄
	intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema)
{
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (!list_empty(&sema->waiters)) // 대기목록이 비어있지 않은지 확인 -> 대기목록이 비어있지 않다면 세마포어를 기다리는 스레드가 존재한다는 것을 의미
	{
		// 중간에 우선순위 변경이 생겼을 수도 있으니 한번 정렬
		list_sort(&sema->waiters, thread_compare_priority, 0);
		thread_unblock(list_entry(list_pop_front(&sema->waiters),
								  struct thread, elem)); // 세마포어의 대기목록에서 첫번째 스레드를 꺼내서 스케줄링 대기열로 이동. 선입선출로 관리함~
	}
	sema->value++; // 세마포어 값을 증가시켜서 현재 세마포어가 사용되지 않는다는 것을 타나냄
	thread_test_preemption();
	intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock)
{
	ASSERT(lock != NULL);

	lock->holder = NULL;			// 락의 소유자를 null로 초기화
	sema_init(&lock->semaphore, 1); // 락 내부의 세마포어를 초기화. 초기값은 1
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *cur = thread_current();
	if (lock->holder)
	{
		cur->wait_on_lock = lock;
		list_insert_ordered(&lock->holder->donations, &cur->donation_elem,
							thread_compare_donate_priority, 0);
		donate_priority();
	}

	sema_down(&lock->semaphore);

	cur->wait_on_lock = NULL;
	lock->holder = cur;
}

// void lock_acquire(struct lock *lock)
// {
// 	ASSERT(lock != NULL);
// 	ASSERT(!intr_context());
// 	ASSERT(!lock_held_by_current_thread(lock));

// 	sema_down(&lock->semaphore);	 // 해당 락의 세마포어를 기다림. 만약 락이 이미 다른 스레드에 의해 소유되었다면, 현재 스레드는 락이 해제될때까지 대기
// 	lock->holder = thread_current(); // 현재 스레드를 락의 소유자로 설정.
// }

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock)
{
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock));

	success = sema_try_down(&lock->semaphore);
	if (success)
		lock->holder = thread_current();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
// void lock_release(struct lock *lock)
// {
// 	ASSERT(lock != NULL);					   // 락이 null이 아닌지 확인
// 	ASSERT(lock_held_by_current_thread(lock)); // 현재 스레드가 락을 소유하고 있는지 확인

// 	lock->holder = NULL;	   // 락의 소유자를 null로 바꿔서 해제.
// 	sema_up(&lock->semaphore); // 락의 내부 세마포어에 시그널을 보냄 -> 다른 스레드가 락을 획득할 수 있도록 함
// }
void lock_release(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock));

	remove_with_lock(lock);
	refresh_priority();

	lock->holder = NULL;
	sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem
{
	struct list_elem elem;		/* List element. */
	struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
	ASSERT(cond != NULL);

	list_init(&cond->waiters); // 대기목록 초기화
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock)
{
	struct semaphore_elem waiter;

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock)); // 현재 스레드가 해당 락을 소유하고 있는지 확인

	sema_init(&waiter.semaphore, 0); // 대기자의 세마포어 초기화. 세마포어를 0으로 초기화해서 대기 상태로 설정
	// list_push_back (&cond->waiters, &waiter.elem); // 현재 스레드를 대기자 목록에 추가
	list_insert_ordered(&cond->waiters, &waiter.elem, sema_compare_priority, 0);
	lock_release(lock);			  // 현재 락을 해제 -> 조건변수를 기다리는 동안에는 해당 락을 해제하여 다른 스레드가 해당 락을 사용할 수 있도록 함.
	sema_down(&waiter.semaphore); // 대기자의 세마포어를 기다림 -> 대기자의 세마포어는 해당 조건 변수에 대한 신호를 기다리는데 사용. 신호를 받을때 까지 대기 상태임
	lock_acquire(lock);			  // 락을 다시 획득
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	if (!list_empty(&cond->waiters)) // 대기중인 스레드가 있는지 확인
	{
		list_sort(&cond->waiters, sema_compare_priority, 0);
		sema_up(&list_entry(list_pop_front(&cond->waiters),
							struct semaphore_elem, elem)
					 ->semaphore);
	}
	// 대기 목록의 첫번째 스레드에 시그널 보냄. 첫번째 대기자를 꺼내서 세마포어 엘리먼트를 대기자 구조체로 변환 후 세마포어에 접근해서 해당 스레드의 대기를 해제
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}

bool sema_compare_priority(const struct list_elem *l, const struct list_elem *s, void *aux UNUSED)
{
	struct semaphore_elem *l_sema = list_entry(l, struct semaphore_elem, elem);
	struct semaphore_elem *s_sema = list_entry(s, struct semaphore_elem, elem);

	struct list *waiter_l_sema = &(l_sema->semaphore.waiters);
	struct list *waiter_s_sema = &(s_sema->semaphore.waiters);

	return list_entry(list_begin(waiter_l_sema), struct thread, elem)->priority > list_entry(list_begin(waiter_s_sema), struct thread, elem)->priority;
}
void refresh_priority(void)
{
	struct thread *cur = thread_current();

	cur->priority = cur->init_priority;

	if (!list_empty(&cur->donations))
	{
		list_sort(&cur->donations, thread_compare_donate_priority, 0);

		struct thread *front = list_entry(list_front(&cur->donations), struct thread, donation_elem);
		if (front->priority > cur->priority)
			cur->priority = front->priority;
	}
}
void remove_with_lock(struct lock *lock)
{
	struct list_elem *e;
	struct thread *cur = thread_current();

	for (e = list_begin(&cur->donations); e != list_end(&cur->donations); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, donation_elem);
		if (t->wait_on_lock == lock)
			list_remove(&t->donation_elem);
	}
}