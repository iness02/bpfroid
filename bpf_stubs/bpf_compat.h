#ifndef __ARG_PLACEHOLDER_1
#define __ARG_PLACEHOLDER_1 0,
#endif

#ifndef __take_second_arg
#define __take_second_arg(__ignored, val, ...) val
#endif

#ifndef __is_defined
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#endif

#ifndef __KVM_VHE_HYPERVISOR__
#define __KVM_VHE_HYPERVISOR__ 0
#endif
#ifndef __BPF_COMPAT_H
#define __BPF_COMPAT_H

#ifndef __BPF_COMPAT_ATOMIC64_T
#define __BPF_COMPAT_ATOMIC64_T
#endif

#ifndef CONFIG_ARM64_VA_BITS
#define CONFIG_ARM64_VA_BITS 48
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct bpf_compat_preempt_count {
    int count;
};

struct bpf_compat_thread_info {
    struct bpf_compat_preempt_count preempt;
};

static __always_inline struct bpf_compat_thread_info *current_thread_info(void)
{
    return (struct bpf_compat_thread_info *)0;
}

/* Force LL/SC atomics, LSE uses physical register asm("x0") illegal in BPF */
#define ARM64_LSE_ATOMIC_INSN(llsc, lse)  llsc

/* Route __lse_ll_sc_body to the LL/SC implementations */
#define __lse_ll_sc_body(op, ...)   __ll_sc_##op(__VA_ARGS__)

/* Provide current_stack_pointer before percpu.h needs it */
static unsigned long current_stack_pointer __attribute__((unused));
#define __ASM_STACK_POINTER_H

#include <linux/types.h>
#include <linux/binfmts.h>

/* Force LL/SC atomics — LSE uses physical register asm("x0") illegal in BPF */
#define ARM64_LSE_ATOMIC_INSN(llsc, lse)  llsc

/* Route __lse_ll_sc_body to the LL/SC implementations */
#define __lse_ll_sc_body(op, ...)   __ll_sc_##op(__VA_ARGS__)

/* Provide current_stack_pointer before percpu.h needs it */
static unsigned long current_stack_pointer __attribute__((unused));
#define __ASM_STACK_POINTER_H

/* Must include types.h before any atomic64_t users */
#include <linux/types.h>

/* Pull in linux_binprm full definition needed by tracee.bpf.c */
#include <linux/binfmts.h>

#endif
