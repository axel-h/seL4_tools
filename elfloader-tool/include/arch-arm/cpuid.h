/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>
#include <armv/machine.h>

#define MPIDR_MASK      0xff00ffffff
#define CURRENTEL_EL2   (2 << 2)

/* Pretty print CPUID information */
void print_cpuid(void);

/* Returns the Cortex-Ax part number, or -1 */
int get_cortex_a_part(void);


/* read ID register from CPUID */
static inline uint32_t read_cpuid_id(void)
{
    uint32_t val;
    asm volatile("mrs %x0, midr_el1" : "=r"(val) :: "cc");
    return val;
}

/* read MP ID register from CPUID , we only care about the affinity bits */
static inline word_t read_cpuid_mpidr(void)
{
    uint64_t val;
    asm volatile("mrs %x0, mpidr_el1" : "=r"(val) :: "cc");
    return val & MPIDR_MASK;
}

/* check if CPU is in HYP/EL2 mode */
word_t is_hyp_mode(void)
{
    uint32_t val;
    asm volatile("mrs %x0, CurrentEL" : "=r"(val) :: "cc");
    return (val == CURRENTEL_EL2);
}
