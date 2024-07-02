/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <autoconf.h>
#include <elfloader/gen_config.h>
#include "sbi.h"

#if !defined(RISCV_SBI_NONE)
int plat_console_putchar(unsigned int c)
{
    sbi_console_putchar(c);
    return 0;
}
#endif
