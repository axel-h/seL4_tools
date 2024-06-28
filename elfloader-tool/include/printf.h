/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#define PRINTF_FUNC(pos_str, post_args) __attribute__((format(printf, pos_str, post_args)))
#define NULL ((void *)0)
#define FILE void

int printf(const char *format, ...) PRINTF_FUNC(1,2);
int sprintf(char *buff, const char *format, ...) PRINTF_FUNC(2,3);
