// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stdlib.h>

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char* in);
uint64_t hal_get_time(void);
size_t hal_get_stack_size(void);
void hal_spraystack(void);
size_t hal_checkstack(void);

#endif