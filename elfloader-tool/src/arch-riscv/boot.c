/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, HENSOLDT Cyber
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <autoconf.h>
#include <elfloader/gen_config.h>

#include <types.h>
#include <strops.h>
#include <binaries/elf/elf.h>
#include <elfloader.h>
#include <abort.h>
#include <cpio/cpio.h>
#include <sbi.h>

#define PT_LEVEL_1 1
#define PT_LEVEL_2 2

#define PT_LEVEL_1_BITS 30
#define PT_LEVEL_2_BITS 21

#define PTE_TYPE_TABLE 0x00
#define PTE_TYPE_SRWX 0xCE

#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE BIT(RISCV_PGSHIFT)

// page table entry (PTE) field
#define PTE_V     0x001 // Valid

#define PTE_PPN0_SHIFT 10

#if __riscv_xlen == 32
#define PT_INDEX_BITS  10
#else
#define PT_INDEX_BITS  9
#endif

#define PTES_PER_PT BIT(PT_INDEX_BITS)

#define PTE_CREATE_PPN(PT_BASE)  (unsigned long)(((PT_BASE) >> RISCV_PGSHIFT) << PTE_PPN0_SHIFT)
#define PTE_CREATE_NEXT(PT_BASE) (unsigned long)(PTE_CREATE_PPN(PT_BASE) | PTE_TYPE_TABLE | PTE_V)
#define PTE_CREATE_LEAF(PT_BASE) (unsigned long)(PTE_CREATE_PPN(PT_BASE) | PTE_TYPE_SRWX | PTE_V)

#define GET_PT_INDEX(addr, n) (((addr) >> (((PT_INDEX_BITS) * ((CONFIG_PT_LEVELS) - (n))) + RISCV_PGSHIFT)) % PTES_PER_PT)

#define VIRT_PHYS_ALIGNED(virt, phys, level_bits) (IS_ALIGNED((virt), (level_bits)) && IS_ALIGNED((phys), (level_bits)))

/* Actually, this has to be global for SMP only, becuase we have to share some
 * pieces of information with the secondary harts.
 */
static elfloader_ctx_t elfloader_ctx;

unsigned long l1pt[PTES_PER_PT] __attribute__((aligned(4096)));
#if __riscv_xlen == 64
unsigned long l2pt[PTES_PER_PT] __attribute__((aligned(4096)));
unsigned long l2pt_elf[PTES_PER_PT] __attribute__((aligned(4096)));
#endif

char elfloader_stack_alloc[BIT(CONFIG_KERNEL_STACK_BITS)];

/*
 * overwrite the default implementation for abort()
 */
void NORETURN abort(void)
{
    printf("HALT due to call to abort()\n");

    /* We could call the SBI shutdown now. However, it's likely there is an
     * issue that needs to be debugged. Instead of doing a busy loop, spinning
     * over a wfi is the better choice here, as it allows the core to enter an
     * idle state until something happens.
     */
    for (;;) {
        asm volatile("wfi" ::: "memory");
    }

    UNREACHABLE();
}

static int map_kernel_window(struct image_info *kernel_info)
{
    uint32_t index;
    unsigned long *lpt;

    /* Map the elfloader into the new address space */

    if (!IS_ALIGNED((uintptr_t)_text, PT_LEVEL_2_BITS)) {
        printf("ERROR: ELF Loader not properly aligned\n");
        return -1;
    }

    index = GET_PT_INDEX((uintptr_t)_text, PT_LEVEL_1);

#if __riscv_xlen == 32
    lpt = l1pt;
#else
    lpt = l2pt_elf;
    l1pt[index] = PTE_CREATE_NEXT((uintptr_t)l2pt_elf);
    index = GET_PT_INDEX((uintptr_t)_text, PT_LEVEL_2);
#endif

    for (unsigned int page = 0; index < PTES_PER_PT; index++, page++) {
        lpt[index] = PTE_CREATE_LEAF((uintptr_t)_text +
                                     (page << PT_LEVEL_2_BITS));
    }

    /* Map the kernel into the new address space */

    if (!VIRT_PHYS_ALIGNED(kernel_info->virt_region_start,
                           kernel_info->phys_region_start, PT_LEVEL_2_BITS)) {
        printf("ERROR: Kernel not properly aligned\n");
        return -1;
    }

    index = GET_PT_INDEX(kernel_info->virt_region_start, PT_LEVEL_1);

#if __riscv_xlen == 64
    lpt = l2pt;
    l1pt[index] = PTE_CREATE_NEXT((uintptr_t)l2pt);
    index = GET_PT_INDEX(kernel_info->virt_region_start, PT_LEVEL_2);
#endif

    for (unsigned int page = 0; index < PTES_PER_PT; index++, page++) {
        lpt[index] = PTE_CREATE_LEAF(kernel_info->phys_region_start +
                                     (page << PT_LEVEL_2_BITS));
    }

    return 0;
}

#if CONFIG_PT_LEVELS == 2
uint64_t vm_mode = 0x1llu << 31;
#elif CONFIG_PT_LEVELS == 3
uint64_t vm_mode = 0x8llu << 60;
#elif CONFIG_PT_LEVELS == 4
uint64_t vm_mode = 0x9llu << 60;
#else
#error "Wrong PT level"
#endif

int hsm_exists = 0;

#if CONFIG_MAX_NUM_NODES > 1

extern void secondary_harts(unsigned long);

int secondary_go = 0;
int next_logical_core_id = 1;
int mutex = 0;
int core_ready[CONFIG_MAX_NUM_NODES] = { 0 };
static void set_and_wait_for_ready(int hart_id, int core_id)
{
    /* Acquire lock to update core ready array */
    while (__atomic_exchange_n(&mutex, 1, __ATOMIC_ACQUIRE) != 0);
    printf("Hart ID %d core ID %d\n", hart_id, core_id);
    core_ready[core_id] = 1;
    __atomic_store_n(&mutex, 0, __ATOMIC_RELEASE);

    /* Wait untill all cores are go */
    for (int i = 0; i < CONFIG_MAX_NUM_NODES; i++) {
        while (__atomic_load_n(&core_ready[i], __ATOMIC_RELAXED) == 0) ;
    }
}
#endif

static inline void sfence_vma(void)
{
    asm volatile("sfence.vma" ::: "memory");
}

static inline void ifence(void)
{
    asm volatile("fence.i" ::: "memory");
}

static inline void enable_virtual_memory(void)
{
    sfence_vma();
    asm volatile(
        "csrw satp, %0\n"
        :
        : "r"(vm_mode | (uintptr_t)l1pt >> RISCV_PGSHIFT)
        :
    );
    ifence();
}

static int run_elfloader(elfloader_ctx_t *ctx, UNUSED int hart_id)
{
    int ret;

    /* Unpack ELF images into memory. */
    ret = load_images(ctx);
    if (0 != ret) {
        printf("ERROR: image loading failed, code %d\n", ret);
        return -1;
    }

    if (ctx->loaded_user_images != 1) {
        printf("ERROR: expected to load just 1 app, actually loaded %u apps\n",
               ctx->loaded_user_images);
        return -1;
    }

    ret = map_kernel_window(&ctx->kernel);
    if (0 != ret) {
        printf("ERROR: could not map kernel window, code %d\n", ret);
        return -1;
    }

#if CONFIG_MAX_NUM_NODES > 1
    while (__atomic_exchange_n(&mutex, 1, __ATOMIC_ACQUIRE) != 0);
    printf("Main entry hart_id:%d\n", hart_id);
    __atomic_store_n(&mutex, 0, __ATOMIC_RELEASE);

    /* Unleash secondary cores */
    __atomic_store_n(&secondary_go, 1, __ATOMIC_RELEASE);

    /* Start all cores */
    int i = 0;
    while (i < CONFIG_MAX_NUM_NODES && hsm_exists) {
        i++;
        if (i != hart_id) {
            sbi_hart_start(i, secondary_harts, i);
        }
    }

    set_and_wait_for_ready(hart_id, 0);
#endif

    printf("Enabling MMU and paging\n");
    enable_virtual_memory();

    printf("Jumping to kernel-image entry point...\n\n");
    struct image_info *user_img = &ctx->user[0];
    ((init_riscv_kernel_t)ctx->kernel.virt_entry)(
        user_img->phys_region_start,
        user_img->phys_region_end,
        user_img->phys_virt_offset,
        user_img->virt_entry,
        (word_t)ctx->dtb.phys_base,
        ctx->dtb.size
#if CONFIG_MAX_NUM_NODES > 1
        ,
        hart_id,
        0
#endif
    );

    /* We should never get here. */
    printf("ERROR: Kernel returned back to the ELF Loader\n");
    return -1;
}

#if CONFIG_MAX_NUM_NODES > 1

void secondary_entry(int hart_id, int core_id)
{
    while (__atomic_load_n(&secondary_go, __ATOMIC_ACQUIRE) == 0) ;

    while (__atomic_exchange_n(&mutex, 1, __ATOMIC_ACQUIRE) != 0);
    printf("Secondary entry hart_id:%d core_id:%d\n", hart_id, core_id);
    __atomic_store_n(&mutex, 0, __ATOMIC_RELEASE);

    set_and_wait_for_ready(hart_id, core_id);

    enable_virtual_memory();

    elfloader_ctx_t *ctx = &elfloader_ctx;
    struct image_info *user_img = &ctx->user[0];
    /* If adding or modifying these parameters you will need to update
     * the registers in head.S
     */
    ((init_riscv_kernel_t)ctx->kernel.virt_entry)(
        user_img->phys_region_start,
        user_img->phys_region_end,
        user_img->phys_virt_offset,
        user_img->virt_entry,
        (word_t)ctx->dtb.phys_base,
        ctx->dtb.size,
        hart_id,
        core_id);
}

#endif

void main(int hart_id, void *bootloader_dtb)
{
    /* Printing uses SBI, so there is no need to initialize any UART. */
    printf("ELF-loader started on (HART %d) (NODES %d)\n",
           hart_id, CONFIG_MAX_NUM_NODES);

    printf("  paddr=[%p..%p]\n", _text, _end - 1);

    /* Clear context. */
    memset(elfloader_ctx, sizeof(elfloader_ctx), 0);
    elfloader_ctx_t *ctx = &elfloader_ctx;

    /* Assume a DTB is passed if the pointer is not NULL. */
    if (bootloader_dtb) {
        ctx->dtb.phys_base = (paddr_t)bootloader_dtb;
        ctx->dtb.size = (size_t)(-1); /* size unknown */
    }

    /* Run the actual ELF loader, this is not expected to return unless there
     * was an error.
     */
    int ret = run_elfloader(ctx, hart_id);
    if (0 != ret) {
        printf("ERROR: ELF-loader failed, code %d\n", ret);
        /* There is nothing we can do to recover. */
        abort();
        UNREACHABLE();
    }

    /* We should never get here. */
    printf("ERROR: ELF-loader didn't hand over control\n");
    abort();
    UNREACHABLE();
}
