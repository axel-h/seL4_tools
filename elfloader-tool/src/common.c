/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2021, HENSOLDT Cyber
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <autoconf.h>
#include <elfloader/gen_config.h>

#include <printf.h>
#include <types.h>
#include <strops.h>
#include <binaries/elf/elf.h>
#include <cpio/cpio.h>

#include <elfloader.h>
#include <fdt.h>

#ifdef CONFIG_HASH_SHA
#include "crypt_sha256.h"
#elif CONFIG_HASH_MD5
#include "crypt_md5.h"
#endif

#include "hash.h"

#ifdef CONFIG_ELFLOADER_ROOTSERVERS_LAST
#include <platform_info.h> // this provides memory_region
#endif

/* generic blob */
typedef struct {
    void const *base;
    size_t size;
    char const *name; /* can be NULL */
} blob_t;

typedef struct {
    paddr_t start;
    paddr_t end;
} memory_bounds_phys_t;

typedef struct {
    vaddr_t start;
    vaddr_t end;
} memory_bounds_virt_t;


extern char _bss[];
extern char _bss_end[];

/*
 * Clear the BSS segment
 */
void clear_bss(void)
{
    char *start = _bss;
    char *end = _bss_end;
    while (start < end) {
        *start = 0;
        start++;
    }
}

#define KEEP_HEADERS_SIZE BIT(PAGE_BITS)

/*
 * Determine if two intervals overlap.
 */
static int regions_overlap(
    uintptr_t startA,
    uintptr_t endA,
    uintptr_t startB,
    uintptr_t endB)
{
    if (endA < startB) {
        return 0;
    }
    if (endB < startA) {
        return 0;
    }
    return 1;
}

/*
 * Ensure that we are able to use the given physical memory range.
 *
 * We fail if the destination physical range overlaps us, or if it goes outside
 * the bounds of memory.
 */
static int ensure_phys_range_valid(
    paddr_t paddr_min,
    paddr_t paddr_max)
{
    /*
     * Ensure that the physical load address of the object we're loading (called
     * `name`) doesn't overwrite us.
     */
    if (regions_overlap(paddr_min,
                        paddr_max - 1,
                        (uintptr_t)_text,
                        (uintptr_t)_end - 1)) {
        printf("ERROR: image load address overlaps with ELF-loader!\n");
        return -1;
    }

    return 0;
}

static int cpioBlob_getFile(
    blob_t const *const cpio,
    char const *const name,
    blob_t *blob)
{
    unsigned long size = 0;
    void const *base = cpio_get_file(cpio->base, cpio->size, name, &size);
    if (!base) {
        return -1; /* file not found */
    }
    if (blob) {
        /* size types differ, ensure casting is always fine */
        _Static_assert(sizeof(size) <= sizeof(size_t),
                       "integer model mismatch");
        *blob = (blob_t) {
            .name = name,
            .base = base,
            .size = (size_t)size,
        };
    }
    return 0;
}

static int cpioBlob_getEntry(
    blob_t const *const cpio,
    unsigned int idx,
    blob_t *blob)
{
    unsigned long size = 0;
    char const *name = NULL;
    void const *base = cpio_get_entry(cpio->base, cpio->size, idx, &name, &size);
    if (!base) {
        return -1; /* entry not found */
    }
    if (blob) {
        /* size types differ, ensure casting is always fine */
        _Static_assert(sizeof(size) <= sizeof(size_t),
                       "integer model mismatch");
        *blob = (blob_t) {
            .name = name,
            .base = base,
            .size = (size_t)size,
        };
    }
    return 0;
}

static int elfBlob_getBounds_phys(
    blob_t const *const elf_blob,
    memory_bounds_phys_t *bounds_phys)
{
    uint64_t start_paddr, end_paddr;
    /* This returns 1 on success and anything else is an error. */
    int ret = elf_getMemoryBounds(elf_blob->base, 1, &start_paddr, &end_paddr);
    if (ret != 1) {
        printf("ERROR: Could not get physical bounds (%d)\n", ret);
        return -1;
    }

    /* Check that image physical address range is sane */
    if (end_paddr < start_paddr) {
        printf("ERROR: physical start address %"PRIx64" is after end %"PRIx64"\n",
               start_paddr, end_paddr);
        return -1;
    }
    if ((start_paddr > UINTPTR_MAX) || (end_paddr > UINTPTR_MAX)) {
        printf("ERROR: image physical address [%"PRIx64"..%"PRIx64"] exceeds "
               "UINTPTR_MAX (0x%x)\n",
               start_paddr, end_paddr, UINTPTR_MAX);
        return -1;
    }

    if (bounds_phys) {
        *bounds_phys = (memory_bounds_phys_t) {
            .start = (paddr_t)start_paddr,
            .end = (paddr_t)end_paddr,
        };
    }
    return 0;
}

static int elfBlob_getBounds_virt(
    blob_t const *const elf_blob,
    memory_bounds_virt_t *bounds_virt)
{
    uint64_t start_vaddr, end_vaddr;
    /* This returns 1 on success and anything else is an error. */
    int ret = elf_getMemoryBounds(elf_blob->base, 0, &start_vaddr, &end_vaddr);
    if (ret != 1) {
        printf("ERROR: Could not get virtual bounds (%d)\n", ret);
        return -1;
    }

    /* Check that image virtual address range is sane */
    if (end_vaddr < start_vaddr) {
        printf("ERROR: virtual start address %"PRIx64" is after end %"PRIx64"\n",
               start_vaddr, end_vaddr);
        return -1;
    }
    if ((start_vaddr > UINTPTR_MAX) || (end_vaddr > UINTPTR_MAX)) {
        printf("ERROR: image virtual address [%"PRIx64"..%"PRIx64"] exceeds "
               "UINTPTR_MAX (0x%x)\n",
               start_vaddr, end_vaddr, UINTPTR_MAX);
        return -1;
    }

    if (bounds_virt) {
        *bounds_virt = (memory_bounds_virt_t) {
            .start = (vaddr_t)start_vaddr,
            .end = (vaddr_t)end_vaddr,
        };
    }
    return 0;
}

/*
 * Unpack an ELF file to the given physical address.
 */
static int unpack_elf_blob_to_paddr(
    blob_t const *const elf_blob,
    paddr_t dest_paddr)
{
    int ret;

    memory_bounds_virt_t bounds_virt = {};
    ret = elfBlob_getBounds_virt(elf_blob, &bounds_virt);
    if (ret != 0) {
        printf("ERROR: Could not get image virt bounds (%d)\n", ret);
        return -1;
    }
    size_t image_size = bounds_virt.end - bounds_virt.start;

    if (dest_paddr + image_size < dest_paddr) {
        printf("ERROR: image destination address integer overflow\n");
        return -1;
    }

    /* Zero out all memory in the region, as the ELF file may be sparse. */
    memset((void *)dest_paddr, 0, image_size);

    /* Load each segment in the ELF file. */
    const void *const elf = elf_blob->base;
    for (unsigned int i = 0; i < elf_getNumProgramHeaders(elf); i++) {
        /* Skip segments that are not marked as being loadable. */
        if (elf_getProgramHeaderType(elf, i) != PT_LOAD) {
            continue;
        }

        /* Parse size/length headers. */
        vaddr_t seg_vaddr = elf_getProgramHeaderVaddr(elf, i);
        size_t seg_size = elf_getProgramHeaderFileSize(elf, i);
        size_t seg_elf_offset = elf_getProgramHeaderOffset(elf, i);

        size_t seg_virt_offset = seg_vaddr - bounds_virt.start;
        paddr_t seg_dest_paddr = dest_paddr + seg_virt_offset;
        void const *seg_src_addr = (void const *)((uintptr_t)elf +
                                                  seg_elf_offset);

        /* Check segment sanity and integer overflows. */
        if ((seg_vaddr < bounds_virt.start) ||
            (seg_size > image_size) ||
            (seg_src_addr < elf) ||
            ((uintptr_t)seg_src_addr + seg_size < (uintptr_t)elf) ||
            (seg_virt_offset > image_size) ||
            (seg_virt_offset + seg_size > image_size) ||
            (seg_dest_paddr < dest_paddr) ||
            (seg_dest_paddr + seg_size < dest_paddr)) {
            printf("ERROR: segement %d invalid\n", i);
            return -1;
        }

        /* Load data into memory. */
        memcpy((void *)seg_dest_paddr, seg_src_addr, seg_size);
    }

    return 0;
}

/*
 * Load an ELF file into physical memory at the given physical address.
 *
 * Returns in 'next_phys_addr' the byte past the last byte of the physical
 * address used.
 */
static int load_elf(
    blob_t const *const elf_blob,
    blob_t const *const cpio,
    char const *elf_hash_filename,
    paddr_t dest_paddr,
    int keep_headers,
    struct image_info *info,
    paddr_t *next_phys_addr)
{
    int ret;

    /* Print diagnostics. */
    printf("ELF-loading image '%s' to %p\n", elf_blob->name, dest_paddr);

    memory_bounds_virt_t bounds_virt = {};
    ret = elfBlob_getBounds_virt(elf_blob, &bounds_virt);
    if (ret != 0) {
        printf("ERROR: Could not get image virt bounds (%d)\n", ret);
        return -1;
    }

    /* round up size to the end of the page next page */
    uint64_t vaddr_end = ROUND_UP(bounds_virt.end, PAGE_BITS);
    size_t image_size = vaddr_end - bounds_virt.start;

    /* Ensure our starting physical address is aligned. */
    if (!IS_ALIGNED(dest_paddr, PAGE_BITS)) {
        printf("ERROR: Attempting to load ELF at unaligned physical address\n");
        return -1;
    }

    /* Ensure that the ELF file itself is 4-byte aligned in memory, so that
     * libelf can perform word accesses on it. */
    if (!IS_ALIGNED(dest_paddr, 2)) {
        printf("ERROR: Input ELF file not 4-byte aligned in memory\n");
        return -1;
    }

#ifdef CONFIG_HASH_NONE

    UNUSED_VARIABLE(elf_blob);
    UNUSED_VARIABLE(cpio);
    UNUSED_VARIABLE(elf_hash_filename);

#else

    /* Get the binary file that contains the Hash */
    blob_t hash_blob;
    ret = cpioBlob_getFile(cpio, elf_hash_filename, &hash_blob);
    if (ret != 0) {
        printf("ERROR: hash file '%s' doesn't exist\n", elf_hash_filename);
        return -1;
    }

#ifdef CONFIG_HASH_SHA
    uint8_t calculated_hash[32];
    hashes_t hashes = { .hash_type = SHA_256 };
#else
    uint8_t calculated_hash[16];
    hashes_t hashes = { .hash_type = MD5 };
#endif

    if (hash_blob.size < sizeof(calculated_hash)) {
        printf("ERROR: hash file '%s' size %zu invalid, expected at least %zu\n",
               elf_hash_filename, hash_blob.size, sizeof(calculated_hash));
    }

    /* Print the Hash for the user to see */
    printf("Hash from ELF File: ");
    print_hash(hash_blob.base, sizeof(calculated_hash));

    get_hash(hashes, hash_blob.base, hash_blob.size, calculated_hash);

    /* Print the hash so the user can see they're the same or different */
    printf("Hash for ELF Input: ");
    print_hash(calculated_hash, sizeof(calculated_hash));

    /* Check the hashes are the same. There is no memcmp() in the striped down
     * runtime lib of ELF Loader, so we compare here byte per byte. */
    for (unsigned int i = 0; i < sizeof(calculated_hash); i++) {
        if (((char const *)hash_blob.base)[i] != ((char const *)calculated_hash)[i]) {
            printf("ERROR: Hashes are different\n");
            return -1;
        }
    }

#endif  /* CONFIG_HASH_NONE */

    /* Print diagnostics. */
    printf("  paddr=[%p..%p]\n", dest_paddr, dest_paddr + image_size - 1);
    printf("  vaddr=[%p..%p]\n", (vaddr_t)bounds_virt.start, (vaddr_t)vaddr_end - 1);
    printf("  virt_entry=%p\n", (vaddr_t)elf_getEntryPoint(elf_blob->base));

    /* Ensure the ELF blob is valid. Unfortunately, elf_checkFile() does not
     * take a "size" parameter, so calling this is potentially dangerous.
     */
    ret = elf_checkFile(elf_blob->base);
    if (0 != ret) {
        printf("ERROR: Invalid ELF file\n");
        return -1;
    }

    /* Ensure sane alignment of the image. */
    if (!IS_ALIGNED(bounds_virt.start, PAGE_BITS)) {
        printf("ERROR: Start of image is not 4K-aligned\n");
        return -1;
    }

    /* Ensure that we region we want to write to is sane. */
    ret = ensure_phys_range_valid(dest_paddr, dest_paddr + image_size);
    if (0 != ret) {
        printf("ERROR: Physical address range invalid\n");
        return -1;
    }

    /* Copy the data. */
    ret = unpack_elf_blob_to_paddr(elf_blob, dest_paddr);
    if (0 != ret) {
        printf("ERROR: Unpacking ELF to %p failed\n", dest_paddr);
        return -1;
    }

    /* Record information about the placement of the image. */
    info->phys_region_start = dest_paddr;
    info->phys_region_end = dest_paddr + image_size;
    info->virt_region_start = bounds_virt.start;
    info->virt_region_end = (vaddr_t)bounds_virt.end;
    info->virt_entry = (vaddr_t)elf_getEntryPoint(elf_blob->base);
    info->phys_virt_offset = dest_paddr - bounds_virt.start;

    /* Round up the destination address to the next page */
    dest_paddr = ROUND_UP(dest_paddr + image_size, PAGE_BITS);

    if (keep_headers) {
        /* Provide the ELF headers in a page afterwards */
        void const *elf = elf_blob->base;
        uint32_t phnum = elf_getNumProgramHeaders(elf);
        uint32_t phsize;
        paddr_t source_paddr;
        if (ISELF32(elf)) {
            phsize = ((struct Elf32_Header const *)elf)->e_phentsize;
            source_paddr = (paddr_t)elf32_getProgramHeaderTable(elf);
        } else {
            phsize = ((struct Elf64_Header const *)elf)->e_phentsize;
            source_paddr = (paddr_t)elf64_getProgramHeaderTable(elf);
        }
        /* We have no way of sharing definitions with the kernel so we just
         * memcpy to a bunch of magic offsets. Explicit numbers for sizes
         * and offsets are used so that it is clear exactly what the layout
         * is */
        memcpy((void *)dest_paddr, &phnum, 4);
        memcpy((void *)(dest_paddr + 4), &phsize, 4);
        memcpy((void *)(dest_paddr + 8), (void *)source_paddr, phsize * phnum);
        /* return the frame after our headers */
        dest_paddr += KEEP_HEADERS_SIZE;
    }

    if (next_phys_addr) {
        *next_phys_addr = dest_paddr;
    }
    return 0;
}

/*
 * ELF-loader for ARM systems.
 *
 * We are currently running out of physical memory, with an ELF file for the
 * kernel and one or more ELF files for the userspace image. (Typically there
 * will only be one userspace ELF file, though if we are running a multi-core
 * CPU, we may have multiple userspace images; one per CPU.) These ELF files
 * are packed into an 'ar' archive.
 *
 * The kernel ELF file indicates what physical address it wants to be loaded
 * at, while userspace images run out of virtual memory, so don't have any
 * requirements about where they are located. We place the kernel at its
 * desired location, and then load userspace images straight after it in
 * physical memory.
 *
 * Several things could possibly go wrong:
 *
 *  1. The physical load address of the kernel might want to overwrite this
 *  ELF-loader;
 *
 *  2. The physical load addresses of the kernel might not actually be in
 *  physical memory;
 *
 *  3. Userspace images may not fit in physical memory, or may try to overlap
 *  the ELF-loader.
 *
 *  We attempt to check for some of these, but some may go unnoticed.
 */
int load_images(
    struct image_info *kernel_info,
    struct image_info *user_info,
    unsigned int max_user_images,
    unsigned int *num_images,
    void const *bootloader_dtb,
    void const **chosen_dtb,
    size_t *chosen_dtb_size)
{
    int ret;
    uintptr_t dtb_phys_start, dtb_phys_end;
    paddr_t next_phys_addr;
    int has_dtb_cpio = 0;
    const blob_t cpio_blob = {
        .name = "cpio_archive",
        .base = _archive_start,
        .size = _archive_start_end - _archive_start,
    };

    /* Load kernel. */
    blob_t kernel_elf_blob;
    ret = cpioBlob_getFile(&cpio_blob, "kernel.elf", &kernel_elf_blob);
    if (0 != ret) {
        printf("ERROR: No kernel image present in archive\n");
        return -1;
    }

    /* Ensure the ELF blob is valid. Unfortunately, elf_checkFile() does not
     * take a "size" parameter, so calling this is potentially dangerous.
     */
    ret = elf_checkFile(kernel_elf_blob.base);
    if (ret != 0) {
        printf("ERROR: Kernel image not a valid ELF file\n");
        return -1;
    }

    memory_bounds_phys_t kernel_bounds_phys;
    ret = elfBlob_getBounds_phys(&kernel_elf_blob, &kernel_bounds_phys);
    if (ret != 0) {
        printf("ERROR: Could not get kernel memory bounds (%d)\n", ret);
        return -1;
    }

    /* Reserve space for the kernel, keep next start address page aligned. */
    next_phys_addr = ROUND_UP(kernel_bounds_phys.end, PAGE_BITS);

    void const *dtb = NULL;

#ifdef CONFIG_ELFLOADER_INCLUDE_DTB

    if (chosen_dtb) {
        printf("Looking for DTB in CPIO archive...");
        /*
         * Note the lack of newline in the above printf().  Normally one would
         * have an fflush(stdout) here to ensure that the message shows up on a
         * line-buffered stream (which is the POSIX default on terminal
         * devices).  But we are freestanding (on the "bare metal"), and using
         * our own unbuffered printf() implementation.
         */
        blob_t dtbBob;
        ret = cpioBlob_getFile(&cpio_blob, "kernel.dtb", &dtbBob);
        if (ret != 0) {
            printf("not found.\n");
        } else {
            dtb = dtbBob.base;
            has_dtb_cpio = 1;
            printf("found at %p.\n", dtbBob.base);
        }
    }

#endif /* CONFIG_ELFLOADER_INCLUDE_DTB */

    if (chosen_dtb && !dtb && bootloader_dtb) {
        /* Use the bootloader's DTB if we are not using the DTB in the CPIO
         * archive.
         */
        dtb = bootloader_dtb;
    }

    /*
     * Move the DTB out of the way, if it's present.
     */
    if (dtb) {
        dtb_phys_start = next_phys_addr;
        size_t dtb_size = fdt_size(dtb);
        if (0 == dtb_size) {
            printf("ERROR: Invalid device tree blob supplied\n");
            return -1;
        }

        /* Make sure this is a sane thing to do */
        ret = ensure_phys_range_valid(next_phys_addr,
                                      next_phys_addr + dtb_size);
        if (0 != ret) {
            printf("ERROR: Physical address of DTB invalid\n");
            return -1;
        }

        memmove((void *)next_phys_addr, dtb, dtb_size);
        next_phys_addr += dtb_size;
        next_phys_addr = ROUND_UP(next_phys_addr, PAGE_BITS);
        dtb_phys_end = next_phys_addr;

        printf("Loaded DTB from %p.\n", dtb);
        printf("   paddr=[%p..%p]\n", dtb_phys_start, dtb_phys_end - 1);
        *chosen_dtb = (void *)dtb_phys_start;
        *chosen_dtb_size = dtb_size;
    }

    /* Load the kernel */
    ret = load_elf(&kernel_elf_blob,
                   &cpio_blob,
                   "kernel.bin", // hash file
                   kernel_bounds_phys.start,
                   0, // don't keep ELF headers
                   kernel_info,
                   NULL); // we have calculated next_phys_addr already
    if (0 != ret) {
        printf("ERROR: Could not load kernel ELF\n");
        return -1;
    }

    /*
     * Load userspace images.
     *
     * We assume (and check) that the kernel is the first file in the archive,
     * that the DTB is the second if present,
     * and then load the (n+user_elf_offset)'th file in the archive onto the
     * (n)'th CPU.
     */
    unsigned int user_elf_offset = 2;
    blob_t blob;
    ret = cpioBlob_getEntry(&cpio_blob, 0, &blob);
    if (0 != ret) {
        printf("ERROR: Could not get entry 0 from CPIO (%d)\n", ret);
        return -1;
    }
    ret = strcmp(blob.name, "kernel.elf");
    if (0 != ret) {
        printf("ERROR: Kernel image not first image in archive\n");
        return -1;
    }

    ret = cpioBlob_getEntry(&cpio_blob, 1, &blob);
    if (0 != ret) {
        if (has_dtb_cpio) {
            printf("ERROR: Kernel DTB not second image in archive\n");
            return -1;
        }
        user_elf_offset = 1;
    }

#ifdef CONFIG_ELFLOADER_ROOTSERVERS_LAST

    /* work out the size of the user images - this corresponds to how much
     * memory load_elf uses */
    unsigned int total_user_image_size = 0;
    for (unsigned int i = 0; i < max_user_images; i++) {
        blob_t user_blob = {};
        ret = cpioBlob_getEntry(&cpio_blob, user_elf_offset + i, &user_blob);
        if (0 != ret) {
            break; /* no more images */
        }
        memory_bounds_virt_t bounds_virt = {};
        ret = elfBlob_getBounds_virt(user_blob, &bounds_virt);
        if (0 != ret) {
            printf("ERROR: Could not get bounds for image #%d\n", i);
            return -1;
        }
        /* round up size to the end of the page next page */
        uint64_t max_vaddr = ROUND_UP(bounds_virt.max, PAGE_BITS);
        size_t image_size = max_vaddr - bounds_virt.start;
        /* one page is used for the kept headers */
        total_user_image_size += image_size + KEEP_HEADERS_SIZE;
    }

    /* work out where to place the user image */
    next_phys_addr = ROUND_DOWN(memory_region[0].end, PAGE_BITS)
                     - ROUND_UP(total_user_image_size, PAGE_BITS);

#endif /* CONFIG_ELFLOADER_ROOTSERVERS_LAST */

    *num_images = 0;
    for (unsigned int i = 0; i < max_user_images; i++) {
        /* Fetch info about the next ELF file in the archive. */
        blob_t user_blob = {};
        ret = cpioBlob_getEntry(&cpio_blob, user_elf_offset + i, &user_blob);
        if (0 != ret) {
            break; /* no more images */
        }

        /* Load the file into memory. */
        ret = load_elf(&user_blob,
                       &cpio_blob,
                       "app.bin", // hash file
                       next_phys_addr,
                       1,  // keep ELF headers
                       &user_info[i],
                       &next_phys_addr);
        if (0 != ret) {
            printf("ERROR: Could not load user image ELF\n");
        }

        *num_images = i + 1;
    }

    return 0;
}

/*
 * Platform specific ELF Loader initialization. Can be overwritten.
 */
WEAK void platform_init(void)
{
    /* nothing by default */
}
