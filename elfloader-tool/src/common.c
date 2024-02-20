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

#if defined(CONFIG_HASH_SHA)
#include "crypt_sha256.h"
#define ELFLOADER_CHECK_HASH
#elif defined(CONFIG_HASH_MD5)
#include "crypt_md5.h"
#define ELFLOADER_CHECK_HASH
#elif !defined(CONFIG_HASH_NONE)
#error "invalid configuration"
#endif

#ifdef ELFLOADER_CHECK_HASH
#include "hash.h"
#endif

#ifdef CONFIG_ELFLOADER_ROOTSERVERS_LAST
#include <platform_info.h> // this provides memory_region
#endif

/* generic blob */
typedef struct {
    char const *name; /* can be NULL */
    void const *base;
    size_t size;
} blob_t;

typedef struct {
    paddr_t min;
    paddr_t max;
} memory_bounds_phys_t;

typedef struct {
    vaddr_t min;
    vaddr_t max;
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

static int cpio_blob_get_file(
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

static int cpio_blob_get_entry(
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

static int get_elf_memory_bounds_phys(
    blob_t const *const elf_blob,
    memory_bounds_phys_t *bounds_phys)
{
    uint64_t min_paddr, max_paddr;
    /* This returns 1 on success and anything else is an error. */
    int ret = elf_getMemoryBounds(elf_blob->base, 1, &min_paddr, &max_paddr);
    if (ret != 1) {
        printf("ERROR: Could not get phys bounds (%d)\n", ret);
        return -1;
    }

    if (bounds_phys) {
        *bounds_phys = (memory_bounds_phys_t) {
            .min = (paddr_t)min_paddr,
            .max = (paddr_t)max_paddr,
        };
    }
    return 0;
}

static int get_elf_memory_bounds_virt(
    blob_t const *const elf_blob,
    memory_bounds_virt_t *bounds_virt)
{
    uint64_t min_vaddr, max_vaddr;
    /* This returns 1 on success and anything else is an error. */
    int ret = elf_getMemoryBounds(elf_blob->base, 0, &min_vaddr, &max_vaddr);
    if (ret != 1) {
        printf("ERROR: Could not get virt bounds (%d)\n", ret);
        return -1;
    }

    /* Check that image virtual address range is sane */
    if ((min_vaddr > UINTPTR_MAX) || (max_vaddr > UINTPTR_MAX)) {
        printf("ERROR: image virtual address [%"PRIu64"..%"PRIu64"] exceeds "
               "UINTPTR_MAX (%u)\n",
               min_vaddr, max_vaddr, UINTPTR_MAX);
        return -1;
    }

    if (bounds_virt) {
        *bounds_virt = (memory_bounds_virt_t) {
            .min = (vaddr_t)min_vaddr,
            .max = (vaddr_t)max_vaddr,
        };
    }
    return 0;
}

#ifdef ELFLOADER_CHECK_HASH
/*
 * Read hash file from CPIO archive and check if blob hash matches
 */
static int check_hash(
    blob_t const *const elf_blob,
    blob_t const *const cpio,
    char const *hash_filename)
{
    blob_t hash_blob;
    int ret = cpio_blob_get_file(cpio, hash_filename, &hash_blob);
    if (ret != 0) {
        printf("ERROR: hash file '%s' doesn't exist\n", hash_filename);
        return -1;
    }

#if defined(CONFIG_HASH_SHA)
    uint8_t calculated_hash[32];
    hashes_t hashes = { .hash_type = SHA_256 };
#elif defined(CONFIG_HASH_MD5)
    uint8_t calculated_hash[16];
    hashes_t hashes = { .hash_type = MD5 };
#else
#error "unsupported hash algorithm"
#endif

    if (hash_blob.size < sizeof(calculated_hash)) {
        printf("ERROR: hash file '%s' size %u invalid, expected at least %u\n",
               hash_filename, hash_blob.size, sizeof(calculated_hash));
    }

    /* Print the Hash for the user to see */
    printf("Hash from ELF File: ");
    print_hash(hash_blob.base, hash_blob.size);

    /* This does not return anything */
    get_hash(hashes, elf_blob->base, elf_blob->size, calculated_hash);

    /* Print the hash so the user can see they're the same or different */
    printf("Hash for ELF Input: ");
    print_hash(calculated_hash, sizeof(calculated_hash));

    /* Check the hashes are the same. There is no memcmp() in the striped down
     * runtime lib of ELF Loader, so we compare here byte per byte.
     */
    for (unsigned int i = 0; i < sizeof(calculated_hash); i++) {
        if (((char const *)hash_blob.base)[i] != ((char const *)calculated_hash)[i]) {
            printf("ERROR: Hashes are different\n");
            return -1;
        }
    }

    return 0;
}
#endif /* not ELFLOADER_CHECK_HASH */

/*
 * Unpack an ELF file to the given physical address.
 */
static int unpack_elf_blob_to_paddr(
    blob_t const *const elf_blob,
    paddr_t dest_paddr)
{
    int ret;

    memory_bounds_virt_t bounds_virt = {0};
    ret = get_elf_memory_bounds_virt(elf_blob, &bounds_virt);
    if (ret != 0) {
        printf("ERROR: Could not get image virt bounds (%d)\n", ret);
        return -1;
    }
    size_t image_size = bounds_virt.max - bounds_virt.min;

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

        size_t seg_virt_offset = seg_vaddr - bounds_virt.min;
        paddr_t seg_dest_paddr = dest_paddr + seg_virt_offset;
        void const *seg_src_addr = (void const *)((uintptr_t)elf +
                                                  seg_elf_offset);

        /* Check segment sanity and integer overflows. */
        if ((seg_vaddr < bounds_virt.min) ||
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
    paddr_t dest_paddr,
    int keep_headers,
    struct image_info *info,
    paddr_t *next_phys_addr)
{
    int ret;

    /* Print diagnostics. */
    printf("ELF-loading image '%s' to %p\n", elf_blob->name, dest_paddr);

    memory_bounds_virt_t bounds_virt = {0};
    ret = get_elf_memory_bounds_virt(elf_blob, &bounds_virt);
    if (ret != 0) {
        printf("ERROR: Could not get image virt bounds (%d)\n", ret);
        return -1;
    }
    /* round up size to the end of the page next page */
    uint64_t max_vaddr = ROUND_UP(bounds_virt.max, PAGE_BITS);
    size_t image_size = max_vaddr - bounds_virt.min;

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

    /* Print diagnostics. */
    printf("  paddr=[%p..%p]\n", dest_paddr, dest_paddr + image_size - 1);
    printf("  vaddr=[%p..%p]\n", (vaddr_t)bounds_virt.min, (vaddr_t)max_vaddr - 1);
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
    if (!IS_ALIGNED(bounds_virt.min, PAGE_BITS)) {
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
    info->virt_region_start = bounds_virt.min;
    info->virt_region_end = (vaddr_t)max_vaddr;
    info->virt_entry = (vaddr_t)elf_getEntryPoint(elf_blob->base);
    info->phys_virt_offset = dest_paddr - bounds_virt.min;

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
        size_t elf_info_len = phsize * phnum;
        memcpy((void *)dest_paddr, &phnum, 4);
        memcpy((void *)(dest_paddr + 4), &phsize, 4);
        size_t elf_info_len = phsize * phnum;
        if (elf_info_len > KEEP_HEADERS_SIZE) [
            printf("ERROR: ELF header exceed one page, need %zu", elf_info_len);
            return -1;
        }
        memcpy((void *)(dest_paddr + 8), (void *)source_paddr, elf_info_len);
        /* return the frame after our headers */
        dest_paddr += KEEP_HEADERS_SIZE;
    }

    if (next_phys_addr) {
        *next_phys_addr = dest_paddr;
    }
    return 0;
}

/*
 * Load the DTB
 */
static int load_dtb(
    blob_t const *const cpio,
    paddr_t dtb_load_phys,
    dtb_info_t *dtb_info)
{
    int ret;

    /* Initialize all fieled are zero, so it is well defined in case
     * CONFIG_ELFLOADER_INCLUDE_DTB is not set.
     */
    blob_t dtb_blob = {};

#ifdef CONFIG_ELFLOADER_INCLUDE_DTB

    /* A DTB present in the CPIO archive takes preference over a DTB passed
     * from the bootloder.
     */

    printf("Looking for DTB in CPIO archive...");
    /* Note the lack of newline in the above printf(). Normally, fflush(stdout)
     * must be called to ensure that the message shows up on a line-buffered
     * stream,  which is the POSIX default on terminal devices). However, we are
     * freestanding (on the "bare metal"), and use our own unbuffered printf()
     * implementation.
     */
    ret = cpio_blob_get_file(cpio, "kernel.dtb", &dtb_blob);
    if (0 != ret) {
        printf("not found.\n");
    } else {
        printf("found at %p.\n", dtb_blob.base);
        if (dtb_info) {
            dtb_info->is_from_cpio = true;
        }
    }

#endif /* CONFIG_ELFLOADER_INCLUDE_DTB */

    /* If we don't have a DTB here, use the one a bootloader might have
     * provided. Since 0 is a valid physical address, the size field is used to
     * determin if the address is valid. A size of -1 indicates, that the actual
     * size is not known - which is usually the case, because a bootloader often
     * just passes an address.
     */
    if (0 == dtb_blob.size) {
        if (0 == dtb_info->size) {
            /* Not having a DTB is not an error. With dtb_info->size still set
             * to zero, the caller can find out that no DTB was loaded and then
             * act accordingly.
             */
            printf("No DTB available\n");
            dtb_info->phys_base = 0;
            return 0;
        }

        printf("Loading DTB passed from bootloader at %p\n",
               dtb_info->phys_base);

        dtb_blob = (blob_t) {
            .name = "booloader_dtb",
            .base = (void const *)(dtb_info->phys_base),
            .size = (size_t)(-1),
        };
    }

    size_t dtb_size = fdt_size(dtb_blob.base);
    if (0 == dtb_size) {
        printf("ERROR: Invalid device tree blob supplied\n");
        return -1;
    }

#ifdef CONFIG_ELFLOADER_INCLUDE_DTB

    if (dtb_info->is_from_cpio && (dtb_size > dtb_blob.size)) {
        printf("ERROR: parsed device tree is larger (%zu byte) than CPIO file (%zu byte)\n",
               dtb_size, dtb_blob.size);
        return -1;
    }

#endif /* CONFIG_ELFLOADER_INCLUDE_DTB */

    /* Move the DTB out of the way. Check that the physical destination
     * location is sane.
     */
    paddr_t dtb_phys_end = dtb_load_phys + dtb_size;
    ret = ensure_phys_range_valid(dtb_load_phys, dtb_phys_end);
    if (0 != ret) {
        printf("ERROR: Physical target address of DTB is invalid\n");
        return -1;
    }

    memmove((void *)dtb_load_phys, dtb_blob.base, dtb_size);

    printf("Loaded DTB from %p.\n", dtb_blob.base);
    printf("   paddr=[%p..%p]\n", dtb_load_phys, dtb_phys_end - 1);

    /* Set DTB values for caller. */
    if (dtb_info) {
        dtb_info->phys_base = dtb_load_phys;
        dtb_info->size = dtb_size;
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
    dtb_info_t *dtb_info)
{
    int ret;

    const blob_t cpio_blob = {
        .name = "cpio_archive",
        .base = _archive_start,
        .size = _archive_start_end - _archive_start,
    };

    /* Set defaults. */
    if (num_images) {
        *num_images = 0;
    }

    /* Load kernel. */
    blob_t kernel_elf_blob;
    ret = cpio_blob_get_file(&cpio_blob, "kernel.elf", &kernel_elf_blob);
    if (0 != ret) {
        printf("ERROR: No kernel image present in archive\n");
        return -1;
    }

#ifdef ELFLOADER_CHECK_HASH
    /* Check kernel image hash */
    ret = check_hash(&kernel_elf_blob, &cpio_blob, "kernel.bin");
    if (0 != ret) {
        printf("ERROR: hash check failed for kernel image (%d)\n", ret);
        return -1;
    }
#endif /* ELFLOADER_CHECK_HASH */

    /* Ensure the ELF blob is valid. Unfortunately, elf_checkFile() does not
     * take a "size" parameter, so calling this is potentially dangerous.
     */
    ret = elf_checkFile(kernel_elf_blob.base);
    if (ret != 0) {
        printf("ERROR: Kernel image not a valid ELF file\n");
        return -1;
    }

    memory_bounds_phys_t kernel_bounds_phys = {0};
    ret = get_elf_memory_bounds_phys(&kernel_elf_blob, &kernel_bounds_phys);
    if (ret != 0) {
        printf("ERROR: Could not get kernel memory bounds (%d)\n", ret);
        return -1;
    }

    /* Load the DTB first, because this allows extracting further platform
     * information from it, which may affect the system setup. The DTB is put
     * after the kernel image, because this ensures it is in a place well
     * aligned with our memory usage.
     */
    paddr_t next_phys_addr = ROUND_UP(kernel_bounds_phys.max, PAGE_BITS);
    ret = load_dtb(&cpio_blob, next_phys_addr, dtb_info);
    if (ret != 0) {
        printf("ERROR: Could not load DTB\n");
        return -1;
    }

    /* It's not an error here if no DTB was loaded. Eventually, the system that
     * we are loading has to decide if it can handle this.
     */
    if (dtb_info->size > 0) {
        next_phys_addr = ROUND_UP(next_phys_addr + dtb_info->size, PAGE_BITS);
    }

    /* Load the kernel */
    ret = load_elf(&kernel_elf_blob,
                   kernel_bounds_phys.min,
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
    ret = cpio_blob_get_entry(&cpio_blob, 0, &blob);
    if (0 != ret) {
        printf("ERROR: Could not get entry 0 from CPIO (%d)\n", ret);
        return -1;
    }
    ret = strcmp(blob.name, "kernel.elf");
    if (0 != ret) {
        printf("ERROR: Kernel image not first image in archive\n");
        return -1;
    }

    ret = cpio_blob_get_entry(&cpio_blob, 1, &blob);
    if (0 != ret) {
        printf("ERROR: Could not get entry 1 from CPIO (%d)\n", ret);
        return -1;
    }
    ret = strcmp(blob.name, "kernel.dtb");
    if (0 != ret) {
#ifdef CONFIG_ELFLOADER_INCLUDE_DTB
        if (dtb_info->is_from_cpio) {
            printf("ERROR: Kernel DTB not second image in archive\n");
            return -1;
        }
#endif
        user_elf_offset = 1;
    }

#ifdef CONFIG_ELFLOADER_ROOTSERVERS_LAST

    /* work out the size of the user images - this corresponds to how much
     * memory load_elf uses */
    unsigned int total_user_image_size = 0;
    for (unsigned int i = 0; i < max_user_images; i++) {
        blob_t user_blob = {0};
        ret = cpio_blob_get_entry(&cpio_blob, user_elf_offset + i, &user_blob);
        if (0 != ret) {
            break; /* no more images */
        }
        memory_bounds_virt_t bounds_virt = {0};
        ret = get_elf_memory_bounds_virt(user_blob, &bounds_virt);
        if (0 != ret) {
            printf("ERROR: Could not get bounds for image #%d\n", i);
            return -1;
        }
        /* round up size to the end of the page next page */
        uint64_t max_vaddr = ROUND_UP(bounds_virt.max, PAGE_BITS);
        size_t image_size = max_vaddr - bounds_virt.min;
        /* one page is used for the kept headers */
        total_user_image_size += image_size + KEEP_HEADERS_SIZE;
    }

    /* work out where to place the user image */

    next_phys_addr = ROUND_DOWN(memory_region[0].end, PAGE_BITS)
                     - ROUND_UP(total_user_image_size, PAGE_BITS);

#endif /* CONFIG_ELFLOADER_ROOTSERVERS_LAST */

    for (unsigned int i = 0; i < max_user_images; i++) {
        /* Fetch info about the next ELF file in the archive. */
        blob_t user_blob = {0};
        ret = cpio_blob_get_entry(&cpio_blob, user_elf_offset + i, &user_blob);
        if (0 != ret) {
            break; /* no more images */
        }

#ifdef ELFLOADER_CHECK_HASH
        /* Check user image hash. Since the name of the file with the hash is
         * hard-coded here, this supports havin one user image only. Currently
         * there is no use case where multiple images are used anyway.
         */
        ret = check_hash(&user_blob, &cpio_blob, "app.bin");
        if (0 != ret) {
            printf("ERROR: hash check failed for %s (%d)\n", user_blob.name, ret);
            return -1;
        }
#endif /* ELFLOADER_CHECK_HASH */
        /* Load the file into memory. */
        ret = load_elf(&user_blob,
                       next_phys_addr,
                       1,  // keep ELF headers
                       &user_info[*num_images],
                       &next_phys_addr);
        if (0 != ret) {
            printf("ERROR: Could not load user image #%d ELF\n", i);
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
