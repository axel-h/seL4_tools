#
# Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

function(check_arch_clang)
    if(KernelSel4ArchIA32 OR KernelSel4ArchX86_64)
        set(triple_regex "^x86_64")
    elseif(KernelSel4ArchAarch32) # also set for arm_hyp
        set(triple_regex "^arm")
    elseif(KernelSel4ArchAarch64)
        set(triple_regex "^aarch64")
    elseif(KernelSel4ArchRiscV32)
        set(triple_regex "^riscv(32|64)")
    elseif(KernelSel4ArchRiscV64)
        set(triple_regex "^riscv64")
    else()
        message(FATAL_ERROR "unsupported KernelSel4Arch '${KernelSel4Arch}'")
    endif()

    string(REGEX MATCH ${triple_regex} matched_triple ${TRIPLE})
    if(NOT matched_triple)
        message(FATAL_ERROR "Clang Triple '${TRIPLE}' isn't for KernelSel4Arch '${KernelSel4Arch}'")
    endif()

endfunction()

function(check_arch_gcc)
    if(KernelSel4ArchIA32)
        set(compiler_variable "defined(__i386)")
    elseif(KernelSel4ArchX86_64)
        set(compiler_variable "defined(__x86_64)")
    elseif(KernelSel4ArchAarch32) # also set for arm_hyp
        if(KernelArchArmV7a) # also set for KernelArchArmV7ve
            set(compiler_variable "defined(__ARM_ARCH_7A__)")
        elseif(KernelArchArmV8a)
            set(compiler_variable "defined(__ARM_ARCH_8A__)")
        else()
            message(FATAL_ERROR "unsupported KernelArmArmV '${KernelArmArmV}'")
        endif()
    elseif(KernelSel4ArchAarch64)
        set(compiler_variable "defined(__aarch64__)")
    elseif(KernelSel4ArchRiscV32)
        set(compiler_variable "__riscv_xlen == 32")
    elseif(KernelSel4ArchRiscV64)
        set(compiler_variable "__riscv_xlen == 64")
    else()
        message(FATAL_ERROR "unsupported KernelSel4Arch '${KernelSel4Arch}'")
    endif()

    set(arch_test "
#if ${compiler_variable}
    int main() {return 0;}
#else
#error Invalid arch
#endif
    ")

    check_c_source_compiles("${arch_test}" compiler_arch_test)

    if(NOT compiler_arch_test)
        message(
            FATAL_ERROR
                "Compiler '${CMAKE_C_COMPILER}' isn't for KernelSel4Arch '${KernelSel4Arch}'"
        )
    endif()

endfunction()

function(check_arch_compiler)
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        check_arch_clang()
        check_arch_gcc()
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        check_arch_gcc()
    else()
        message(FATAL_ERROR "unsupported CMAKE_C_COMPILER_ID: '${CMAKE_C_COMPILER_ID}'")
    endif()
endfunction()
