# tools/kexpl/Makefile — сборка PS5-payload триггеров.
#
# Путь 1 (как задумано апстримом): ps5-payload-dev SDK с clang-18/lld-18.
#   export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk && make PS5=1
#   Требуется host clang/lld (SDK bin/prospero-clang — обёртка над ними).
#
# Путь 2 (используется здесь, по умолчанию): freestanding-сборка gcc.
#   gcc -nostdlib -static -no-pie ... — валидный ELF64 ET_EXEC без libc/libkernel,
#   все вызовы через raw syscall. elfldr грузит ET_EXEC (elfldr.c:172-178:
#   ctx.base_addr = min_vaddr; MAP_FIXED), поэтому такой payload исполняется.
#
# Цель: make all -> *.elf ; make verify -> file/readelf/sha256

TRIGGERS := t1_aio_wait_race t2_aio_del_reuse t3_umtx_shm t4_ip6_msfilter t5_aio_poll_abuse

ifeq ($(PS5),1)
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
CFLAGS  := -O2 -Wall -Wno-unused-variable
LDFLAGS :=
ELFS := $(addsuffix .elf,$(TRIGGERS))
else
CC      := gcc
CFLAGS  := -O2 -static -nostdlib -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
           -fno-unwind-tables -fno-ident -fno-zero-initialized-in-bss -mno-red-zone -Wall -Wno-unused-variable
LDFLAGS := -nostdlib -static -no-pie -Wl,-e,_start -Wl,--build-id=none
ELFS := $(addsuffix .elf,$(TRIGGERS))
endif

all: $(ELFS)

%.elf: %.c kexpl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

verify:
	@for f in $(ELFS); do \
	  export LC_ALL=C; \
	  echo "===== $$f"; \
	  file -b $$f; \
	  readelf -h $$f | grep -E "Class|Type|Machine|Entry"; \
	  readelf -lW $$f | grep -E "^  LOAD"; \
	  sha256sum $$f; \
	done

clean:
	rm -f $(ELFS) *.o

.PHONY: all verify clean
