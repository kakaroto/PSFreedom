PPU_CC = ppu-gcc
PPU_OBJCOPY = ppu-objcopy

PAYLOADS= default_shellcode.bin \
	shellcode_panic.bin \
	default_payload.bin \

#	payload_bdemu.bin \
	payload_no_bdemu.bin \
	payload_dev_bdemu.bin \
	payload_dev_no_bdemu.bin


all: default_payload.h default_shellcode.h $(PAYLOADS)

raw2payload: raw2payload.c

clean:
	rm -f *.bin *.o *.h *~ raw2payload

%.o: %.S
	$(PPU_CC) -c $< -o $@
%.bin: %.o
	$(PPU_OBJCOPY) -O binary $< $@
%.h: %.bin raw2payload
	./raw2payload $< $@ $(*F)
