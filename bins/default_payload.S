/* Common Symbols */
#define memcpy 			0x7c01c
#define memset 			0x4d144
#define strcpy 			0x4d2f0
#define strncmp	 		0x4d344
#define strlen			0x4d318
#define strdup			0x1b3b3c // FIXME: unsure of the name!
#define alloc 			0x62088
#define free 			0x624c8
#define add_kernel_module 	0xd22d8
#define syscall_table		0x2eb128
#define get_device_descriptor	0xd2998 // FIXME: unsure of the name!
#define unknown_func1		0xd29c4 // FIXME
#define unknown_func2		0xd292c // FIXME
	
#define MAGIC_NUMBER		0x505346726565646d
#define PAGE_SIZE 		0x1000
#define RET1_OFFSET 		0x1ac
#define PAYLOAD_OFFSET_IN_PAGE 	0x18
#define MAGIC_NUMBER_LENGTH	payload_entry - payload_start
#define CODE_OFFSET_IN_PAGE 	(PAYLOAD_OFFSET_IN_PAGE + MAGIC_NUMBER_LENGTH)
#define PAYLOAD_SIZE		ADDR_IN_PAGE(payload_end)
#define RESIDENT_PAYLOAD_OFFSET	(overwritten_kernel_function)
#define RESIDENT_PAYLOAD_SIZE   (payload_end - RESIDENT_PAYLOAD_OFFSET)
#define UNKNOWN_HOOK_BIN_OFFSET	(MEM_BASE3-MEM_BASE2+RESIDENT_PAYLOAD_OFFSET)
#define ADDR_IN_PAGE(target) 	(CODE_OFFSET_IN_PAGE + (target) - payload_entry)
#define ADDR_IN_MEM1(target) 	(ADDR_IN_PAGE(target))
#define ADDR_IN_MEM2(target) 	((target) - RESIDENT_PAYLOAD_OFFSET)

/* Addressing Macros */
// Payload bases
#define MEM_BASE1 		(0x700000)
#define MEM_BASE2 		(0x50B3C)
#define MEM_BASE3 		(0x50F4C)

// Absolute branching
#define ABSOLUTE_MEM1(target)	(target - (MEM_BASE1 + ADDR_IN_MEM1(.)))
#define ABSOLUTE_MEM2(target)	(target - (MEM_BASE2 + ADDR_IN_MEM2(.)))

// Dynamic macros to load a label into a register
#define MEM_BASE(dest) \
	li dest, 1; \
	rldicr dest, dest, 63, 0;
#define LOAD_LABEL(base, dest, source, address) \
	oris	dest, source, ((base) + (address))@h; \
	ori	dest, dest, ((base) + (address))@l;
#define LOAD_LABEL1(dest, source, address) \
	LOAD_LABEL(MEM_BASE1, dest, source, ADDR_IN_MEM1 (address))
#define LOAD_LABEL2(dest, source, address) \
	LOAD_LABEL(MEM_BASE2, dest, source, ADDR_IN_MEM2 (address))
#define LOADI_LABEL1(dest, address) \
	LOAD_LABEL(MEM_BASE1, dest, dest, ADDR_IN_MEM1 (address))
#define LOADI_LABEL2(dest, address) \
	LOAD_LABEL(MEM_BASE2, dest, dest, ADDR_IN_MEM2 (address))
	
#define LOAD_MEM_BASE1(dest) \
	MEM_BASE (dest) \
	oris	dest, dest, MEM_BASE1@h;
#define LOAD_MEM_BASE2(dest) \
	MEM_BASE (dest) \
	LOAD_LABEL (MEM_BASE2, dest, dest, 0)

// Add system calls. Use only in exploit_main because of registers used...
#define ADD_SYSCALL(ptr, num) \
	LOAD_LABEL2 (%r3, %r31, ptr) \
	LOAD_LABEL (0, %r4, %r31, syscall_table) \
	std	%r3, 0x08*num(%r4) \

	
// For loading an absolute value
#define LOAD_ABS(dest, source, address) LOAD_LABEL(0, dest, source, address)
#define LOADI_ABS(dest, address) LOAD_ABS(dest, dest, address)
	
// Absolute .quads
// HACK ALERT: the open toolchain bugs during compilation when trying to add
// a 'bignum' with address or MEM_BASE1.. so we split it here into two .long
// makes it easy since PPC is big endian.
#define QUAD_MEM1(address) \
	.long 0x80000000; \
	.long MEM_BASE1 + ADDR_IN_MEM1(address);
#define QUAD_MEM2(address) \
	.long 0x80000000; \
	.long MEM_BASE2 + ADDR_IN_MEM2(address);

/* Patch Table Macros */
#define PATCH_INST(offset, instruction...) .long offset; instruction
#define PATCH_DATA(offset, data...) .long offset; .long data
#define PATCH_BRANCH(offset, op, target) .long offset; op (target - offset)

	
	// payload_entry:
	// @next_block: Receives in %r3 the pointer to the next memory page
	//
	// This is the entry code to the payload, it will copy the payload to
	// a specific memory location (MEM_BASE1) then jump to the main in it.
	// This is necessary because all branches and calls are 
	//
	// payload_entry (next_block):
	// {
	//   current_block = next_block - PAGE_SIZE;
	//
	//   for (i = PAGE_SIZE - sizeof(uint64); i >= 0; i -= sizeof(uint64)
	//     MEM_BASE1[i] = current_block[i];
	//   goto MEM_BASE1 + exploit_main;
	//  }
.org 0
payload_start:	
	// Position 0x18 in the page
	.quad	MAGIC_NUMBER
	// Position 0x20 in the page
payload_entry:				// This is the entry point that gets
					// branched to from the shellcode
	
	subi	%r3, %r3, PAGE_SIZE 	// The shellcode adds 0x1000 to %r3,
					// so we revert that to point %r3 to the
					// start of this page
	li	%r5, PAGE_SIZE		// Set %r5 to the end of this page
	LOAD_MEM_BASE1(%r4)		// Load 0x8000000000700000 into %r4
payload_copy:
	subi	%r5, %r5, 8		// set %r5 to read the previous quad
	ldx	%r6, %r3, %r5		// Copy quad content of %r3[%r5] to %r6
	stdx	%r6, %r4, %r5		// Store quad %r6 to *%r4
	cmpldi	%r5, 0			// if %r5 reaches our block, end it
	bne	l_payload_copy
	addi	%r4, %r4, ADDR_IN_PAGE(exploit_main)	// Jump to exploit_main
	mtctr	%r4
	bctr
	
	// exploit_main:
	//
	// This is the main function of the exploit, its code is position
	// dependent on MEM_BASE1 and it gets executed from there. It copies
	// the rest of the payload to a safe-from-overwrite memory, while it
	// overwrites an apparently useless/unused function from the kernel.
	// It will also add necessary syscalls and patch the kernel before
	// memsetting the code in MEM_BASE1 to 0 and returning the control
	// back to the kernel
	//
	// exploit_main ():
	// {
	//   memcpy(MEM_BASE2, RESIDENT_PAYLOAD_OFFSET, RESIDENT_PAYLOAD_SIZE)
	//   add_kernel_module (kernel_module_struct);
	//   syscall_table[36] = syscall36_ptr;
	//   ptr = patch_table;
	//   while (ptr[0] != NULL)
	//     *ptr[0] = ptr[1];
	//   memset(MEM_BASE1, 0, PAYLOAD_SIZE);
	//  }
exploit_main:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)
	b	l_patches_applied
	MEM_BASE (%r31)			// Load 0x8000000000000000 in %r31
	LOAD_LABEL(MEM_BASE2, %r3, %r31, 0)	// Load MEM_BASE2 in %r3
	// Copy functions that need to stay resident in memory to MEM_BASE2
	LOAD_LABEL1 (%r4, %r31, RESIDENT_PAYLOAD_OFFSET)
	li	%r5, RESIDENT_PAYLOAD_SIZE
	bl	ABSOLUTE_MEM1(memcpy)
	// Add kernel module for device6
	//LOAD_LABEL2 (%r3, %r31, kernel_module_struct)
	//bl	ABSOLUTE_MEM1(add_kernel_module)
	// Add system call 36 for backup manager
	//ADD_SYSCALL (syscall36_ptr, 36)
	//LOAD_LABEL1 (%r5, %r31, patch_table)
l_apply_patches_loop:
	lwz	%r3, 0(%r5)	// If entry in patch table is NULL, we're done
	cmplwi	%r3, 0
	beq	l_patches_applied
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r31
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	l_apply_patches_loop
l_patches_applied:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	LOAD_MEM_BASE1(%r3)
	li	%r4, 0
	li	%r5, PAYLOAD_SIZE
	b	ABSOLUTE_MEM1(memset)

	//
	// patch_table:
	//
	// The patch table used by exploit_main to patch the kernel
	// it format is .long address, .long new_value
	//
	// it will patch its content until the destination address is 0
	//
patch_table:	
	PATCH_INST(0x0490e0, ld %r4, 0xf08(%r2))
	PATCH_INST(0x0490e4, ld %r3, 0x20(%r28))
	PATCH_INST(0x0490e8, std %r3, 0(%r4))
//	PATCH_BRANCH(0x04f0a8, bl, MEM_BASE2 + ADDR_IN_MEM2(address))
//	PATCH_BRANCH(0x2aafc8, b, MEM_BASE2 + ADDR_IN_MEM2(address))
	PATCH_INST(0x04ed18, li %r4, 0)
	PATCH_INST(0x04ed1c, stw %r4, 0(%r3))
	PATCH_INST(0x04ed20, blr)
	PATCH_DATA(0x3ba890, 0x01000000)
	PATCH_INST(0x0505d0, li %r3, 1)
	PATCH_INST(0x0505d4, blr)
	.long	0

	//
	// overwritten_kernel_function:
	//
	// For now noone knows what the original kernel function did, but
	// this just patches it up to just return 1, and also replaces its
	// content with our own payload
	//
	
.align 4
overwritten_kernel_function:	
	li	%r3, 1
	blr

	// Pointers to various functions
memory_patching_desc:	
	b	memory_patching
hook_open_desc:	
	b	hook_open
syscall36_ptr:
	QUAD_MEM2 (syscall36)
	.quad 0x800000000033E720
kernel_module_struct:
	QUAD_MEM2 (kernel_module_name)
	QUAD_MEM2 (device_match_desc)
	QUAD_MEM2 (device_connect_desc)
	QUAD_MEM2 (device_disconnect_desc)
device_match_desc:	
	QUAD_MEM2 (device_match)
	.quad 0x800000000033E720
device_connect_desc:	
	QUAD_MEM2 (device_connect)
	.quad 0x800000000033E720
device_disconnect_desc:	
	QUAD_MEM2 (device_disconnect)
	.quad 0x800000000033E720
device_setup_response_desc:
	QUAD_MEM2 (device_setup_response)	
	.quad 0x800000000033E720
game_path:	
	.quad 0
game_path_end:	
	.quad 0
flags:	
	.long 0
	
	//
	// device_match:
	// @arg: Some unknown argument, maybe a driver structure
	//
	// This checks for new USB device insertion and validates the
	// vendorID/productID to match 0xaaaac0de (device 6).
	// returns 0 to handle it or -1 to refuse it.
	//
	// device_match(arg):
	// {
	//    char *descriptor = get_device_descriptor(arg, 0, 1);
	//
	//    if (*(uint32 *) (descriptor + 8)) == "0xAAAAC0DE)
	//      return 0;
	//    else
	//      return -1;
	//  }
.align 4
device_match:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	li	%r5, 1
	bl	ABSOLUTE_MEM2(get_device_descriptor)
	lwz	%r5, 8(%r3)
	li	%r3, 0
	lis	%r4, 0xaaaa
	ori	%r4, %r4, 0xc0de
	cmplw	%r4, %r5
	beq	l_device_found
	li	%r3, -1
l_device_found:
	extsw	%r3, %r3
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

	//
	// device_connect:
	// @arg: Some unknown argument, maybe a driver structure
	//
	// This handles a connection of a USB device with the proper
	// productID/vendorID 
	//
	// device_connect(arg):
	// {
	//    short buf[8];
	//
	//    unknown_func1(arg, 0);
	//    *((uint64_t *)buf) = 0;
	//    buf[0] = 0x21AA;
	//    buf[3] = 0;
	//    unknown_func2(arg, buf, 0, device_setup_response_desc, 0);
	//    return 0;
	//  }
device_connect:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	bl	ABSOLUTE_MEM2(unknown_func1)
	addi	%r4, %r1, 0x70		// Set %r4 to a pointer in the stack
	li	%r5, 0
	std	%r5, 0(%r4)		// %r4[0] = 0;
	li	%r6, 0x21aa
	sth	%r6, 0(%r4)		// %r4[0] = 0x21aa;
	li	%r6, 0
	sth	%r6, 6(%r4)		// %r4[6] = 0;
	MEM_BASE (%r6)
	LOADI_LABEL2 (%r6, device_setup_response_desc)
	li	%r7, 0
	bl	ABSOLUTE_MEM2(unknown_func2)
	li	%r3, 0
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

	//
	// device_discconnect:
	// @arg: Some unknown argument, maybe a driver structure
	//
	// This handles a disconnection of a prviously handled USB device
	//
	//  device_discconnect(arg):
	//  {
	//  }
device_disconnect:
	blr

	//
	// device_setup_response:
	// @arg: Some unknown argument, maybe a driver structure
	//
	// This seems to be a callback that gets called once the USB device
	// responds to a SETUP request.
	//
	//  device_setup_response(arg):
	//  {
	//  }
device_setup_response:
	blr

	//
	// syscall36:
	// @path: The path to use for bdvd redirection
	//
	// This new syscall will redirect all file access from /dev_bdvd to
	// the path specified in argument here.
	//
	//  syscall36 (path):
	//  {
	//    char *tmp = strdup(path);
	//
	//    if (game_path)
	//      free (game_path);
	//    game_path = malloc (2048);
	//    strcpy (game_path, tmp);
	//    free (tmp);
	//    game_path_end = game_path + strlen(game_path);
	//    return 0;
	//  }
syscall36:
	stdu	%r1, -0xd0(%r1)
	mflr	%r0
	std	%r0, 0xe0(%r1)
	std	%r31, 0xc8(%r1)
	addi	%r4, %r1, 0x70
	bl	ABSOLUTE_MEM2(strdup)	// strdup %arg3 into %r1[0x70]
	MEM_BASE (%r31)
	LOADI_LABEL2 (%r31, game_path)
	ld	%r3, 0(%r31)
	cmpdi	%r3, 0			// if game_path != NULL: free(game_path)
	beq	l_game_path_null
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
l_game_path_null:
	li	%r4, 0x27
	li	%r3, 0x800
	bl	ABSOLUTE_MEM2(alloc)	// alloc (2048)
	std	%r3, 0(%r31)
	ld	%r4, 0x70(%r1)
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r3, 0x70(%r1)
	li	%r4, 0x27
	bl	ABSOLUTE_MEM2(free)
	ld	%r3, 0(%r31)
	bl	ABSOLUTE_MEM2(strlen)
	ld	%r4, 0(%r31)
	add	%r3, %r4, %r3
	std	%r3, 8(%r31)
	li	%r3, 0			// return 0
	ld	%r31, 0xc8(%r1)
	ld	%r0, 0xe0(%r1)
	addi	%r1, %r1, 0xd0
	mtlr	%r0
	blr

	//
	// hook_open:
	// @path: The path to open
	// @mode: The mode to use for opening the file
	//
	// This hook replaces the open syscall and will replace the path used
	// for file open when the game_path is set to allow for bdvd emulation
	//
	//  hook_open (path, mode):
	//  {
	//    if (strncmp(path, "/dev_bdvd", 9) == 0 && game_path != NULL) {
	//      strcpy (game_path_end, path + 9)
	//      path = game_path;
	//    }
	//    
	//    return original_open (path, mode);
	//  }	
hook_open:
	stdu	%r1, -0xa0(%r1)
	mflr	%r0
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r31, 0x98(%r1)
	std	%r26, 0x70(%r1)
	std	%r27, 0x78(%r1)
	std	%r0, 0xb0(%r1)
	mr	%r28, %r4
	mr	%r29, %r3
	MEM_BASE(%r31)
	LOAD_LABEL2(%r4, %r31, hook_path)
	li	%r5, (hook_path_end - hook_path)
	bl	ABSOLUTE_MEM2(strncmp)
	cmpldi	%r3, 0
	bne	l_proceed
	LOAD_LABEL2(%r31, %r31, game_path)
	ld	%r3, 0(%r31)
	cmpldi	%r3, 0
	beq	l_proceed
	ld	%r3, 8(%r31)
	addi	%r4, %r29, (hook_path_end - hook_path)
	bl	ABSOLUTE_MEM2(strcpy)
	ld	%r29, 0(%r31)
l_proceed:
	mr	%r3, %r29
	b	ABSOLUTE_MEM2(0x2aaff0)
	
memory_patching:
	mflr	%r0
	stdu	%r1, -0x1a0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0x1b0(%r1)
	mr	%r29, %r3
	mr	%r30, %r4
	MEM_BASE (%r31)
	ld	%r28, -0x6a00(%r2)
	ld	%r28, 0x68(%r28)
	ld	%r28, 0x18(%r28)
	ld	%r27, 0xf08(%r2)
	ld	%r9, 0x18(%r29)
	lwz	%r9, 0x30(%r9)
	rldicl	%r9, %r9, 48, 16
	cmpwi	%r9, 0x29
	bne	loc_4d4
	ld	%r4, 0x10(%r28)
	rldicr	%r5, %r4, 24, 39
	rldicl	%r5, %r5, 8, 56
	cmpwi	%r5, 0xff
	beq	loc_4a8
	ori	%r4, %r4, 3
	std	%r4, 0x10(%r28)
	li	%r3, 6
	stw	%r3, 0(%r30)
	b	loc_4b8
loc_4a8:
	ori	%r4, %r4, 2
	std	%r4, 0x10(%r28)
	li	%r3, 0x2c
	stw	%r3, 0(%r30)
loc_4b8:
	lwz	%r5, 4(%r28)
	ld	%r4, 8(%r28)
	ld	%r3, 0(%r27)
	add	%r9, %r3, %r5
	std	%r9, 0(%r27)
	bl	ABSOLUTE_MEM2(memcpy)
	b	loc_594
loc_4d4:
	mr	%r3, %r29
	mr	%r4, %r30
	bl	ABSOLUTE_MEM2(0x4e81c)
	mr	%r29, %r31
	LOADI_LABEL2(%r29, flags)
	lwz	%r3, 0(%r29)
	lwz	%r5, 4(%r28)
	add	%r3, %r3, %r5
	stw	%r3, 0(%r29)
	ld	%r4, 0x10(%r28)
	rldicr	%r5, %r4, 24, 39
	rldicl	%r5, %r5, 8, 56
	cmpwi	%r5, 0xff
	bne	loc_594
	ld	%r3, 0(%r27)
	li	%r4, 0
	li	%r6, 0
loc_51c:
	add	%r7, %r3, %r4
	lwz	%r5, 0(%r7)
	xor	%r6, %r6, %r5
	addi	%r4, %r4, 4
	cmpldi	%r4, 0x400
	bne	loc_51c
	lwz	%r3, 0(%r29)
	rldicr	%r6, %r6, 32, 31
	or	%r6, %r6, %r3
	li	%r3, 0
	stw	%r3, 0(%r29)
	mr	%r7, %r31
	LOADI_LABEL2(%r7, memory_patch_table)
loc_554:
	ld	%r3, 0(%r7)
	cmpldi	%r3, 0
	beq	loc_594
	addi	%r7, %r7, 0x10
	cmpld	%r3, %r6
	bne	loc_554
	ld	%r5, -8(%r7)
	ld	%r7, 0(%r27)
loc_574:
	lwz	%r3, 0(%r5)
	cmplwi	%r3, 0
	beq	loc_594
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r7
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	loc_574
loc_594:
	li	%r3, 0
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0x1b0(%r1)
	addi	%r1, %r1, 0x1a0
	mtlr	%r0
	blr

// FIXME: maybe this needs a specific offset ?
.org UNKNOWN_HOOK_BIN_OFFSET
some_other_hooked_function:	
	stdu	%r1, -0xb0(%r1)
	mflr	%r0
	std	%r30, 0xa0(%r1)
	std	%r31, 0xa8(%r1)
	std	%r29, 0x98(%r1)
	std	%r0, 0xc0(%r1)
	li	%r30, 0xfa0
	li	%r31, 0xc8
	b	ABSOLUTE_MEM2(0xab04)

memory_patch_table:	
	.quad	0xa0556f3d002cb8fd
	QUAD_MEM2(memory_patch_table1)
	.quad	0x8c0a948c000d99b1
	QUAD_MEM2(memory_patch_table3)
	.quad	0xa2bc1a5600052adc
	QUAD_MEM2(memory_patch_table4)
	.quad	0x6b70280200020017
	QUAD_MEM2(memory_patch_table2)
	.quad	0x0000000000000000
memory_patch_table_1:	
	.quad	0x0030535438600082
	.quad	0x005f3fc038600001
	.quad	0x005f3fc44e800020
	.long	0x00000000
memory_patch_table_2:	
	.quad	0x0002ed0c3ba00001
	.long	0x00000000
memory_patch_table_3:	
	.quad	0x0022b8885f746f6f
	.quad	0x0022b88c6c322e78
	.quad	0x0022b8906d6c2372
	.quad	0x0022b8946f6f7400
	.long	0x00000000
memory_patch_table_4:	
	.quad	0x000d68b85f746f6f
	.quad	0x000d68bc6c322e78
	.quad	0x000d68c06d6c2372
	.quad	0x000d68c46f6f7400
	.long	0x00000000

hook_path:	
	.string "PSFreedom"
hook_path_end:	
kernel_module_name:	
	.string "mod"
payload_end:
	// fill out to 3840 bytes
.org 3840