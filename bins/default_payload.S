/* Common Symbols */
#define memcpy 0x7c01c
#define memset 0x4d144
#define strcpy 0x4d2f0
#define strncmp 0x4d344
#define alloc 0x62088
#define free 0x624c8
#define add_kernel_module 0xd22d8

#define ADDR(target) (0x20 + (target) - shell_code_entry)
	
/* Addressing Macros */
// Payload bases
#define BASE1 (0x700080 - 0x80)
#define BASE2 (0x50BD4 - 0x244)

// Absolute branching
#define ABS(base, target) ((target) - (base) - .)
#define ABS1(target) ABS(BASE1, (target))
#define ABS2(target) ABS(BASE2, (target))

// Dynamic macros to load a label into a register
#define MEM_BASE(dest) \
	li dest, 1; \
	rldicr dest, dest, 63, 0;
#define LOAD_LABEL(base, dest, source, address) \
	oris	dest, source, ((base) + (address))@h; \
	ori		dest, dest, ((base) + (address))@l;
#define LOAD_LABEL1(dest, source, address) LOAD_LABEL(BASE1, dest, source, address)
#define LOAD_LABEL2(dest, source, address) LOAD_LABEL(BASE2, dest, source, address)
#define LOADI_LABEL1(dest, address) LOAD_LABEL(BASE1, dest, dest, address)
#define LOADI_LABEL2(dest, address) LOAD_LABEL(BASE2, dest, dest, address)
// For loading an absolute value
#define LOAD_ABS(dest, source, address) LOAD_LABEL(0, dest, source, address)
#define LOADI_ABS(dest, address) LOAD_ABS(dest, dest, address)
// Absolute .quads
#define QUAD_ABS(base, address) .quad 0x8000000000000000 + base + address
#define QUAD_ABS1(address) QUAD_ABS(BASE1, address)
#define QUAD_ABS2(address) QUAD_ABS(BASE2, address)

/* Patch Table Macros */
#define PATCH_INST(offset, instruction...) .long offset; instruction
#define PATCH_DATA(offset, data...) .long offset; .long data
#define PATCH_BRANCH(offset, op, target) .long offset; op (. + (target - offset))

.org 0
	// Position 0x18 in the block
	.long	0x50534672
	.long   0x6565646d
	// Position 0x20 in the block
shell_code_entry:			// This is the entry point that gets
					// branched to from the shellcode
	
	subi	%r3, %r3, 0x1000 	// The shellcode adds 0x1000 to %r3,
					// so we revert that to point %r3 to the
					// start of this block
	li	%r5, 0x1000		// Set %r5 to the end of this block
	li	%r4, 1
	rldicr	%r4, %r4, 63, 0
	oris	%r4, %r4, 0x70		// Load 0x8000000000700000 into %r4
shell_code_copy:
	subi	%r5, %r5, 8		// 
	ldx	%r6, %r3, %r5		// Copy 64bit content of %r3[%r5] to %r6
	stdx	%r6, %r4, %r5		// Store 64bit %r6 to %r4
	cmpldi	%r5, 0			// if %r5 reaches our block, end it
	bne	shell_code_copy
	addi	%r4,%r4, ADDR(exploit_main)	// Jump to data shell_code_entry
	mtctr	%r4
	bctr

exploit_main:
	mflr	%r0
	stdu	%r1, -0xa0(%r1)
	std	%r27, 0x78(%r1)
	std	%r28, 0x80(%r1)
	std	%r29, 0x88(%r1)
	std	%r30, 0x90(%r1)
	std	%r31, 0x98(%r1)
	std	%r0, 0xb0(%r1)
	li	%r31, 1
	rldicr	%r31, %r31, 63, 0
	mr	%r3, %r31
	oris	%r3, %r3, 0x05
	ori	%r3, %r3, 0xb3c
	mr	%r4, %r31
	oris	%r4, %r4, 0x70
	ori	%r4, %r4, 0x1ac
	li	%r5, 0x4fa
	bl	ABS1(0x7c01c)
	mr	%r3, %r31
	oris	%r3, %r3, 5
	ori	%r3, %r3, 0xb3c
	addi	%r3, %r3, 0x20
	bl	ABS1(0xd22d8)
	mr	%r3, %r31
	oris	%r3, %r3, 5
	ori	%r3, %r3, 0xb3c
	mr	%r4, %r31
	oris	%r4, %r4, 0x2e
	ori	%r4, %r4, 0xb128
	addi	%r3, %r3, 0x10
	std	%r3, 0x120(%r4)
	mr	%r5, %r31
	oris	%r5, %r5, 0x70
	ori	%r5, %r5, 0x150
loc_108:
	lwz	%r3, 0(%r5)
	cmplwi	%r3, 0
	beq	loc_128
	lwz	%r4, 4(%r5)
	add	%r3, %r3, %r31
	stw	%r4, 0(%r3)
	addi	%r5, %r5, 8
	b	loc_108
loc_128:
	b	loc_6b0
	stdu	%r1, -0xb0(%r1)
	mflr	%r0
	std	%r30, 0xa0(%r1)
	std	%r31, 0xa8(%r1)
	std	%r29, 0x98(%r1)
	std	%r0, 0xc0(%r1)
	li	%r30, 0x7d0
	li	%r31, 0xc8
	b	ABS1(0xab04)

#define PATCH_INST(offset, instruction...) .long offset; instruction
#define PATCH_DATA(offset, data...) .long offset; .long data
#define PATCH_BRANCH(offset, op, target) .long offset; op (. + (target - offset))

	PATCH_INST(0x0490e0, ld %r4, 0xf08(%r2))
	PATCH_INST(0x0490e4, ld %r3, 0x20(%r28))
	PATCH_INST(0x0490e8, std %r3, 0(%r4))
	PATCH_BRANCH(0x04f0a8, bl, 0x050b44)
	PATCH_BRANCH(0x2aafc8, b, 0x050b48)
	PATCH_INST(0x04ed18, li %r4, 0)
	PATCH_INST(0x04ed1c, stw %r4, 0(%r3))
	PATCH_INST(0x04ed20, blr)
	PATCH_DATA(0x3ba890, 0x01000000)
	PATCH_INST(0x0505d0, li %r3, 1)
	PATCH_INST(0x0505d4, blr)
	.long	0

.org 0x1ac
	li	%r3, 1
	blr
	b	loc_426
	b	loc_3a4

.org 0x1bc
	// looks like a class
	.quad 0x8000000000050CA8
	.quad 0x800000000033E720
	.quad 0x8000000000051032
	.quad 0x8000000000050B7C
	.quad 0x8000000000050B8C
	.quad 0x8000000000050B9C
	.quad 0x8000000000050BD4 // .match = port6_match
	.quad 0x800000000033E720
	.quad 0x8000000000050C1C // .plug = port6_plugged
	.quad 0x800000000033E720
	.quad 0x8000000000050C78 // .unplug = port6_unplugged
	.quad 0x800000000033E720
	.quad 0x8000000000050C84 // .??? = store_flag
	.quad 0x800000000033E720

	.quad 0
	.quad 0
flag:	.long 0
	.long 0

.org 0x244  // Relocated to 0x50BD4, ABS offset is 0x50990
port6_match:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	li	%r5, 1
	bl	ABS2(0xd2998)
	lwz	%r5, 8(%r3)
	li	%r3, 0
	lis	%r4, 0xaaaa
	ori	%r4, %r4, 0xc0de
	cmplw	%r4, %r5
	beq	loc_278
	li	%r3, -1
loc_278:
	extsw	%r3, %r3
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

.org 0x28c
// Relocated to 0x50C1C
port6_plugged:
	stdu	%r1, -0x80(%r1)
	mflr	%r0
	std	%r0, 0x90(%r1)
	li	%r4, 0
	bl	ABS2(0xd29c4)
	addi	%r4, %r1, 0x70
	li	%r5, 0
	std	%r5, 0(%r4)
	li	%r6, 0x21aa
	sth	%r6, 0(%r4)
	li	%r6, 0
	sth	%r6, 6(%r4)
	li	%r6, 1
	rldicr	%r6, %r6, 63, 0
	oris	%r6, %r6, 5
	ori	%r6, %r6, 0xbac
	li	%r7, 0
	bl	ABS2(0xd292c)
	li	%r3, 0
	ld	%r0, 0x90(%r1)
	mtlr	%r0
	addi	%r1, %r1, 0x80
	blr

.org 0x2e8
// Relocated to 0x50C78
port6_unplugged:
	blr

store_flag: // 0x50c84
	cmpwi	%r3, 0
	bne	loc_314
	li	%r3, 1
	rldicr	%r3, %r3, 63, 0
	oris	%r3, %r3, 5
	ori	%r3, %r3, 0xbbc
	li	%r4, 1
	stw	%r4, 0x10(%r3)  // store 1 in "flag"
loc_314:
	blr

	stdu	%r1, -0xd0(%r1)
	mflr	%r0
	std	%r0, 0xe0(%r1)
	std	%r31, 0xc8(%r1)
	addi	%r4, %r1, 0x70
	bl	ABS2(0x1b3b3c)
	li	%r31, 1
	rldicr	%r31, %r31, 63, 0
	oris	%r31, %r31, 5
	ori	%r31, %r31, 0xbbc
	ld	%r3, 0(%r31)
	cmpdi	%r3, 0
	beq	loc_354
	li	%r4, 0x27
	bl	ABS2(0x624c8)
loc_354:
	li	%r4, 0x27
	li	%r3, 0x800
	bl	ABS2(0x62088)
	std	%r3, 0(%r31)
	ld	%r4, 0x70(%r1)
	bl	ABS2(0x4d2f0)
	ld	%r3, 0x70(%r1)
	li	%r4, 0x27
	bl	ABS2(0x624c8)
	ld	%r3, 0(%r31)
	bl	ABS2(0x4d318)
	ld	%r4, 0(%r31)
	add	%r3, %r4, %r3
	std	%r3, 8(%r31)
	li	%r3, 0
	ld	%r31, 0xc8(%r1)
	ld	%r0, 0xe0(%r1)
	addi	%r1, %r1, 0xd0
	mtlr	%r0
	blr
loc_3a4:
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
	li	%r31, 1
	rldicr	%r31, %r31, 63, 0
	mr	%r3, %r29
	mr	%r4, %r31
	oris	%r4, %r4, 5
	ori	%r4, %r4, 0x1028
	li	%r5, 9
	bl	ABS2(0x4d344)
	cmpldi	%r3, 0
	bne	loc_424
	oris	%r31, %r31, 5
	ori	%r31, %r31, 0xbbc
	lwz	%r3, 0x10(%r31)
	cmplwi	%r3, 0
	beq	loc_424
	ld	%r3, 0(%r31)
	cmpldi	%r3, 0
	beq	loc_424
	ld	%r3, 8(%r31)
	addi	%r4, %r29, 9
	bl	ABS2(0x4d2f0)
	ld	%r29, 0(%r31)
loc_424:
	mr	%r3, %r29
	b	ABS2(0x2aaff0)
loc_426:
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
	li	%r31, 1
	rldicr	%r31, %r31, 63, 0
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
	bl	ABS2(0x7c01c)
	b	loc_594
loc_4d4:
	mr	%r3, %r29
	mr	%r4, %r30
	bl	ABS2(0x4e81c)
	mr	%r29, %r31
	oris	%r29, %r29, 5
	ori	%r29, %r29, 0xbd0
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
	oris	%r7, %r7, 5
	ori	%r7, %r7, 0xf70
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
	stdu	%r1, -0xb0(%r1)
	mflr	%r0
	std	%r30, 0xa0(%r1)
	std	%r31, 0xa8(%r1)
	std	%r29, 0x98(%r1)
	std	%r0, 0xc0(%r1)
	li	%r30, 0xfa0
	li	%r31, 0xc8
	b	ABS2(0xab04)

	.quad	0xa0556f3d002cb8fd
	.quad	0x8000000000050fb8
	.quad	0x8c0a948c000d99b1
	.quad	0x8000000000050fe0
	.quad	0xa2bc1a5600052adc
	.quad	0x8000000000051004
	.quad	0x6b70280200020017
	.quad	0x8000000000050fd4
	.quad	0x0000000000000000
	.quad	0x0030535438600082
	.quad	0x005f3fc038600001
	.quad	0x005f3fc44e800020
	.quad	0x000000000002ed0c
	.quad	0x3ba0000100000000
	.quad	0x0022b8885f746f6f
	.quad	0x0022b88c6c322e78
	.quad	0x0022b8906d6c2372
	.quad	0x0022b8946f6f7400
	.quad	0x00000000000d68b8
	.quad	0x5f746f6f000d68bc
	.quad	0x6c322e78000d68c0
	.quad	0x6d6c2372000d68c4
	.quad	0x6f6f740000000000

	.string "psgroove!"
	.string "mod"

.org 0x6b0
loc_6b0:
	ld	%r27, 0x78(%r1)
	ld	%r28, 0x80(%r1)
	ld	%r29, 0x88(%r1)
	ld	%r30, 0x90(%r1)
	ld	%r31, 0x98(%r1)
	ld	%r0, 0xb0(%r1)
	addi	%r1, %r1, 0xa0
	mtlr	%r0
	li	%r3, 1
	rldicr	%r3, %r3, 63, 0
	oris	%r3, %r3, 0x70
	li	%r4, 0
	li	%r5, 0x6e8
	b	ABS1(0x4d144)
	nop
	nop

	// fill out to 3840 bytes
.org 3840