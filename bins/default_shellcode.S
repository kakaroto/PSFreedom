/* JIG payload. Must not exceed 40 bytes */
.org 0
.globl jigcode
jigcode:
	ld	%r4, -0x10(%r3)
	ld	%r3, -0x8(%r3)
.1:
	ld	%r5, 0x18(%r3)
	addi	%r3, %r3, 0x1000
	cmpw	%r4, %r5
	bne	.1
	addi	%r6, %r3, -0xFE0
	mtctr	%r6
	bctr
.org 0x28