;******************************************************************************
;* TI ARM C/C++ Codegen                                             PC v5.1.6 *
;* Date/Time created: Wed Aug 13 14:52:27 2014                                *
;******************************************************************************
	.compiler_opts --abi=eabi --arm_vmrs_si_workaround=on --code_state=16 --diag_wrap=off --disable_dual_state --embedded_constants=on --endian=little --float_support=FPv4SPD16 --hll_source=on --object_format=elf --silicon_version=7M4 --symdebug:dwarf --symdebug:dwarf_version=3 --unaligned_access=on 
	.thumb

$C$DW$CU	.dwtag  DW_TAG_compile_unit
	.dwattr $C$DW$CU, DW_AT_name("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$CU, DW_AT_producer("TI TI ARM C/C++ Codegen PC v5.1.6 Copyright (c) 1996-2014 Texas Instruments Incorporated")
	.dwattr $C$DW$CU, DW_AT_TI_version(0x01)
	.dwattr $C$DW$CU, DW_AT_comp_dir("C:\Users\khimes\workspace_v6_0\cyassl_tests\Debug")

$C$DW$1	.dwtag  DW_TAG_subprogram, DW_AT_name("memcpy")
	.dwattr $C$DW$1, DW_AT_TI_symbol_name("memcpy")
	.dwattr $C$DW$1, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$1, DW_AT_declaration
	.dwattr $C$DW$1, DW_AT_external
	.dwattr $C$DW$1, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/string.h")
	.dwattr $C$DW$1, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$1, DW_AT_decl_column(0x16)
$C$DW$2	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$2, DW_AT_type(*$C$DW$T$3)
$C$DW$3	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$3, DW_AT_type(*$C$DW$T$160)
$C$DW$4	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$4, DW_AT_type(*$C$DW$T$158)
	.dwendtag $C$DW$1


$C$DW$5	.dwtag  DW_TAG_subprogram, DW_AT_name("memset")
	.dwattr $C$DW$5, DW_AT_TI_symbol_name("memset")
	.dwattr $C$DW$5, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$5, DW_AT_declaration
	.dwattr $C$DW$5, DW_AT_external
	.dwattr $C$DW$5, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/string.h")
	.dwattr $C$DW$5, DW_AT_decl_line(0x63)
	.dwattr $C$DW$5, DW_AT_decl_column(0x16)
$C$DW$6	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$6, DW_AT_type(*$C$DW$T$3)
$C$DW$7	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$7, DW_AT_type(*$C$DW$T$10)
$C$DW$8	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$8, DW_AT_type(*$C$DW$T$158)
	.dwendtag $C$DW$5

	.sect	".const"
	.align	4
	.elfsym	||$O1$$||,SYM_SIZE(32)
||$O1$$||:
	.bits	1634760805,32			; $O1$$.sigma[0] @ 0
	.bits	857760878,32			; $O1$$.sigma[1] @ 32
	.bits	2036477234,32			; $O1$$.sigma[2] @ 64
	.bits	1797285236,32			; $O1$$.sigma[3] @ 96
	.bits	1634760805,32			; $O1$$.tau[0] @ 128
	.bits	824206446,32			; $O1$$.tau[1] @ 160
	.bits	2036477238,32			; $O1$$.tau[2] @ 192
	.bits	1797285236,32			; $O1$$.tau[3] @ 224


;*********************************************************************
;* GROUPED GLOBALS FOR $O1$$                                         *
;*********************************************************************
sigma:	.set	||$O1$$||+0
$C$DW$9	.dwtag  DW_TAG_variable, DW_AT_name("sigma")
	.dwattr $C$DW$9, DW_AT_TI_symbol_name("sigma")
	.dwattr $C$DW$9, DW_AT_type(*$C$DW$T$1129)
	.dwattr $C$DW$9, DW_AT_location[DW_OP_addr sigma]
	.dwattr $C$DW$9, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$9, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$9, DW_AT_decl_column(0x15)
tau:	.set	||$O1$$||+16
$C$DW$10	.dwtag  DW_TAG_variable, DW_AT_name("tau")
	.dwattr $C$DW$10, DW_AT_TI_symbol_name("tau")
	.dwattr $C$DW$10, DW_AT_type(*$C$DW$T$1129)
	.dwattr $C$DW$10, DW_AT_location[DW_OP_addr tau]
	.dwattr $C$DW$10, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$10, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$10, DW_AT_decl_column(0x15)
;	c:\ti\ccsv6\tools\compiler\arm_5.1.6\bin\armopt.exe --call_assumptions=3 --gen_opt_info=2 C:\\Users\\khimes\\AppData\\Local\\Temp\\048162 C:\\Users\\khimes\\AppData\\Local\\Temp\\048164 --opt_info_filename=cyassl/ctaocrypt/src/chacha.nfo 
;

; The following variables will be grouped together to share a common
; base address.  References in the source interlisting will look like
; "1$$.tau", "K$1->tau", "C$1->tau", "&1$$+16", and "C$1+16".
;
;    --offset--    --size--	--variable--
;
;         0           16	static const unsigned sigma[4]
;        16           16	static const unsigned tau[4]
;
	.sect	".text:Chacha_SetKey"
	.clink
	.thumbfunc Chacha_SetKey
	.thumb
	.global	Chacha_SetKey

$C$DW$11	.dwtag  DW_TAG_subprogram, DW_AT_name("Chacha_SetKey")
	.dwattr $C$DW$11, DW_AT_low_pc(Chacha_SetKey)
	.dwattr $C$DW$11, DW_AT_high_pc(0x00)
	.dwattr $C$DW$11, DW_AT_TI_symbol_name("Chacha_SetKey")
	.dwattr $C$DW$11, DW_AT_external
	.dwattr $C$DW$11, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$11, DW_AT_TI_begin_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$11, DW_AT_TI_begin_line(0x71)
	.dwattr $C$DW$11, DW_AT_TI_begin_column(0x05)
	.dwattr $C$DW$11, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$11, DW_AT_decl_line(0x71)
	.dwattr $C$DW$11, DW_AT_decl_column(0x05)
	.dwattr $C$DW$11, DW_AT_TI_max_frame_size(0x00)
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 114,column 1,is_stmt,address Chacha_SetKey,isa 1

	.dwfde $C$DW$CIE, Chacha_SetKey
$C$DW$12	.dwtag  DW_TAG_formal_parameter, DW_AT_name("ctx")
	.dwattr $C$DW$12, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$12, DW_AT_type(*$C$DW$T$507)
	.dwattr $C$DW$12, DW_AT_location[DW_OP_reg0]
$C$DW$13	.dwtag  DW_TAG_formal_parameter, DW_AT_name("key")
	.dwattr $C$DW$13, DW_AT_TI_symbol_name("key")
	.dwattr $C$DW$13, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$13, DW_AT_location[DW_OP_reg1]
$C$DW$14	.dwtag  DW_TAG_formal_parameter, DW_AT_name("keySz")
	.dwattr $C$DW$14, DW_AT_TI_symbol_name("keySz")
	.dwattr $C$DW$14, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$14, DW_AT_location[DW_OP_reg2]

;*****************************************************************************
;* FUNCTION NAME: Chacha_SetKey                                              *
;*                                                                           *
;*   Regs Modified     : A1,A2,A3,A4,SR                                      *
;*   Regs Used         : A1,A2,A3,A4,LR,SR                                   *
;*   Local Frame Size  : 0 Args + 0 Auto + 0 Save = 0 byte                   *
;*****************************************************************************
Chacha_SetKey:
;* --------------------------------------------------------------------------*
;* A2    assigned to k
$C$DW$15	.dwtag  DW_TAG_variable, DW_AT_name("k")
	.dwattr $C$DW$15, DW_AT_TI_symbol_name("k")
	.dwattr $C$DW$15, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$15, DW_AT_location[DW_OP_reg1]
;* A3    assigned to constants
$C$DW$16	.dwtag  DW_TAG_variable, DW_AT_name("constants")
	.dwattr $C$DW$16, DW_AT_TI_symbol_name("constants")
	.dwattr $C$DW$16, DW_AT_type(*$C$DW$T$632)
	.dwattr $C$DW$16, DW_AT_location[DW_OP_reg2]
;* A3    assigned to keySz
$C$DW$17	.dwtag  DW_TAG_variable, DW_AT_name("keySz")
	.dwattr $C$DW$17, DW_AT_TI_symbol_name("keySz")
	.dwattr $C$DW$17, DW_AT_type(*$C$DW$T$631)
	.dwattr $C$DW$17, DW_AT_location[DW_OP_reg2]
;* A2    assigned to key
$C$DW$18	.dwtag  DW_TAG_variable, DW_AT_name("key")
	.dwattr $C$DW$18, DW_AT_TI_symbol_name("key")
	.dwattr $C$DW$18, DW_AT_type(*$C$DW$T$802)
	.dwattr $C$DW$18, DW_AT_location[DW_OP_reg1]
;* A1    assigned to ctx
$C$DW$19	.dwtag  DW_TAG_variable, DW_AT_name("ctx")
	.dwattr $C$DW$19, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$19, DW_AT_type(*$C$DW$T$508)
	.dwattr $C$DW$19, DW_AT_location[DW_OP_reg0]
	.dwcfi	cfa_offset, 0
;** 118	-----------------------    if ( ctx == NULL ) goto g4;
        CBZ       A1, ||$C$L1||         ; [] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 118,column 5,is_stmt,isa 1
        ; BRANCHCC OCCURS {||$C$L1||}    ; [] |118| 
;* --------------------------------------------------------------------------*
;** 132	-----------------------    k = key;
;** 146	-----------------------    *((unsigned *)ctx+16) = *(unsigned *)key;
;** 147	-----------------------    *((unsigned *)ctx+20) = ((unsigned *)k)[1];
;** 148	-----------------------    *((unsigned *)ctx+24) = ((unsigned *)k)[2];
;** 149	-----------------------    *((unsigned *)ctx+28) = ((unsigned *)k)[3];
;** 150	-----------------------    if ( keySz == 32u ) goto g6;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 146,column 5,is_stmt,isa 1
        LDR       A4, [A2, #0]          ; [DPU_3_PIPE] |146| 
        STR       A4, [A1, #16]         ; [DPU_3_PIPE] |146| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 147,column 5,is_stmt,isa 1
        LDR       A4, [A2, #4]          ; [DPU_3_PIPE] |147| 
        STR       A4, [A1, #20]         ; [DPU_3_PIPE] |147| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 148,column 5,is_stmt,isa 1
        LDR       A4, [A2, #8]          ; [DPU_3_PIPE] |148| 
        STR       A4, [A1, #24]         ; [DPU_3_PIPE] |148| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 149,column 5,is_stmt,isa 1
        LDR       A4, [A2, #12]         ; [DPU_3_PIPE] |149| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 150,column 5,is_stmt,isa 1
        CMP       A3, #32               ; [DPU_3_PIPE] |150| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 149,column 5,is_stmt,isa 1
        STR       A4, [A1, #28]         ; [DPU_3_PIPE] |149| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 150,column 5,is_stmt,isa 1
        BEQ       ||$C$L3||             ; [DPU_3_PIPE] |150| 
        ; BRANCHCC OCCURS {||$C$L3||}    ; [] |150| 
;* --------------------------------------------------------------------------*
;** 156	-----------------------    if ( keySz == 16u ) goto g5;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 156,column 9,is_stmt,isa 1
        CMP       A3, #16               ; [DPU_3_PIPE] |156| 
        BEQ       ||$C$L2||             ; [DPU_3_PIPE] |156| 
        ; BRANCHCC OCCURS {||$C$L2||}    ; [] |156| 
;* --------------------------------------------------------------------------*
||$C$L1||:    
;**	-----------------------g4:
;** 157	-----------------------    return (-173);
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 157,column 13,is_stmt,isa 1
        MVN       A2, #172              ; [DPU_3_PIPE] |157| 
        B         ||$C$L5||             ; [DPU_3_PIPE] |157| 
        ; BRANCH OCCURS {||$C$L5||}      ; [] |157| 
;* --------------------------------------------------------------------------*
||$C$L2||:    
;**	-----------------------g5:
;** 159	-----------------------    constants = &1$$+16;
;** 159	-----------------------    goto g7;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 159,column 9,is_stmt,isa 1
        MOVW      A3, ||$O1$$||+16      ; [DPU_3_PIPE] |159| 
        MOVT      A3, ||$O1$$||+16      ; [DPU_3_PIPE] |159| 
        B         ||$C$L4||             ; [DPU_3_PIPE] |159| 
        ; BRANCH OCCURS {||$C$L4||}      ; [] |159| 
;* --------------------------------------------------------------------------*
||$C$L3||:    
;**	-----------------------g6:
;** 151	-----------------------    k += 16;
;** 152	-----------------------    constants = &1$$;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 152,column 9,is_stmt,isa 1
        MOVW      A3, ||$O1$$||+0       ; [DPU_3_PIPE] |152| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 151,column 9,is_stmt,isa 1
        ADDS      A2, A2, #16           ; [DPU_3_PIPE] |151| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 152,column 9,is_stmt,isa 1
        MOVT      A3, ||$O1$$||+0       ; [DPU_3_PIPE] |152| 
;* --------------------------------------------------------------------------*
||$C$L4||:    
;**	-----------------------g7:
;** 161	-----------------------    *((unsigned *)ctx+32) = *(unsigned *)k;
;** 162	-----------------------    *((unsigned *)ctx+36) = ((unsigned *)k)[1];
;** 163	-----------------------    *((unsigned *)ctx+40) = ((unsigned *)k)[2];
;** 164	-----------------------    *((unsigned *)ctx+44) = ((unsigned *)k)[3];
;** 165	-----------------------    *(unsigned *)ctx = *constants;
;** 166	-----------------------    *((unsigned *)ctx+4) = constants[1];
;** 167	-----------------------    *((unsigned *)ctx+8) = constants[2];
;** 168	-----------------------    *((unsigned *)ctx+12) = constants[3];
;** 170	-----------------------    return 0;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 161,column 5,is_stmt,isa 1
        LDR       A4, [A2, #0]          ; [DPU_3_PIPE] |161| 
        STR       A4, [A1, #32]         ; [DPU_3_PIPE] |161| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 162,column 5,is_stmt,isa 1
        LDR       A4, [A2, #4]          ; [DPU_3_PIPE] |162| 
        STR       A4, [A1, #36]         ; [DPU_3_PIPE] |162| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 163,column 5,is_stmt,isa 1
        LDR       A4, [A2, #8]          ; [DPU_3_PIPE] |163| 
        STR       A4, [A1, #40]         ; [DPU_3_PIPE] |163| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 164,column 5,is_stmt,isa 1
        LDR       A2, [A2, #12]         ; [DPU_3_PIPE] |164| 
        STR       A2, [A1, #44]         ; [DPU_3_PIPE] |164| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 165,column 5,is_stmt,isa 1
        LDR       A2, [A3, #0]          ; [DPU_3_PIPE] |165| 
        STR       A2, [A1, #0]          ; [DPU_3_PIPE] |165| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 166,column 5,is_stmt,isa 1
        LDR       A2, [A3, #4]          ; [DPU_3_PIPE] |166| 
        STR       A2, [A1, #4]          ; [DPU_3_PIPE] |166| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 167,column 5,is_stmt,isa 1
        LDR       A2, [A3, #8]          ; [DPU_3_PIPE] |167| 
        STR       A2, [A1, #8]          ; [DPU_3_PIPE] |167| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 168,column 5,is_stmt,isa 1
        LDR       A3, [A3, #12]         ; [DPU_3_PIPE] |168| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 170,column 5,is_stmt,isa 1
        MOVS      A2, #0                ; [DPU_3_PIPE] |170| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 168,column 5,is_stmt,isa 1
        STR       A3, [A1, #12]         ; [DPU_3_PIPE] |168| 
;* --------------------------------------------------------------------------*
||$C$L5||:    
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 170,column 5,is_stmt,isa 1
        MOV       A1, A2                ; [DPU_3_PIPE] |170| 
$C$DW$20	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$20, DW_AT_low_pc(0x00)
	.dwattr $C$DW$20, DW_AT_TI_return
        BX        LR                    ; [DPU_3_PIPE] |170| 
        ; BRANCH OCCURS                  ; [] |170| 
	.dwattr $C$DW$11, DW_AT_TI_end_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$11, DW_AT_TI_end_line(0xab)
	.dwattr $C$DW$11, DW_AT_TI_end_column(0x01)
	.dwendentry
	.dwendtag $C$DW$11

	.sect	".text:Chacha_SetIV"
	.clink
	.thumbfunc Chacha_SetIV
	.thumb
	.global	Chacha_SetIV

$C$DW$21	.dwtag  DW_TAG_subprogram, DW_AT_name("Chacha_SetIV")
	.dwattr $C$DW$21, DW_AT_low_pc(Chacha_SetIV)
	.dwattr $C$DW$21, DW_AT_high_pc(0x00)
	.dwattr $C$DW$21, DW_AT_TI_symbol_name("Chacha_SetIV")
	.dwattr $C$DW$21, DW_AT_external
	.dwattr $C$DW$21, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$21, DW_AT_TI_begin_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$21, DW_AT_TI_begin_line(0x4e)
	.dwattr $C$DW$21, DW_AT_TI_begin_column(0x05)
	.dwattr $C$DW$21, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$21, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$21, DW_AT_decl_column(0x05)
	.dwattr $C$DW$21, DW_AT_TI_max_frame_size(0x20)
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 79,column 1,is_stmt,address Chacha_SetIV,isa 1

	.dwfde $C$DW$CIE, Chacha_SetIV
$C$DW$22	.dwtag  DW_TAG_formal_parameter, DW_AT_name("ctx")
	.dwattr $C$DW$22, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$22, DW_AT_type(*$C$DW$T$507)
	.dwattr $C$DW$22, DW_AT_location[DW_OP_reg0]
$C$DW$23	.dwtag  DW_TAG_formal_parameter, DW_AT_name("inIv")
	.dwattr $C$DW$23, DW_AT_TI_symbol_name("inIv")
	.dwattr $C$DW$23, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$23, DW_AT_location[DW_OP_reg1]
$C$DW$24	.dwtag  DW_TAG_formal_parameter, DW_AT_name("counter")
	.dwattr $C$DW$24, DW_AT_TI_symbol_name("counter")
	.dwattr $C$DW$24, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$24, DW_AT_location[DW_OP_reg2]

;*****************************************************************************
;* FUNCTION NAME: Chacha_SetIV                                               *
;*                                                                           *
;*   Regs Modified     : A1,A2,A3,A4,V1,V2,V3,V9,SP,LR,SR,D0,D0_hi,D1,D1_hi, *
;*                           D2,D2_hi,D3,D3_hi,D4,D4_hi,D5,D5_hi,D6,D6_hi,D7,*
;*                           D7_hi,FPEXC,FPSCR                               *
;*   Regs Used         : A1,A2,A3,A4,V1,V2,V3,V9,SP,LR,SR,D0,D0_hi,D1,D1_hi, *
;*                           D2,D2_hi,D3,D3_hi,D4,D4_hi,D5,D5_hi,D6,D6_hi,D7,*
;*                           D7_hi,FPEXC,FPSCR                               *
;*   Local Frame Size  : 0 Args + 12 Auto + 16 Save = 28 byte                *
;*****************************************************************************
Chacha_SetIV:
;* --------------------------------------------------------------------------*
;* V2    assigned to counter
$C$DW$25	.dwtag  DW_TAG_variable, DW_AT_name("counter")
	.dwattr $C$DW$25, DW_AT_TI_symbol_name("counter")
	.dwattr $C$DW$25, DW_AT_type(*$C$DW$T$631)
	.dwattr $C$DW$25, DW_AT_location[DW_OP_reg5]
;* A2    assigned to inIv
$C$DW$26	.dwtag  DW_TAG_variable, DW_AT_name("inIv")
	.dwattr $C$DW$26, DW_AT_TI_symbol_name("inIv")
	.dwattr $C$DW$26, DW_AT_type(*$C$DW$T$802)
	.dwattr $C$DW$26, DW_AT_location[DW_OP_reg1]
;* V1    assigned to ctx
$C$DW$27	.dwtag  DW_TAG_variable, DW_AT_name("ctx")
	.dwattr $C$DW$27, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$27, DW_AT_type(*$C$DW$T$508)
	.dwattr $C$DW$27, DW_AT_location[DW_OP_reg4]
$C$DW$28	.dwtag  DW_TAG_variable, DW_AT_name("temp")
	.dwattr $C$DW$28, DW_AT_TI_symbol_name("temp")
	.dwattr $C$DW$28, DW_AT_type(*$C$DW$T$1127)
	.dwattr $C$DW$28, DW_AT_location[DW_OP_breg13 0]
	.dwcfi	cfa_offset, 0
;** 81	-----------------------    memset(&temp, 0, 12u);
;** 83	-----------------------    if ( ctx == NULL ) goto g3;
        PUSH      {V1, V2, V3, LR}      ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 16
	.dwcfi	save_reg_to_mem, 14, -4
	.dwcfi	save_reg_to_mem, 6, -8
	.dwcfi	save_reg_to_mem, 5, -12
	.dwcfi	save_reg_to_mem, 4, -16
        MOV       V3, A2                ; [DPU_3_PIPE] |79| 
        MOV       V2, A3                ; [DPU_3_PIPE] |79| 
        MOV       V1, A1                ; [DPU_3_PIPE] |79| 
        SUB       SP, SP, #16           ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 32
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 81,column 5,is_stmt,isa 1
        MOVS      A2, #0                ; [DPU_3_PIPE] |81| 
        MOVS      A3, #12               ; [DPU_3_PIPE] |81| 
        MOV       A1, SP                ; [DPU_3_PIPE] |81| 
$C$DW$29	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$29, DW_AT_low_pc(0x00)
	.dwattr $C$DW$29, DW_AT_name("memset")
	.dwattr $C$DW$29, DW_AT_TI_call
        BL        memset                ; [DPU_3_PIPE] |81| 
        ; CALL OCCURS {memset }          ; [] |81| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 79,column 1,is_stmt,isa 1
        MOV       A2, V3                ; [DPU_3_PIPE] |79| 
        CBZ       V1, ||$C$L6||         ; [] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 83,column 5,is_stmt,isa 1
        ; BRANCHCC OCCURS {||$C$L6||}    ; [] |83| 
;* --------------------------------------------------------------------------*
;** 95	-----------------------    memcpy(&temp, (const void *)inIv, 12u);
;** 97	-----------------------    *((unsigned *)ctx+48) = counter;
;** 98	-----------------------    *((unsigned *)ctx+52) = temp[0];
;** 99	-----------------------    *((unsigned *)ctx+56) = temp[1];
;** 100	-----------------------    *((unsigned *)ctx+60) = temp[2];
;** 102	-----------------------    return 0;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 95,column 5,is_stmt,isa 1
        MOV       A1, SP                ; [DPU_3_PIPE] |95| 
        MOVS      A3, #12               ; [DPU_3_PIPE] |95| 
$C$DW$30	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$30, DW_AT_low_pc(0x00)
	.dwattr $C$DW$30, DW_AT_name("memcpy")
	.dwattr $C$DW$30, DW_AT_TI_call
        BL        memcpy                ; [DPU_3_PIPE] |95| 
        ; CALL OCCURS {memcpy }          ; [] |95| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 99,column 5,is_stmt,isa 1
        LDR       A1, [SP, #4]          ; [DPU_3_PIPE] |99| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 98,column 5,is_stmt,isa 1
        LDR       A3, [SP, #0]          ; [DPU_3_PIPE] |98| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 100,column 5,is_stmt,isa 1
        LDR       A2, [SP, #8]          ; [DPU_3_PIPE] |100| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 97,column 5,is_stmt,isa 1
        STR       V2, [V1, #48]         ; [DPU_3_PIPE] |97| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 99,column 5,is_stmt,isa 1
        STR       A1, [V1, #56]         ; [DPU_3_PIPE] |99| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 98,column 5,is_stmt,isa 1
        STR       A3, [V1, #52]         ; [DPU_3_PIPE] |98| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 100,column 5,is_stmt,isa 1
        STR       A2, [V1, #60]         ; [DPU_3_PIPE] |100| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 102,column 5,is_stmt,isa 1
        MOVS      A1, #0                ; [DPU_3_PIPE] |102| 
        B         ||$C$L7||             ; [DPU_3_PIPE] |102| 
        ; BRANCH OCCURS {||$C$L7||}      ; [] |102| 
;* --------------------------------------------------------------------------*
||$C$L6||:    
;**	-----------------------g3:
;** 84	-----------------------    return (-173);
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 84,column 9,is_stmt,isa 1
        MVN       A1, #172              ; [DPU_3_PIPE] |84| 
;* --------------------------------------------------------------------------*
||$C$L7||:    
        ADD       SP, SP, #16           ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 16
$C$DW$31	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$31, DW_AT_low_pc(0x00)
	.dwattr $C$DW$31, DW_AT_TI_return
        POP       {V1, V2, V3, PC}      ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 0
        ; BRANCH OCCURS                  ; [] 
	.dwattr $C$DW$21, DW_AT_TI_end_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$21, DW_AT_TI_end_line(0x67)
	.dwattr $C$DW$21, DW_AT_TI_end_column(0x01)
	.dwendentry
	.dwendtag $C$DW$21

	.sect	".text:Chacha_encrypt_bytes"
	.clink
	.thumbfunc Chacha_encrypt_bytes
	.thumb

$C$DW$32	.dwtag  DW_TAG_subprogram, DW_AT_name("Chacha_encrypt_bytes")
	.dwattr $C$DW$32, DW_AT_low_pc(Chacha_encrypt_bytes)
	.dwattr $C$DW$32, DW_AT_high_pc(0x00)
	.dwattr $C$DW$32, DW_AT_TI_symbol_name("Chacha_encrypt_bytes")
	.dwattr $C$DW$32, DW_AT_TI_begin_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$32, DW_AT_TI_begin_line(0xd0)
	.dwattr $C$DW$32, DW_AT_TI_begin_column(0x0d)
	.dwattr $C$DW$32, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$32, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$32, DW_AT_decl_column(0x0d)
	.dwattr $C$DW$32, DW_AT_TI_max_frame_size(0xd8)
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 210,column 1,is_stmt,address Chacha_encrypt_bytes,isa 1

	.dwfde $C$DW$CIE, Chacha_encrypt_bytes
$C$DW$33	.dwtag  DW_TAG_formal_parameter, DW_AT_name("ctx")
	.dwattr $C$DW$33, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$33, DW_AT_type(*$C$DW$T$507)
	.dwattr $C$DW$33, DW_AT_location[DW_OP_reg0]
$C$DW$34	.dwtag  DW_TAG_formal_parameter, DW_AT_name("m")
	.dwattr $C$DW$34, DW_AT_TI_symbol_name("m")
	.dwattr $C$DW$34, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$34, DW_AT_location[DW_OP_reg1]
$C$DW$35	.dwtag  DW_TAG_formal_parameter, DW_AT_name("c")
	.dwattr $C$DW$35, DW_AT_TI_symbol_name("c")
	.dwattr $C$DW$35, DW_AT_type(*$C$DW$T$637)
	.dwattr $C$DW$35, DW_AT_location[DW_OP_reg2]
$C$DW$36	.dwtag  DW_TAG_formal_parameter, DW_AT_name("bytes")
	.dwattr $C$DW$36, DW_AT_TI_symbol_name("bytes")
	.dwattr $C$DW$36, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$36, DW_AT_location[DW_OP_reg3]

;*****************************************************************************
;* FUNCTION NAME: Chacha_encrypt_bytes                                       *
;*                                                                           *
;*   Regs Modified     : A1,A2,A3,A4,V1,V2,V3,V4,V5,V6,V7,V8,V9,SP,LR,SR     *
;*   Regs Used         : A1,A2,A3,A4,V1,V2,V3,V4,V5,V6,V7,V8,V9,SP,LR,SR     *
;*   Local Frame Size  : 0 Args + 176 Auto + 36 Save = 212 byte              *
;*****************************************************************************
Chacha_encrypt_bytes:
;* --------------------------------------------------------------------------*
;* A1    assigned to $O$C33
$C$DW$37	.dwtag  DW_TAG_variable, DW_AT_name("$O$C33")
	.dwattr $C$DW$37, DW_AT_TI_symbol_name("$O$C33")
	.dwattr $C$DW$37, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$37, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C34
$C$DW$38	.dwtag  DW_TAG_variable, DW_AT_name("$O$C34")
	.dwattr $C$DW$38, DW_AT_TI_symbol_name("$O$C34")
	.dwattr $C$DW$38, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$38, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C35
$C$DW$39	.dwtag  DW_TAG_variable, DW_AT_name("$O$C35")
	.dwattr $C$DW$39, DW_AT_TI_symbol_name("$O$C35")
	.dwattr $C$DW$39, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$39, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C36
$C$DW$40	.dwtag  DW_TAG_variable, DW_AT_name("$O$C36")
	.dwattr $C$DW$40, DW_AT_TI_symbol_name("$O$C36")
	.dwattr $C$DW$40, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$40, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C37
$C$DW$41	.dwtag  DW_TAG_variable, DW_AT_name("$O$C37")
	.dwattr $C$DW$41, DW_AT_TI_symbol_name("$O$C37")
	.dwattr $C$DW$41, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$41, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C38
$C$DW$42	.dwtag  DW_TAG_variable, DW_AT_name("$O$C38")
	.dwattr $C$DW$42, DW_AT_TI_symbol_name("$O$C38")
	.dwattr $C$DW$42, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$42, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C39
$C$DW$43	.dwtag  DW_TAG_variable, DW_AT_name("$O$C39")
	.dwattr $C$DW$43, DW_AT_TI_symbol_name("$O$C39")
	.dwattr $C$DW$43, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$43, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C40
$C$DW$44	.dwtag  DW_TAG_variable, DW_AT_name("$O$C40")
	.dwattr $C$DW$44, DW_AT_TI_symbol_name("$O$C40")
	.dwattr $C$DW$44, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$44, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C41
$C$DW$45	.dwtag  DW_TAG_variable, DW_AT_name("$O$C41")
	.dwattr $C$DW$45, DW_AT_TI_symbol_name("$O$C41")
	.dwattr $C$DW$45, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$45, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C42
$C$DW$46	.dwtag  DW_TAG_variable, DW_AT_name("$O$C42")
	.dwattr $C$DW$46, DW_AT_TI_symbol_name("$O$C42")
	.dwattr $C$DW$46, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$46, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C43
$C$DW$47	.dwtag  DW_TAG_variable, DW_AT_name("$O$C43")
	.dwattr $C$DW$47, DW_AT_TI_symbol_name("$O$C43")
	.dwattr $C$DW$47, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$47, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C44
$C$DW$48	.dwtag  DW_TAG_variable, DW_AT_name("$O$C44")
	.dwattr $C$DW$48, DW_AT_TI_symbol_name("$O$C44")
	.dwattr $C$DW$48, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$48, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C45
$C$DW$49	.dwtag  DW_TAG_variable, DW_AT_name("$O$C45")
	.dwattr $C$DW$49, DW_AT_TI_symbol_name("$O$C45")
	.dwattr $C$DW$49, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$49, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C46
$C$DW$50	.dwtag  DW_TAG_variable, DW_AT_name("$O$C46")
	.dwattr $C$DW$50, DW_AT_TI_symbol_name("$O$C46")
	.dwattr $C$DW$50, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$50, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C47
$C$DW$51	.dwtag  DW_TAG_variable, DW_AT_name("$O$C47")
	.dwattr $C$DW$51, DW_AT_TI_symbol_name("$O$C47")
	.dwattr $C$DW$51, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$51, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C48
$C$DW$52	.dwtag  DW_TAG_variable, DW_AT_name("$O$C48")
	.dwattr $C$DW$52, DW_AT_TI_symbol_name("$O$C48")
	.dwattr $C$DW$52, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$52, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C49
$C$DW$53	.dwtag  DW_TAG_variable, DW_AT_name("$O$C49")
	.dwattr $C$DW$53, DW_AT_TI_symbol_name("$O$C49")
	.dwattr $C$DW$53, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$53, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C50
$C$DW$54	.dwtag  DW_TAG_variable, DW_AT_name("$O$C50")
	.dwattr $C$DW$54, DW_AT_TI_symbol_name("$O$C50")
	.dwattr $C$DW$54, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$54, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C51
$C$DW$55	.dwtag  DW_TAG_variable, DW_AT_name("$O$C51")
	.dwattr $C$DW$55, DW_AT_TI_symbol_name("$O$C51")
	.dwattr $C$DW$55, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$55, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C52
$C$DW$56	.dwtag  DW_TAG_variable, DW_AT_name("$O$C52")
	.dwattr $C$DW$56, DW_AT_TI_symbol_name("$O$C52")
	.dwattr $C$DW$56, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$56, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C53
$C$DW$57	.dwtag  DW_TAG_variable, DW_AT_name("$O$C53")
	.dwattr $C$DW$57, DW_AT_TI_symbol_name("$O$C53")
	.dwattr $C$DW$57, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$57, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C54
$C$DW$58	.dwtag  DW_TAG_variable, DW_AT_name("$O$C54")
	.dwattr $C$DW$58, DW_AT_TI_symbol_name("$O$C54")
	.dwattr $C$DW$58, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$58, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C55
$C$DW$59	.dwtag  DW_TAG_variable, DW_AT_name("$O$C55")
	.dwattr $C$DW$59, DW_AT_TI_symbol_name("$O$C55")
	.dwattr $C$DW$59, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$59, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C56
$C$DW$60	.dwtag  DW_TAG_variable, DW_AT_name("$O$C56")
	.dwattr $C$DW$60, DW_AT_TI_symbol_name("$O$C56")
	.dwattr $C$DW$60, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$60, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C57
$C$DW$61	.dwtag  DW_TAG_variable, DW_AT_name("$O$C57")
	.dwattr $C$DW$61, DW_AT_TI_symbol_name("$O$C57")
	.dwattr $C$DW$61, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$61, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C58
$C$DW$62	.dwtag  DW_TAG_variable, DW_AT_name("$O$C58")
	.dwattr $C$DW$62, DW_AT_TI_symbol_name("$O$C58")
	.dwattr $C$DW$62, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$62, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C59
$C$DW$63	.dwtag  DW_TAG_variable, DW_AT_name("$O$C59")
	.dwattr $C$DW$63, DW_AT_TI_symbol_name("$O$C59")
	.dwattr $C$DW$63, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$63, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C60
$C$DW$64	.dwtag  DW_TAG_variable, DW_AT_name("$O$C60")
	.dwattr $C$DW$64, DW_AT_TI_symbol_name("$O$C60")
	.dwattr $C$DW$64, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$64, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C61
$C$DW$65	.dwtag  DW_TAG_variable, DW_AT_name("$O$C61")
	.dwattr $C$DW$65, DW_AT_TI_symbol_name("$O$C61")
	.dwattr $C$DW$65, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$65, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C62
$C$DW$66	.dwtag  DW_TAG_variable, DW_AT_name("$O$C62")
	.dwattr $C$DW$66, DW_AT_TI_symbol_name("$O$C62")
	.dwattr $C$DW$66, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$66, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C63
$C$DW$67	.dwtag  DW_TAG_variable, DW_AT_name("$O$C63")
	.dwattr $C$DW$67, DW_AT_TI_symbol_name("$O$C63")
	.dwattr $C$DW$67, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$67, DW_AT_location[DW_OP_reg0]
;* A1    assigned to $O$C64
$C$DW$68	.dwtag  DW_TAG_variable, DW_AT_name("$O$C64")
	.dwattr $C$DW$68, DW_AT_TI_symbol_name("$O$C64")
	.dwattr $C$DW$68, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$68, DW_AT_location[DW_OP_reg0]
$C$DW$69	.dwtag  DW_TAG_variable, DW_AT_name("$O$U7")
	.dwattr $C$DW$69, DW_AT_TI_symbol_name("$O$U7")
	.dwattr $C$DW$69, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$69, DW_AT_location[DW_OP_breg13 64]
$C$DW$70	.dwtag  DW_TAG_variable, DW_AT_name("$O$U11")
	.dwattr $C$DW$70, DW_AT_TI_symbol_name("$O$U11")
	.dwattr $C$DW$70, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$70, DW_AT_location[DW_OP_breg13 68]
$C$DW$71	.dwtag  DW_TAG_variable, DW_AT_name("$O$U15")
	.dwattr $C$DW$71, DW_AT_TI_symbol_name("$O$U15")
	.dwattr $C$DW$71, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$71, DW_AT_location[DW_OP_breg13 72]
$C$DW$72	.dwtag  DW_TAG_variable, DW_AT_name("$O$U19")
	.dwattr $C$DW$72, DW_AT_TI_symbol_name("$O$U19")
	.dwattr $C$DW$72, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$72, DW_AT_location[DW_OP_breg13 76]
$C$DW$73	.dwtag  DW_TAG_variable, DW_AT_name("$O$U23")
	.dwattr $C$DW$73, DW_AT_TI_symbol_name("$O$U23")
	.dwattr $C$DW$73, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$73, DW_AT_location[DW_OP_breg13 80]
$C$DW$74	.dwtag  DW_TAG_variable, DW_AT_name("$O$U27")
	.dwattr $C$DW$74, DW_AT_TI_symbol_name("$O$U27")
	.dwattr $C$DW$74, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$74, DW_AT_location[DW_OP_breg13 84]
$C$DW$75	.dwtag  DW_TAG_variable, DW_AT_name("$O$U31")
	.dwattr $C$DW$75, DW_AT_TI_symbol_name("$O$U31")
	.dwattr $C$DW$75, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$75, DW_AT_location[DW_OP_breg13 88]
$C$DW$76	.dwtag  DW_TAG_variable, DW_AT_name("$O$U35")
	.dwattr $C$DW$76, DW_AT_TI_symbol_name("$O$U35")
	.dwattr $C$DW$76, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$76, DW_AT_location[DW_OP_breg13 92]
$C$DW$77	.dwtag  DW_TAG_variable, DW_AT_name("$O$U39")
	.dwattr $C$DW$77, DW_AT_TI_symbol_name("$O$U39")
	.dwattr $C$DW$77, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$77, DW_AT_location[DW_OP_breg13 96]
$C$DW$78	.dwtag  DW_TAG_variable, DW_AT_name("$O$U43")
	.dwattr $C$DW$78, DW_AT_TI_symbol_name("$O$U43")
	.dwattr $C$DW$78, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$78, DW_AT_location[DW_OP_breg13 100]
$C$DW$79	.dwtag  DW_TAG_variable, DW_AT_name("$O$U47")
	.dwattr $C$DW$79, DW_AT_TI_symbol_name("$O$U47")
	.dwattr $C$DW$79, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$79, DW_AT_location[DW_OP_breg13 104]
$C$DW$80	.dwtag  DW_TAG_variable, DW_AT_name("$O$U51")
	.dwattr $C$DW$80, DW_AT_TI_symbol_name("$O$U51")
	.dwattr $C$DW$80, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$80, DW_AT_location[DW_OP_breg13 108]
$C$DW$81	.dwtag  DW_TAG_variable, DW_AT_name("$O$U55")
	.dwattr $C$DW$81, DW_AT_TI_symbol_name("$O$U55")
	.dwattr $C$DW$81, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$81, DW_AT_location[DW_OP_breg13 112]
$C$DW$82	.dwtag  DW_TAG_variable, DW_AT_name("$O$U59")
	.dwattr $C$DW$82, DW_AT_TI_symbol_name("$O$U59")
	.dwattr $C$DW$82, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$82, DW_AT_location[DW_OP_breg13 116]
$C$DW$83	.dwtag  DW_TAG_variable, DW_AT_name("$O$U63")
	.dwattr $C$DW$83, DW_AT_TI_symbol_name("$O$U63")
	.dwattr $C$DW$83, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$83, DW_AT_location[DW_OP_breg13 120]
$C$DW$84	.dwtag  DW_TAG_variable, DW_AT_name("$O$U67")
	.dwattr $C$DW$84, DW_AT_TI_symbol_name("$O$U67")
	.dwattr $C$DW$84, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$84, DW_AT_location[DW_OP_breg13 124]
;* LR    assigned to $O$L3
$C$DW$85	.dwtag  DW_TAG_variable, DW_AT_name("$O$L3")
	.dwattr $C$DW$85, DW_AT_TI_symbol_name("$O$L3")
	.dwattr $C$DW$85, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$85, DW_AT_location[DW_OP_reg14]
;* V4    assigned to i
$C$DW$86	.dwtag  DW_TAG_variable, DW_AT_name("i")
	.dwattr $C$DW$86, DW_AT_TI_symbol_name("i")
	.dwattr $C$DW$86, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$86, DW_AT_location[DW_OP_reg7]
$C$DW$87	.dwtag  DW_TAG_variable, DW_AT_name("bytes")
	.dwattr $C$DW$87, DW_AT_TI_symbol_name("bytes")
	.dwattr $C$DW$87, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$87, DW_AT_location[DW_OP_breg13 128]
$C$DW$88	.dwtag  DW_TAG_variable, DW_AT_name("c")
	.dwattr $C$DW$88, DW_AT_TI_symbol_name("c")
	.dwattr $C$DW$88, DW_AT_type(*$C$DW$T$637)
	.dwattr $C$DW$88, DW_AT_location[DW_OP_breg13 132]
$C$DW$89	.dwtag  DW_TAG_variable, DW_AT_name("m")
	.dwattr $C$DW$89, DW_AT_TI_symbol_name("m")
	.dwattr $C$DW$89, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$89, DW_AT_location[DW_OP_breg13 136]
;* A1    assigned to ctx
$C$DW$90	.dwtag  DW_TAG_variable, DW_AT_name("ctx")
	.dwattr $C$DW$90, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$90, DW_AT_type(*$C$DW$T$508)
	.dwattr $C$DW$90, DW_AT_location[DW_OP_reg0]
$C$DW$91	.dwtag  DW_TAG_variable, DW_AT_name("i")
	.dwattr $C$DW$91, DW_AT_TI_symbol_name("i")
	.dwattr $C$DW$91, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$91, DW_AT_location[DW_OP_breg13 140]
;* V9    assigned to $O$d2
$C$DW$92	.dwtag  DW_TAG_variable, DW_AT_name("$O$d2")
	.dwattr $C$DW$92, DW_AT_TI_symbol_name("$O$d2")
	.dwattr $C$DW$92, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$92, DW_AT_location[DW_OP_reg12]
$C$DW$93	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_60")
	.dwattr $C$DW$93, DW_AT_TI_symbol_name("$O$x_60")
	.dwattr $C$DW$93, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$93, DW_AT_location[DW_OP_breg13 144]
;* A3    assigned to $O$x_56
$C$DW$94	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_56")
	.dwattr $C$DW$94, DW_AT_TI_symbol_name("$O$x_56")
	.dwattr $C$DW$94, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$94, DW_AT_location[DW_OP_reg2]
;* A2    assigned to $O$x_52
$C$DW$95	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_52")
	.dwattr $C$DW$95, DW_AT_TI_symbol_name("$O$x_52")
	.dwattr $C$DW$95, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$95, DW_AT_location[DW_OP_reg1]
;* V8    assigned to $O$x_48
$C$DW$96	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_48")
	.dwattr $C$DW$96, DW_AT_TI_symbol_name("$O$x_48")
	.dwattr $C$DW$96, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$96, DW_AT_location[DW_OP_reg11]
;* V7    assigned to $O$x_44
$C$DW$97	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_44")
	.dwattr $C$DW$97, DW_AT_TI_symbol_name("$O$x_44")
	.dwattr $C$DW$97, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$97, DW_AT_location[DW_OP_reg10]
$C$DW$98	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_40")
	.dwattr $C$DW$98, DW_AT_TI_symbol_name("$O$x_40")
	.dwattr $C$DW$98, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$98, DW_AT_location[DW_OP_breg13 148]
$C$DW$99	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_36")
	.dwattr $C$DW$99, DW_AT_TI_symbol_name("$O$x_36")
	.dwattr $C$DW$99, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$99, DW_AT_location[DW_OP_breg13 152]
;* V6    assigned to $O$x_32
$C$DW$100	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_32")
	.dwattr $C$DW$100, DW_AT_TI_symbol_name("$O$x_32")
	.dwattr $C$DW$100, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$100, DW_AT_location[DW_OP_reg9]
;* V5    assigned to $O$x_28
$C$DW$101	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_28")
	.dwattr $C$DW$101, DW_AT_TI_symbol_name("$O$x_28")
	.dwattr $C$DW$101, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$101, DW_AT_location[DW_OP_reg8]
;* LR    assigned to $O$x_24
$C$DW$102	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_24")
	.dwattr $C$DW$102, DW_AT_TI_symbol_name("$O$x_24")
	.dwattr $C$DW$102, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$102, DW_AT_location[DW_OP_reg14]
;* V9    assigned to $O$x_20
$C$DW$103	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_20")
	.dwattr $C$DW$103, DW_AT_TI_symbol_name("$O$x_20")
	.dwattr $C$DW$103, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$103, DW_AT_location[DW_OP_reg12]
;* V4    assigned to $O$x_16
$C$DW$104	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_16")
	.dwattr $C$DW$104, DW_AT_TI_symbol_name("$O$x_16")
	.dwattr $C$DW$104, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$104, DW_AT_location[DW_OP_reg7]
;* V3    assigned to $O$x_12
$C$DW$105	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_12")
	.dwattr $C$DW$105, DW_AT_TI_symbol_name("$O$x_12")
	.dwattr $C$DW$105, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$105, DW_AT_location[DW_OP_reg6]
;* V2    assigned to $O$x_8
$C$DW$106	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_8")
	.dwattr $C$DW$106, DW_AT_TI_symbol_name("$O$x_8")
	.dwattr $C$DW$106, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$106, DW_AT_location[DW_OP_reg5]
$C$DW$107	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_4")
	.dwattr $C$DW$107, DW_AT_TI_symbol_name("$O$x_4")
	.dwattr $C$DW$107, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$107, DW_AT_location[DW_OP_breg13 156]
;* V1    assigned to $O$x_0
$C$DW$108	.dwtag  DW_TAG_variable, DW_AT_name("$O$x_0")
	.dwattr $C$DW$108, DW_AT_TI_symbol_name("$O$x_0")
	.dwattr $C$DW$108, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$108, DW_AT_location[DW_OP_reg4]
;* LR    assigned to $O$U236
$C$DW$109	.dwtag  DW_TAG_variable, DW_AT_name("$O$U236")
	.dwattr $C$DW$109, DW_AT_TI_symbol_name("$O$U236")
	.dwattr $C$DW$109, DW_AT_type(*$C$DW$T$799)
	.dwattr $C$DW$109, DW_AT_location[DW_OP_reg14]
;* V9    assigned to $O$U236
$C$DW$110	.dwtag  DW_TAG_variable, DW_AT_name("$O$U236")
	.dwattr $C$DW$110, DW_AT_TI_symbol_name("$O$U236")
	.dwattr $C$DW$110, DW_AT_type(*$C$DW$T$799)
	.dwattr $C$DW$110, DW_AT_location[DW_OP_reg12]
;* V1    assigned to $O$U234
$C$DW$111	.dwtag  DW_TAG_variable, DW_AT_name("$O$U234")
	.dwattr $C$DW$111, DW_AT_TI_symbol_name("$O$U234")
	.dwattr $C$DW$111, DW_AT_type(*$C$DW$T$797)
	.dwattr $C$DW$111, DW_AT_location[DW_OP_reg4]
;* V2    assigned to $O$U234
$C$DW$112	.dwtag  DW_TAG_variable, DW_AT_name("$O$U234")
	.dwattr $C$DW$112, DW_AT_TI_symbol_name("$O$U234")
	.dwattr $C$DW$112, DW_AT_type(*$C$DW$T$797)
	.dwattr $C$DW$112, DW_AT_location[DW_OP_reg5]
;* A1    assigned to $O$U239
$C$DW$113	.dwtag  DW_TAG_variable, DW_AT_name("$O$U239")
	.dwattr $C$DW$113, DW_AT_TI_symbol_name("$O$U239")
	.dwattr $C$DW$113, DW_AT_type(*$C$DW$T$799)
	.dwattr $C$DW$113, DW_AT_location[DW_OP_reg0]
;* V1    assigned to $O$U239
$C$DW$114	.dwtag  DW_TAG_variable, DW_AT_name("$O$U239")
	.dwattr $C$DW$114, DW_AT_TI_symbol_name("$O$U239")
	.dwattr $C$DW$114, DW_AT_type(*$C$DW$T$799)
	.dwattr $C$DW$114, DW_AT_location[DW_OP_reg4]
$C$DW$115	.dwtag  DW_TAG_variable, DW_AT_name("temp")
	.dwattr $C$DW$115, DW_AT_TI_symbol_name("temp")
	.dwattr $C$DW$115, DW_AT_type(*$C$DW$T$139)
	.dwattr $C$DW$115, DW_AT_location[DW_OP_breg13 0]
	.dwcfi	cfa_offset, 0
;** 217	-----------------------    if ( !bytes ) goto g15;
        PUSH      {V1, V2, V3, V4, V5, V6, V7, V8, LR} ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 36
	.dwcfi	save_reg_to_mem, 14, -4
	.dwcfi	save_reg_to_mem, 11, -8
	.dwcfi	save_reg_to_mem, 10, -12
	.dwcfi	save_reg_to_mem, 9, -16
	.dwcfi	save_reg_to_mem, 8, -20
	.dwcfi	save_reg_to_mem, 7, -24
	.dwcfi	save_reg_to_mem, 6, -28
	.dwcfi	save_reg_to_mem, 5, -32
	.dwcfi	save_reg_to_mem, 4, -36
        SUB       SP, SP, #180          ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 216
        STR       A4, [SP, #128]        ; [DPU_3_PIPE] |210| 
        STR       A3, [SP, #132]        ; [DPU_3_PIPE] |210| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 217,column 5,is_stmt,isa 1
        CMP       A4, #0                ; [DPU_3_PIPE] |217| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 210,column 1,is_stmt,isa 1
        STR       A2, [SP, #136]        ; [DPU_3_PIPE] |210| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 217,column 5,is_stmt,isa 1
        BEQ       ||$C$L14||            ; [DPU_3_PIPE] |217| 
        ; BRANCHCC OCCURS {||$C$L14||}   ; [] |217| 
;* --------------------------------------------------------------------------*
;**  	-----------------------    #pragma LOOP_FLAGS(4352u)
;**  	-----------------------    goto g6;
        B         ||$C$L10||            ; [DPU_3_PIPE] 
        ; BRANCH OCCURS {||$C$L10||}     ; [] 
;* --------------------------------------------------------------------------*
||$C$L8||:    
;**	-----------------------g3:
;**  	-----------------------    U$234 = m;
;**  	-----------------------    U$239 = c;
;** 227	-----------------------    L$3 = 16;
;**  	-----------------------    U$236 = &((unsigned char *)temp)[0];
;**  	-----------------------    #pragma MUST_ITERATE(16, 16, 16)
;**  	-----------------------    // LOOP BELOW UNROLLED BY FACTOR(4)
;**  	-----------------------    #pragma LOOP_FLAGS(4098u)
        LDR       V2, [SP, #136]        ; [DPU_3_PIPE] 
        LDR       V1, [SP, #132]        ; [DPU_3_PIPE] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 227,column 21,is_stmt,isa 1
        MOV       LR, #16               ; [DPU_3_PIPE] |227| 
        MOV       V9, SP                ; [DPU_3_PIPE] 
;* --------------------------------------------------------------------------*
;*   BEGIN LOOP ||$C$L9||
;*
;*   Loop source line                : 227
;*   Loop closing brace source line  : 229
;*   Loop Unroll Multiple            : 4x
;*   Known Minimum Trip Count        : 16
;*   Known Maximum Trip Count        : 16
;*   Known Max Trip Count Factor     : 16
;* --------------------------------------------------------------------------*
||$C$L9||:    
;**	-----------------------g4:
;** 228	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 228	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 228	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 228	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 227	-----------------------    if ( --L$3 ) goto g4;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 228,column 13,is_stmt,isa 1
        LDRB      V4, [V9], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V5, [V2], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V3, [V9], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V8, [V9], #1          ; [DPU_3_PIPE] |228| 
        EOR       V4, V4, V5            ; [DPU_3_PIPE] |228| 
        STRB      V4, [V1], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V5, [V2], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V7, [V9], #1          ; [DPU_3_PIPE] |228| 
        EOR       V3, V3, V5            ; [DPU_3_PIPE] |228| 
        STRB      V3, [V1], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V5, [V2], #1          ; [DPU_3_PIPE] |228| 
        EOR       V4, V8, V5            ; [DPU_3_PIPE] |228| 
        STRB      V4, [V1], #1          ; [DPU_3_PIPE] |228| 
        LDRB      V4, [V2], #1          ; [DPU_3_PIPE] |228| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 227,column 21,is_stmt,isa 1
        SUBS      LR, LR, #1            ; [DPU_3_PIPE] |227| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 228,column 13,is_stmt,isa 1
        EOR       V3, V7, V4            ; [DPU_3_PIPE] |228| 
        STRB      V3, [V1], #1          ; [DPU_3_PIPE] |228| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 227,column 21,is_stmt,isa 1
        BNE       ||$C$L9||             ; [DPU_3_PIPE] |227| 
        ; BRANCHCC OCCURS {||$C$L9||}    ; [] |227| 
;* --------------------------------------------------------------------------*
;** 230	-----------------------    bytes -= 64u;
;* --------------------------------------------------------------------------*
;** 231	-----------------------    c += 64;
;** 232	-----------------------    m += 64;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 230,column 9,is_stmt,isa 1
        LDR       A3, [SP, #132]        ; [DPU_3_PIPE] |230| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 231,column 9,is_stmt,isa 1
        LDR       A2, [SP, #136]        ; [DPU_3_PIPE] |231| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 230,column 9,is_stmt,isa 1
        SUBS      A4, A4, #64           ; [DPU_3_PIPE] |230| 
        STR       A4, [SP, #128]        ; [DPU_3_PIPE] |230| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 231,column 9,is_stmt,isa 1
        ADDS      A3, A3, #64           ; [DPU_3_PIPE] |231| 
        STR       A3, [SP, #132]        ; [DPU_3_PIPE] |231| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 232,column 9,is_stmt,isa 1
        ADDS      A2, A2, #64           ; [DPU_3_PIPE] |232| 
        STR       A2, [SP, #136]        ; [DPU_3_PIPE] |232| 
;* --------------------------------------------------------------------------*
;*   BEGIN LOOP ||$C$L10||
;* --------------------------------------------------------------------------*
||$C$L10||:    
;**	-----------------------g6:
;** 182	-----------------------    U$7 = *(unsigned *)ctx;  // [5]
;** 182	-----------------------    x_0 = U$7;  // [5]
;** 182	-----------------------    U$11 = *((unsigned *)ctx+4);  // [5]
;** 182	-----------------------    x_4 = U$11;  // [5]
;** 182	-----------------------    U$15 = *((unsigned *)ctx+8);  // [5]
;** 182	-----------------------    x_8 = U$15;  // [5]
;** 182	-----------------------    U$19 = *((unsigned *)ctx+12);  // [5]
;** 182	-----------------------    x_12 = U$19;  // [5]
;** 182	-----------------------    U$23 = *((unsigned *)ctx+16);  // [5]
;** 182	-----------------------    x_16 = U$23;  // [5]
;** 182	-----------------------    U$27 = *((unsigned *)ctx+20);  // [5]
;** 182	-----------------------    x_20 = U$27;  // [5]
;** 182	-----------------------    U$31 = *((unsigned *)ctx+24);  // [5]
;** 182	-----------------------    x_24 = U$31;  // [5]
;** 182	-----------------------    U$35 = *((unsigned *)ctx+28);  // [5]
;** 182	-----------------------    x_28 = U$35;  // [5]
;** 182	-----------------------    U$39 = *((unsigned *)ctx+32);  // [5]
;** 182	-----------------------    x_32 = U$39;  // [5]
;** 182	-----------------------    U$43 = *((unsigned *)ctx+36);  // [5]
;** 182	-----------------------    x_36 = U$43;  // [5]
;** 182	-----------------------    U$47 = *((unsigned *)ctx+40);  // [5]
;** 182	-----------------------    x_40 = U$47;  // [5]
;** 182	-----------------------    U$51 = *((unsigned *)ctx+44);  // [5]
;** 182	-----------------------    x_44 = U$51;  // [5]
;** 182	-----------------------    U$55 = *((unsigned *)ctx+48);  // [5]
;** 182	-----------------------    x_48 = U$55;  // [5]
;** 182	-----------------------    U$59 = *((unsigned *)ctx+52);  // [5]
;** 182	-----------------------    x_52 = U$59;  // [5]
;** 182	-----------------------    U$63 = *((unsigned *)ctx+56);  // [5]
;** 182	-----------------------    x_56 = U$63;  // [5]
;** 182	-----------------------    U$67 = *((unsigned *)ctx+60);  // [5]
;** 182	-----------------------    x_60 = U$67;  // [5]
;** 185	-----------------------    i = 20u;  // [5]
;**  	-----------------------    #pragma MUST_ITERATE(10, 10, 10)
;**  	-----------------------    #pragma LOOP_FLAGS(0u)
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 182,column 9,is_stmt,isa 1
        LDR       V7, [A1, #16]         ; [DPU_3_PIPE] |182| 
        LDR       A4, [A1, #36]         ; [DPU_3_PIPE] |182| 
        LDR       V1, [A1, #0]          ; [DPU_3_PIPE] |182| 
        LDR       V3, [A1, #32]         ; [DPU_3_PIPE] |182| 
        LDR       V8, [A1, #12]         ; [DPU_3_PIPE] |182| 
        LDR       V4, [A1, #28]         ; [DPU_3_PIPE] |182| 
        LDR       LR, [A1, #4]          ; [DPU_3_PIPE] |182| 
        LDR       V5, [A1, #24]         ; [DPU_3_PIPE] |182| 
        STR       V7, [SP, #80]         ; [DPU_3_PIPE] |182| 
        LDR       A3, [A1, #40]         ; [DPU_3_PIPE] |182| 
        STR       A4, [SP, #100]        ; [DPU_3_PIPE] |182| 
        LDR       V9, [A1, #8]          ; [DPU_3_PIPE] |182| 
        STR       V1, [SP, #64]         ; [DPU_3_PIPE] |182| 
        LDR       V6, [A1, #20]         ; [DPU_3_PIPE] |182| 
        STR       V3, [SP, #96]         ; [DPU_3_PIPE] |182| 
        LDR       A2, [A1, #44]         ; [DPU_3_PIPE] |182| 
        STR       V8, [SP, #76]         ; [DPU_3_PIPE] |182| 
        MOV       V7, A4                ; [DPU_3_PIPE] |182| 
        LDR       A4, [A1, #52]         ; [DPU_3_PIPE] |182| 
        STR       V4, [SP, #92]         ; [DPU_3_PIPE] |182| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 185,column 10,is_stmt,isa 1
        MOVS      V1, #20               ; [DPU_3_PIPE] |185| 
        STR       V1, [SP, #140]        ; [DPU_3_PIPE] |185| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 182,column 9,is_stmt,isa 1
        MOV       V3, V8                ; [DPU_3_PIPE] |182| 
        STR       LR, [SP, #68]         ; [DPU_3_PIPE] |182| 
        LDR       V8, [A1, #48]         ; [DPU_3_PIPE] |182| 
        STR       V5, [SP, #88]         ; [DPU_3_PIPE] |182| 
        LDR       V4, [SP, #80]         ; [DPU_3_PIPE] |182| 
        STR       A3, [SP, #104]        ; [DPU_3_PIPE] |182| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 185,column 10,is_stmt,isa 1
        LDR       V1, [SP, #64]         ; [DPU_3_PIPE] |185| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 182,column 9,is_stmt,isa 1
        STR       A4, [SP, #116]        ; [DPU_3_PIPE] |182| 
        LDR       A4, [A1, #60]         ; [DPU_3_PIPE] |182| 
        STR       V9, [SP, #72]         ; [DPU_3_PIPE] |182| 
        MOV       V2, LR                ; [DPU_3_PIPE] |182| 
        STR       V2, [SP, #156]        ; [DPU_3_PIPE] |182| 
        MOV       LR, V5                ; [DPU_3_PIPE] |182| 
        STR       V6, [SP, #84]         ; [DPU_3_PIPE] |182| 
        LDR       V5, [SP, #92]         ; [DPU_3_PIPE] |182| 
        STR       V7, [SP, #152]        ; [DPU_3_PIPE] |182| 
        MOV       V7, A3                ; [DPU_3_PIPE] |182| 
        LDR       A3, [A1, #56]         ; [DPU_3_PIPE] |182| 
        STR       A2, [SP, #108]        ; [DPU_3_PIPE] |182| 
        MOV       V2, V9                ; [DPU_3_PIPE] |182| 
        STR       V7, [SP, #148]        ; [DPU_3_PIPE] |182| 
        MOV       V9, V6                ; [DPU_3_PIPE] |182| 
        STR       V8, [SP, #112]        ; [DPU_3_PIPE] |182| 
        LDR       V6, [SP, #96]         ; [DPU_3_PIPE] |182| 
        STR       A4, [SP, #124]        ; [DPU_3_PIPE] |182| 
        MOV       V7, A2                ; [DPU_3_PIPE] |182| 
        STR       A4, [SP, #144]        ; [DPU_3_PIPE] |182| 
        LDR       A2, [SP, #116]        ; [DPU_3_PIPE] |182| 
        STR       A3, [SP, #120]        ; [DPU_3_PIPE] |182| 
;* --------------------------------------------------------------------------*
;*   BEGIN LOOP ||$C$L11||
;*
;*   Loop source line                : 185
;*   Loop closing brace source line  : 194
;*   Known Minimum Trip Count        : 10
;*   Known Maximum Trip Count        : 10
;*   Known Max Trip Count Factor     : 10
;* --------------------------------------------------------------------------*
||$C$L11||:    
;**	-----------------------g7:
;** 186	-----------------------    x_0 += x_16;  // [5]
;** 186	-----------------------    C$64 = x_48^x_0;  // [5]
;** 186	-----------------------    x_48 = C$64<<16|C$64>>16u;  // [5]
;** 186	-----------------------    x_32 += x_48;  // [5]
;** 186	-----------------------    C$63 = x_16^x_32;  // [5]
;** 186	-----------------------    x_16 = C$63<<12|C$63>>20u;  // [5]
;** 186	-----------------------    x_0 += x_16;  // [5]
;** 186	-----------------------    C$62 = x_48^x_0;  // [5]
;** 186	-----------------------    x_48 = C$62<<8|C$62>>24u;  // [5]
;** 186	-----------------------    x_32 += x_48;  // [5]
;** 186	-----------------------    C$61 = x_16^x_32;  // [5]
;** 186	-----------------------    x_16 = C$61<<7|C$61>>25u;  // [5]
;** 187	-----------------------    x_4 += x_20;  // [5]
;** 187	-----------------------    C$60 = x_52^x_4;  // [5]
;** 187	-----------------------    x_52 = C$60<<16|C$60>>16u;  // [5]
;** 187	-----------------------    x_36 += x_52;  // [5]
;** 187	-----------------------    C$59 = x_20^x_36;  // [5]
;** 187	-----------------------    x_20 = C$59<<12|C$59>>20u;  // [5]
;** 187	-----------------------    x_4 += x_20;  // [5]
;** 187	-----------------------    C$58 = x_52^x_4;  // [5]
;** 187	-----------------------    x_52 = C$58<<8|C$58>>24u;  // [5]
;** 187	-----------------------    x_36 += x_52;  // [5]
;** 187	-----------------------    C$57 = x_20^x_36;  // [5]
;** 187	-----------------------    x_20 = C$57<<7|C$57>>25u;  // [5]
;** 188	-----------------------    x_8 += x_24;  // [5]
;** 188	-----------------------    C$56 = x_56^x_8;  // [5]
;** 188	-----------------------    x_56 = C$56<<16|C$56>>16u;  // [5]
;** 188	-----------------------    x_40 += x_56;  // [5]
;** 188	-----------------------    C$55 = x_24^x_40;  // [5]
;** 188	-----------------------    x_24 = C$55<<12|C$55>>20u;  // [5]
;** 188	-----------------------    x_8 += x_24;  // [5]
;** 188	-----------------------    C$54 = x_56^x_8;  // [5]
;** 188	-----------------------    x_56 = C$54<<8|C$54>>24u;  // [5]
;** 188	-----------------------    x_40 += x_56;  // [5]
;** 188	-----------------------    C$53 = x_24^x_40;  // [5]
;** 188	-----------------------    x_24 = C$53<<7|C$53>>25u;  // [5]
;** 189	-----------------------    x_12 += x_28;  // [5]
;** 189	-----------------------    C$52 = x_60^x_12;  // [5]
;** 189	-----------------------    x_60 = C$52<<16|C$52>>16u;  // [5]
;** 189	-----------------------    x_44 += x_60;  // [5]
;** 189	-----------------------    C$51 = x_28^x_44;  // [5]
;** 189	-----------------------    x_28 = C$51<<12|C$51>>20u;  // [5]
;** 189	-----------------------    x_12 += x_28;  // [5]
;** 189	-----------------------    C$50 = x_60^x_12;  // [5]
;** 189	-----------------------    x_60 = C$50<<8|C$50>>24u;  // [5]
;** 189	-----------------------    x_44 += x_60;  // [5]
;** 189	-----------------------    C$49 = x_28^x_44;  // [5]
;** 189	-----------------------    x_28 = C$49<<7|C$49>>25u;  // [5]
;** 190	-----------------------    x_0 += x_20;  // [5]
;** 190	-----------------------    C$48 = x_60^x_0;  // [5]
;** 190	-----------------------    x_60 = C$48<<16|C$48>>16u;  // [5]
;** 190	-----------------------    x_40 += x_60;  // [5]
;** 190	-----------------------    C$47 = x_20^x_40;  // [5]
;** 190	-----------------------    x_20 = C$47<<12|C$47>>20u;  // [5]
;** 190	-----------------------    x_0 += x_20;  // [5]
;** 190	-----------------------    C$46 = x_60^x_0;  // [5]
;** 190	-----------------------    x_60 = C$46<<8|C$46>>24u;  // [5]
;** 190	-----------------------    x_40 += x_60;  // [5]
;** 190	-----------------------    C$45 = x_20^x_40;  // [5]
;** 190	-----------------------    x_20 = C$45<<7|C$45>>25u;  // [5]
;** 191	-----------------------    x_4 += x_24;  // [5]
;** 191	-----------------------    C$44 = x_48^x_4;  // [5]
;** 191	-----------------------    x_48 = C$44<<16|C$44>>16u;  // [5]
;** 191	-----------------------    x_44 += x_48;  // [5]
;** 191	-----------------------    C$43 = x_24^x_44;  // [5]
;** 191	-----------------------    x_24 = C$43<<12|C$43>>20u;  // [5]
;** 191	-----------------------    x_4 += x_24;  // [5]
;** 191	-----------------------    C$42 = x_48^x_4;  // [5]
;** 191	-----------------------    x_48 = C$42<<8|C$42>>24u;  // [5]
;** 191	-----------------------    x_44 += x_48;  // [5]
;** 191	-----------------------    C$41 = x_24^x_44;  // [5]
;** 191	-----------------------    x_24 = C$41<<7|C$41>>25u;  // [5]
;** 192	-----------------------    x_8 += x_28;  // [5]
;** 192	-----------------------    C$40 = x_52^x_8;  // [5]
;** 192	-----------------------    x_52 = C$40<<16|C$40>>16u;  // [5]
;** 192	-----------------------    x_32 += x_52;  // [5]
;** 192	-----------------------    C$39 = x_28^x_32;  // [5]
;** 192	-----------------------    x_28 = C$39<<12|C$39>>20u;  // [5]
;** 192	-----------------------    x_8 += x_28;  // [5]
;** 192	-----------------------    C$38 = x_52^x_8;  // [5]
;** 192	-----------------------    x_52 = C$38<<8|C$38>>24u;  // [5]
;** 192	-----------------------    x_32 += x_52;  // [5]
;** 192	-----------------------    C$37 = x_28^x_32;  // [5]
;** 192	-----------------------    x_28 = C$37<<7|C$37>>25u;  // [5]
;** 193	-----------------------    x_12 += x_16;  // [5]
;** 193	-----------------------    C$36 = x_56^x_12;  // [5]
;** 193	-----------------------    x_56 = C$36<<16|C$36>>16u;  // [5]
;** 193	-----------------------    x_36 += x_56;  // [5]
;** 193	-----------------------    C$35 = x_16^x_36;  // [5]
;** 193	-----------------------    x_16 = C$35<<12|C$35>>20u;  // [5]
;** 193	-----------------------    x_12 += x_16;  // [5]
;** 193	-----------------------    C$34 = x_56^x_12;  // [5]
;** 193	-----------------------    x_56 = C$34<<8|C$34>>24u;  // [5]
;** 193	-----------------------    x_36 += x_56;  // [5]
;** 193	-----------------------    C$33 = x_16^x_36;  // [5]
;** 193	-----------------------    x_16 = C$33<<7|C$33>>25u;  // [5]
;** 185	-----------------------    if ( i -= 2u ) goto g7;  // [5]
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 186,column 9,is_stmt,isa 1
        ADDS      V1, V4, V1            ; [DPU_3_PIPE] |186| 
        EOR       V8, V1, V8            ; [DPU_3_PIPE] |186| 
        ROR       V8, V8, #16           ; [DPU_3_PIPE] |186| 
        ADD       V6, V8, V6            ; [DPU_3_PIPE] |186| 
        EOR       V4, V6, V4            ; [DPU_3_PIPE] |186| 
        ROR       V4, V4, #20           ; [DPU_3_PIPE] |186| 
        ADDS      V1, V4, V1            ; [DPU_3_PIPE] |186| 
        EOR       V8, V1, V8            ; [DPU_3_PIPE] |186| 
        ROR       V8, V8, #24           ; [DPU_3_PIPE] |186| 
        STR       V8, [SP, #160]        ; [DPU_3_PIPE] |186| 
        ADD       V8, V8, V6            ; [DPU_3_PIPE] |186| 
        STR       V8, [SP, #164]        ; [DPU_3_PIPE] |186| 
        MOV       V6, V8                ; [DPU_3_PIPE] |186| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 189,column 9,is_stmt,isa 1
        LDR       V8, [SP, #144]        ; [DPU_3_PIPE] |189| 
        ADD       V3, V5, V3            ; [DPU_3_PIPE] |189| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 186,column 9,is_stmt,isa 1
        EOR       V6, V6, V4            ; [DPU_3_PIPE] |186| 
        ROR       A4, V6, #25           ; [DPU_3_PIPE] |186| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 189,column 9,is_stmt,isa 1
        EOR       V4, V3, V8            ; [DPU_3_PIPE] |189| 
        ROR       V6, V4, #16           ; [DPU_3_PIPE] |189| 
        ADD       V4, V6, V7            ; [DPU_3_PIPE] |189| 
        EOR       V5, V4, V5            ; [DPU_3_PIPE] |189| 
        ROR       V5, V5, #20           ; [DPU_3_PIPE] |189| 
        ADD       V7, V5, V3            ; [DPU_3_PIPE] |189| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        ADD       V3, A4, V7            ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 189,column 9,is_stmt,isa 1
        EOR       V7, V7, V6            ; [DPU_3_PIPE] |189| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        ADD       V6, LR, V2            ; [DPU_3_PIPE] |188| 
        EOR       V2, V6, A3            ; [DPU_3_PIPE] |188| 
        LDR       A3, [SP, #148]        ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 189,column 9,is_stmt,isa 1
        ROR       V7, V7, #24           ; [DPU_3_PIPE] |189| 
        ADD       V4, V7, V4            ; [DPU_3_PIPE] |189| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        ROR       V8, V2, #16           ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 189,column 9,is_stmt,isa 1
        EOR       V5, V4, V5            ; [DPU_3_PIPE] |189| 
        ROR       V5, V5, #25           ; [DPU_3_PIPE] |189| 
        STR       V5, [SP, #168]        ; [DPU_3_PIPE] |189| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        ADD       V5, V8, A3            ; [DPU_3_PIPE] |188| 
        LDR       A3, [SP, #168]        ; [DPU_3_PIPE] |188| 
        EOR       V2, V5, LR            ; [DPU_3_PIPE] |188| 
        ROR       V2, V2, #20           ; [DPU_3_PIPE] |188| 
        ADD       LR, V2, V6            ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 192,column 9,is_stmt,isa 1
        ADD       V6, A3, LR            ; [DPU_3_PIPE] |192| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        EOR       A3, LR, V8            ; [DPU_3_PIPE] |188| 
        LDR       V8, [SP, #156]        ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 192,column 9,is_stmt,isa 1
        STR       V6, [SP, #172]        ; [DPU_3_PIPE] |192| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        ROR       LR, A3, #24           ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        EOR       V6, V3, LR            ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 188,column 9,is_stmt,isa 1
        ADD       LR, LR, V5            ; [DPU_3_PIPE] |188| 
        EOR       V2, LR, V2            ; [DPU_3_PIPE] |188| 
        ROR       V5, V2, #25           ; [DPU_3_PIPE] |188| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 187,column 9,is_stmt,isa 1
        ADD       V2, V9, V8            ; [DPU_3_PIPE] |187| 
        EOR       V8, V2, A2            ; [DPU_3_PIPE] |187| 
        LDR       A2, [SP, #152]        ; [DPU_3_PIPE] |187| 
        ROR       A3, V8, #16           ; [DPU_3_PIPE] |187| 
        ADD       V8, A3, A2            ; [DPU_3_PIPE] |187| 
        EOR       V9, V8, V9            ; [DPU_3_PIPE] |187| 
        ROR       A2, V9, #20           ; [DPU_3_PIPE] |187| 
        ADD       V9, A2, V2            ; [DPU_3_PIPE] |187| 
        EOR       V2, V9, A3            ; [DPU_3_PIPE] |187| 
        ROR       V2, V2, #24           ; [DPU_3_PIPE] |187| 
        ADD       V8, V2, V8            ; [DPU_3_PIPE] |187| 
        EOR       A2, V8, A2            ; [DPU_3_PIPE] |187| 
        ROR       A2, A2, #25           ; [DPU_3_PIPE] |187| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 190,column 9,is_stmt,isa 1
        ADDS      V1, A2, V1            ; [DPU_3_PIPE] |190| 
        EOR       V7, V1, V7            ; [DPU_3_PIPE] |190| 
        ROR       V7, V7, #16           ; [DPU_3_PIPE] |190| 
        ADD       A3, V7, LR            ; [DPU_3_PIPE] |190| 
        EOR       LR, A3, A2            ; [DPU_3_PIPE] |190| 
        ROR       LR, LR, #20           ; [DPU_3_PIPE] |190| 
        ADD       V1, LR, V1            ; [DPU_3_PIPE] |190| 
        EOR       V7, V1, V7            ; [DPU_3_PIPE] |190| 
        ROR       V7, V7, #24           ; [DPU_3_PIPE] |190| 
        STR       V7, [SP, #144]        ; [DPU_3_PIPE] |190| 
        ADD       V7, V7, A3            ; [DPU_3_PIPE] |190| 
        STR       V7, [SP, #148]        ; [DPU_3_PIPE] |190| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 191,column 9,is_stmt,isa 1
        LDR       V7, [SP, #160]        ; [DPU_3_PIPE] |191| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        ROR       V6, V6, #16           ; [DPU_3_PIPE] |193| 
        ADD       A2, V6, V8            ; [DPU_3_PIPE] |193| 
        EOR       V8, A2, A4            ; [DPU_3_PIPE] |193| 
        ROR       A4, V8, #20           ; [DPU_3_PIPE] |193| 
        ADDS      V3, A4, V3            ; [DPU_3_PIPE] |193| 
        EOR       V6, V3, V6            ; [DPU_3_PIPE] |193| 
        ROR       A3, V6, #24           ; [DPU_3_PIPE] |193| 
        ADD       V6, A3, A2            ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 191,column 9,is_stmt,isa 1
        LDR       A2, [SP, #172]        ; [DPU_3_PIPE] |191| 
        ADD       V9, V5, V9            ; [DPU_3_PIPE] |191| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        STR       V6, [SP, #152]        ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 191,column 9,is_stmt,isa 1
        EOR       V6, V9, V7            ; [DPU_3_PIPE] |191| 
        ROR       V6, V6, #16           ; [DPU_3_PIPE] |191| 
        ADD       V4, V6, V4            ; [DPU_3_PIPE] |191| 
        EOR       V5, V4, V5            ; [DPU_3_PIPE] |191| 
        ROR       V5, V5, #20           ; [DPU_3_PIPE] |191| 
        ADD       V9, V5, V9            ; [DPU_3_PIPE] |191| 
        STR       V9, [SP, #156]        ; [DPU_3_PIPE] |191| 
        EOR       V9, V9, V6            ; [DPU_3_PIPE] |191| 
        ROR       V8, V9, #24           ; [DPU_3_PIPE] |191| 
        ADD       V7, V8, V4            ; [DPU_3_PIPE] |191| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 192,column 9,is_stmt,isa 1
        EOR       V4, A2, V2            ; [DPU_3_PIPE] |192| 
        LDR       A2, [SP, #164]        ; [DPU_3_PIPE] |192| 
        ROR       V6, V4, #16           ; [DPU_3_PIPE] |192| 
        LDR       V4, [SP, #168]        ; [DPU_3_PIPE] |192| 
        ADD       V9, V6, A2            ; [DPU_3_PIPE] |192| 
        LDR       A2, [SP, #172]        ; [DPU_3_PIPE] |192| 
        EOR       V2, V9, V4            ; [DPU_3_PIPE] |192| 
        ROR       V4, V2, #20           ; [DPU_3_PIPE] |192| 
        ADDS      V2, V4, A2            ; [DPU_3_PIPE] |192| 
        EOR       V6, V2, V6            ; [DPU_3_PIPE] |192| 
        ROR       A2, V6, #24           ; [DPU_3_PIPE] |192| 
        ADD       V6, A2, V9            ; [DPU_3_PIPE] |192| 
        LDR       V9, [SP, #148]        ; [DPU_3_PIPE] |192| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 190,column 9,is_stmt,isa 1
        EOR       V9, V9, LR            ; [DPU_3_PIPE] |190| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 191,column 9,is_stmt,isa 1
        EOR       LR, V7, V5            ; [DPU_3_PIPE] |191| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 192,column 9,is_stmt,isa 1
        EOR       V5, V6, V4            ; [DPU_3_PIPE] |192| 
        LDR       V4, [SP, #152]        ; [DPU_3_PIPE] |192| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        EORS      V4, V4, A4            ; [DPU_3_PIPE] |193| 
        LDR       A4, [SP, #140]        ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 190,column 9,is_stmt,isa 1
        ROR       V9, V9, #25           ; [DPU_3_PIPE] |190| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 191,column 9,is_stmt,isa 1
        ROR       LR, LR, #25           ; [DPU_3_PIPE] |191| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 192,column 9,is_stmt,isa 1
        ROR       V5, V5, #25           ; [DPU_3_PIPE] |192| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 193,column 9,is_stmt,isa 1
        ROR       V4, V4, #25           ; [DPU_3_PIPE] |193| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 185,column 24,is_stmt,isa 1
        SUBS      A4, A4, #2            ; [DPU_3_PIPE] |185| 
        STR       A4, [SP, #140]        ; [DPU_3_PIPE] |185| 
        BNE       ||$C$L11||            ; [DPU_3_PIPE] |185| 
        ; BRANCHCC OCCURS {||$C$L11||}   ; [] |185| 
;* --------------------------------------------------------------------------*
;** 197	-----------------------    x_0 += U$7;  // [5]
;* --------------------------------------------------------------------------*
;** 197	-----------------------    x_4 += U$11;  // [5]
;** 197	-----------------------    x_8 += U$15;  // [5]
;** 197	-----------------------    x_12 += U$19;  // [5]
;** 197	-----------------------    x_16 += U$23;  // [5]
;** 197	-----------------------    x_20 += U$27;  // [5]
;** 197	-----------------------    x_24 += U$31;  // [5]
;** 197	-----------------------    x_28 += U$35;  // [5]
;** 197	-----------------------    x_32 += U$39;  // [5]
;** 197	-----------------------    x_36 += U$43;  // [5]
;** 197	-----------------------    x_40 += U$47;  // [5]
;** 197	-----------------------    x_44 += U$51;  // [5]
;** 197	-----------------------    x_48 += U$55;  // [5]
;** 197	-----------------------    x_52 += U$59;  // [5]
;** 197	-----------------------    x_56 += U$63;  // [5]
;** 197	-----------------------    x_60 += U$67;  // [5]
;** 201	-----------------------    temp[0] = x_0;  // [5]
;** 201	-----------------------    temp[1] = x_4;  // [5]
;** 201	-----------------------    temp[2] = x_8;  // [5]
;** 201	-----------------------    temp[3] = x_12;  // [5]
;** 201	-----------------------    temp[4] = x_16;  // [5]
;** 201	-----------------------    temp[5] = x_20;  // [5]
;** 201	-----------------------    temp[6] = x_24;  // [5]
;** 201	-----------------------    temp[7] = x_28;  // [5]
;** 201	-----------------------    temp[8] = x_32;  // [5]
;** 201	-----------------------    temp[9] = x_36;  // [5]
;** 201	-----------------------    temp[10] = x_40;  // [5]
;** 201	-----------------------    temp[11] = x_44;  // [5]
;** 201	-----------------------    temp[12] = x_48;  // [5]
;** 201	-----------------------    temp[13] = x_52;  // [5]
;** 201	-----------------------    temp[14] = x_56;  // [5]
;** 201	-----------------------    temp[15] = x_60;  // [5]
;** 220	-----------------------    ++(*((unsigned *)ctx+48));
;** 221	-----------------------    if ( bytes > 64u ) goto g3;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 220,column 9,is_stmt,isa 1
        LDR       A4, [A1, #48]         ; [DPU_3_PIPE] |220| 
        STR       A4, [SP, #140]        ; [DPU_3_PIPE] |220| 
        LDR       A4, [SP, #64]         ; [DPU_3_PIPE] |220| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADDS      A4, A4, V1            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V1, [SP, #156]        ; [DPU_3_PIPE] |201| 
        STR       A4, [SP, #0]          ; [DPU_3_PIPE] |201| 
        LDR       A4, [SP, #68]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADDS      A4, A4, V1            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V1, [SP, #72]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADDS      V1, V1, V2            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V2, [SP, #76]         ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #8]          ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADDS      V1, V2, V3            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V3, [SP, #80]         ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #12]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADDS      V1, V3, V4            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V4, [SP, #84]         ; [DPU_3_PIPE] |201| 
        LDR       V3, [SP, #88]         ; [DPU_3_PIPE] |201| 
        STR       A4, [SP, #4]          ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 220,column 9,is_stmt,isa 1
        LDR       A4, [SP, #128]        ; [DPU_3_PIPE] |220| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V2, [SP, #152]        ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #16]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V4, V9            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V9, [SP, #92]         ; [DPU_3_PIPE] |201| 
        LDR       V4, [SP, #96]         ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #20]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V3, LR            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       LR, [SP, #100]        ; [DPU_3_PIPE] |201| 
        LDR       V3, [SP, #104]        ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #24]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V9, V5            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V9, [SP, #148]        ; [DPU_3_PIPE] |201| 
        LDR       V5, [SP, #108]        ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #28]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V4, V6            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V6, [SP, #112]        ; [DPU_3_PIPE] |201| 
        LDR       V4, [SP, #116]        ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #32]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, LR, V2            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       LR, [SP, #120]        ; [DPU_3_PIPE] |201| 
        LDR       V2, [SP, #140]        ; [DPU_3_PIPE] |201| 
        STR       V1, [SP, #36]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V3, V9            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        LDR       V3, [SP, #144]        ; [DPU_3_PIPE] |201| 
        LDR       V9, [SP, #124]        ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 221,column 9,is_stmt,isa 1
        CMP       A4, #64               ; [DPU_3_PIPE] |221| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #40]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V5, V7            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #44]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V6, V8            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #48]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V4, A2            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #52]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, LR, A3            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #56]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 197,column 9,is_stmt,isa 1
        ADD       V1, V9, V3            ; [DPU_3_PIPE] |197| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 201,column 9,is_stmt,isa 1
        STR       V1, [SP, #60]         ; [DPU_3_PIPE] |201| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 220,column 9,is_stmt,isa 1
        ADD       V1, V2, #1            ; [DPU_3_PIPE] |220| 
        STR       V1, [A1, #48]         ; [DPU_3_PIPE] |220| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 221,column 9,is_stmt,isa 1
        BHI       ||$C$L8||             ; [DPU_3_PIPE] |221| 
        ; BRANCHCC OCCURS {||$C$L8||}    ; [] |221| 
;* --------------------------------------------------------------------------*
;** 222	-----------------------    if ( !bytes ) goto g15;
;* --------------------------------------------------------------------------*
        MOV       A1, A4                ; [DPU_3_PIPE] 
        CBZ       A1, ||$C$L14||        ; [] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 222,column 25,is_stmt,isa 1
        ; BRANCHCC OCCURS {||$C$L14||}   ; [] |222| 
;* --------------------------------------------------------------------------*
;** 223	-----------------------    d$2 = bytes>>1u;
;** 222	-----------------------    i = 0u;
;** 223	-----------------------    if ( !(bytes>>1) ) goto g13;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 223,column 17,is_stmt,isa 1
        LSRS      V1, A1, #1            ; [DPU_3_PIPE] |223| 
        LSR       V9, A1, #1            ; [DPU_3_PIPE] |223| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 222,column 18,is_stmt,isa 1
        MOV       V4, #0                ; [DPU_3_PIPE] |222| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 223,column 17,is_stmt,isa 1
        BEQ       ||$C$L13||            ; [DPU_3_PIPE] |223| 
        ; BRANCHCC OCCURS {||$C$L13||}   ; [] |223| 
;* --------------------------------------------------------------------------*
;**  	-----------------------    U$234 = m;
;**  	-----------------------    U$239 = c;
;**  	-----------------------    U$236 = &((unsigned char *)temp)[0];
;**  	-----------------------    #pragma MUST_ITERATE(1, 32, 1)
;**  	-----------------------    // LOOP BELOW UNROLLED BY FACTOR(2)
;**  	-----------------------    #pragma LOOP_FLAGS(4102u)
        LDR       V1, [SP, #136]        ; [DPU_3_PIPE] 
        LDR       A1, [SP, #132]        ; [DPU_3_PIPE] 
        MOV       LR, SP                ; [DPU_3_PIPE] 
;* --------------------------------------------------------------------------*
;*   BEGIN LOOP ||$C$L12||
;*
;*   Loop source line                : 222
;*   Loop closing brace source line  : 224
;*   Loop Unroll Multiple            : 2x
;*   Known Minimum Trip Count        : 1
;*   Known Maximum Trip Count        : 32
;*   Known Max Trip Count Factor     : 1
;* --------------------------------------------------------------------------*
||$C$L12||:    
;**	-----------------------g12:
;** 223	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 223	-----------------------    *U$239++ = *U$234++^*U$236++;
;** 222	-----------------------    i += 2u;
;** 222	-----------------------    if ( --d$2 ) goto g12;
        LDRB      V3, [LR], #1          ; [DPU_3_PIPE] |223| 
        LDRB      V5, [V1], #1          ; [DPU_3_PIPE] |223| 
        LDRB      V2, [LR], #1          ; [DPU_3_PIPE] |223| 
        EOR       V3, V3, V5            ; [DPU_3_PIPE] |223| 
        STRB      V3, [A1], #1          ; [DPU_3_PIPE] |223| 
        LDRB      V3, [V1], #1          ; [DPU_3_PIPE] |223| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 222,column 25,is_stmt,isa 1
        SUBS      V9, V9, #1            ; [DPU_3_PIPE] |222| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 222,column 36,is_stmt,isa 1
        ADD       V4, V4, #2            ; [DPU_3_PIPE] |222| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 223,column 17,is_stmt,isa 1
        EOR       V2, V2, V3            ; [DPU_3_PIPE] |223| 
        STRB      V2, [A1], #1          ; [DPU_3_PIPE] |223| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 222,column 25,is_stmt,isa 1
        BNE       ||$C$L12||            ; [DPU_3_PIPE] |222| 
        ; BRANCHCC OCCURS {||$C$L12||}   ; [] |222| 
;* --------------------------------------------------------------------------*
||$C$L13||:    
;**	-----------------------g13:
;**  	-----------------------    if ( !(bytes&1u) ) goto g15;
        MOV       A1, A4                ; [DPU_3_PIPE] 
        LSRS      A1, A1, #1            ; [DPU_3_PIPE] 
        BCC       ||$C$L14||            ; [DPU_3_PIPE] 
        ; BRANCHCC OCCURS {||$C$L14||}   ; [] 
;* --------------------------------------------------------------------------*
; Peeled loop iterations for unrolled loop:
;** 223	-----------------------    c[i] = m[i]^((unsigned char *)temp)[i];
;**	-----------------------g15:
;**  	-----------------------    return;
        LDR       A1, [SP, #136]        ; [DPU_3_PIPE] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 223,column 17,is_stmt,isa 1
        LDRB      LR, [V4, +SP]         ; [DPU_3_PIPE] |223| 
        LDR       V9, [SP, #132]        ; [DPU_3_PIPE] |223| 
        LDRB      A2, [A1, +V4]         ; [DPU_3_PIPE] |223| 
        EOR       A1, LR, A2            ; [DPU_3_PIPE] |223| 
        STRB      A1, [V9, +V4]         ; [DPU_3_PIPE] |223| 
;* --------------------------------------------------------------------------*
||$C$L14||:    
        ADD       SP, SP, #180          ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 36
$C$DW$116	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$116, DW_AT_low_pc(0x00)
	.dwattr $C$DW$116, DW_AT_TI_return
        POP       {V1, V2, V3, V4, V5, V6, V7, V8, PC} ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 0
        ; BRANCH OCCURS                  ; [] 
	.dwattr $C$DW$32, DW_AT_TI_end_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$32, DW_AT_TI_end_line(0xea)
	.dwattr $C$DW$32, DW_AT_TI_end_column(0x01)
	.dwendentry
	.dwendtag $C$DW$32

	.sect	".text:Chacha_Process"
	.clink
	.thumbfunc Chacha_Process
	.thumb
	.global	Chacha_Process

$C$DW$117	.dwtag  DW_TAG_subprogram, DW_AT_name("Chacha_Process")
	.dwattr $C$DW$117, DW_AT_low_pc(Chacha_Process)
	.dwattr $C$DW$117, DW_AT_high_pc(0x00)
	.dwattr $C$DW$117, DW_AT_TI_symbol_name("Chacha_Process")
	.dwattr $C$DW$117, DW_AT_external
	.dwattr $C$DW$117, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$117, DW_AT_TI_begin_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$117, DW_AT_TI_begin_line(0xef)
	.dwattr $C$DW$117, DW_AT_TI_begin_column(0x05)
	.dwattr $C$DW$117, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$117, DW_AT_decl_line(0xef)
	.dwattr $C$DW$117, DW_AT_decl_column(0x05)
	.dwattr $C$DW$117, DW_AT_TI_max_frame_size(0x08)
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 240,column 1,is_stmt,address Chacha_Process,isa 1

	.dwfde $C$DW$CIE, Chacha_Process
$C$DW$118	.dwtag  DW_TAG_formal_parameter, DW_AT_name("ctx")
	.dwattr $C$DW$118, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$118, DW_AT_type(*$C$DW$T$507)
	.dwattr $C$DW$118, DW_AT_location[DW_OP_reg0]
$C$DW$119	.dwtag  DW_TAG_formal_parameter, DW_AT_name("output")
	.dwattr $C$DW$119, DW_AT_TI_symbol_name("output")
	.dwattr $C$DW$119, DW_AT_type(*$C$DW$T$637)
	.dwattr $C$DW$119, DW_AT_location[DW_OP_reg1]
$C$DW$120	.dwtag  DW_TAG_formal_parameter, DW_AT_name("input")
	.dwattr $C$DW$120, DW_AT_TI_symbol_name("input")
	.dwattr $C$DW$120, DW_AT_type(*$C$DW$T$636)
	.dwattr $C$DW$120, DW_AT_location[DW_OP_reg2]
$C$DW$121	.dwtag  DW_TAG_formal_parameter, DW_AT_name("msglen")
	.dwattr $C$DW$121, DW_AT_TI_symbol_name("msglen")
	.dwattr $C$DW$121, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$121, DW_AT_location[DW_OP_reg3]

;*****************************************************************************
;* FUNCTION NAME: Chacha_Process                                             *
;*                                                                           *
;*   Regs Modified     : A1,A2,A3,A4,V1,V9,SP,LR,SR,FPEXC,FPSCR              *
;*   Regs Used         : A1,A2,A3,A4,V1,V9,SP,LR,SR,FPEXC,FPSCR              *
;*   Local Frame Size  : 0 Args + 0 Auto + 8 Save = 8 byte                   *
;*****************************************************************************
Chacha_Process:
;* --------------------------------------------------------------------------*
;* A4    assigned to msglen
$C$DW$122	.dwtag  DW_TAG_variable, DW_AT_name("msglen")
	.dwattr $C$DW$122, DW_AT_TI_symbol_name("msglen")
	.dwattr $C$DW$122, DW_AT_type(*$C$DW$T$631)
	.dwattr $C$DW$122, DW_AT_location[DW_OP_reg3]
;* A2    assigned to input
$C$DW$123	.dwtag  DW_TAG_variable, DW_AT_name("input")
	.dwattr $C$DW$123, DW_AT_TI_symbol_name("input")
	.dwattr $C$DW$123, DW_AT_type(*$C$DW$T$802)
	.dwattr $C$DW$123, DW_AT_location[DW_OP_reg1]
;* A3    assigned to output
$C$DW$124	.dwtag  DW_TAG_variable, DW_AT_name("output")
	.dwattr $C$DW$124, DW_AT_TI_symbol_name("output")
	.dwattr $C$DW$124, DW_AT_type(*$C$DW$T$801)
	.dwattr $C$DW$124, DW_AT_location[DW_OP_reg2]
;* A1    assigned to ctx
$C$DW$125	.dwtag  DW_TAG_variable, DW_AT_name("ctx")
	.dwattr $C$DW$125, DW_AT_TI_symbol_name("ctx")
	.dwattr $C$DW$125, DW_AT_type(*$C$DW$T$508)
	.dwattr $C$DW$125, DW_AT_location[DW_OP_reg0]
	.dwcfi	cfa_offset, 0
;** 241	-----------------------    if ( ctx == NULL ) goto g3;
        PUSH      {V1, LR}              ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 8
	.dwcfi	save_reg_to_mem, 14, -4
	.dwcfi	save_reg_to_mem, 4, -8
        MOV       V1, A3                ; [DPU_3_PIPE] |240| 
        MOV       A3, A2                ; [DPU_3_PIPE] |240| 
        MOV       A2, V1                ; [DPU_3_PIPE] |240| 
        CBZ       A1, ||$C$L15||        ; [] 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 241,column 5,is_stmt,isa 1
        ; BRANCHCC OCCURS {||$C$L15||}   ; [] |241| 
;* --------------------------------------------------------------------------*
;** 244	-----------------------    Chacha_encrypt_bytes(ctx, input, output, msglen);
;** 246	-----------------------    return 0;
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 244,column 5,is_stmt,isa 1
$C$DW$126	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$126, DW_AT_low_pc(0x00)
	.dwattr $C$DW$126, DW_AT_name("Chacha_encrypt_bytes")
	.dwattr $C$DW$126, DW_AT_TI_call
        BL        Chacha_encrypt_bytes  ; [DPU_3_PIPE] |244| 
        ; CALL OCCURS {Chacha_encrypt_bytes }  ; [] |244| 
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 246,column 5,is_stmt,isa 1
        MOVS      A1, #0                ; [DPU_3_PIPE] |246| 
$C$DW$127	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$127, DW_AT_low_pc(0x00)
	.dwattr $C$DW$127, DW_AT_TI_return
        POP       {V1, PC}              ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 0
        ; BRANCH OCCURS                  ; [] 
	.dwcfi	restore_reg, 4
;* --------------------------------------------------------------------------*
||$C$L15||:    
;**	-----------------------g3:
;** 242	-----------------------    return (-173);
	.dwpsn	file "C:/cyassl/ctaocrypt/src/chacha.c",line 242,column 9,is_stmt,isa 1
        MVN       A1, #172              ; [DPU_3_PIPE] |242| 
;* --------------------------------------------------------------------------*
$C$DW$128	.dwtag  DW_TAG_TI_branch
	.dwattr $C$DW$128, DW_AT_low_pc(0x00)
	.dwattr $C$DW$128, DW_AT_TI_return
        POP       {V1, PC}              ; [DPU_3_PIPE] 
	.dwcfi	cfa_offset, 0
        ; BRANCH OCCURS                  ; [] 
	.dwattr $C$DW$117, DW_AT_TI_end_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$117, DW_AT_TI_end_line(0xf7)
	.dwattr $C$DW$117, DW_AT_TI_end_column(0x01)
	.dwendentry
	.dwendtag $C$DW$117

;; Inlined function references:
;; [  5] Chacha_wordtobyte
;*****************************************************************************
;* UNDEFINED EXTERNAL REFERENCES                                             *
;*****************************************************************************
	.global	memset
	.global	memcpy

;******************************************************************************
;* BUILD ATTRIBUTES                                                           *
;******************************************************************************
	.battr "aeabi", Tag_File, 1, Tag_ABI_PCS_wchar_t(2)
	.battr "aeabi", Tag_File, 1, Tag_ABI_FP_rounding(0)
	.battr "aeabi", Tag_File, 1, Tag_ABI_FP_denormal(0)
	.battr "aeabi", Tag_File, 1, Tag_ABI_FP_exceptions(0)
	.battr "aeabi", Tag_File, 1, Tag_ABI_FP_number_model(1)
	.battr "aeabi", Tag_File, 1, Tag_ABI_enum_size(1)
	.battr "aeabi", Tag_File, 1, Tag_ABI_optimization_goals(2)
	.battr "aeabi", Tag_File, 1, Tag_ABI_FP_optimization_goals(0)
	.battr "TI", Tag_File, 1, Tag_Bitfield_layout(2)
	.battr "TI", Tag_File, 1, Tag_FP_interface(1)

;******************************************************************************
;* TYPE INFORMATION                                                           *
;******************************************************************************

$C$DW$T$486	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$486, DW_AT_byte_size(0x01)
$C$DW$129	.dwtag  DW_TAG_enumerator, DW_AT_name("CYASSL_WORD_SIZE"), DW_AT_const_value(0x04)
	.dwattr $C$DW$129, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$129, DW_AT_decl_line(0x65)
	.dwattr $C$DW$129, DW_AT_decl_column(0x05)
$C$DW$130	.dwtag  DW_TAG_enumerator, DW_AT_name("CYASSL_BIT_SIZE"), DW_AT_const_value(0x08)
	.dwattr $C$DW$130, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$130, DW_AT_decl_line(0x66)
	.dwattr $C$DW$130, DW_AT_decl_column(0x05)
$C$DW$131	.dwtag  DW_TAG_enumerator, DW_AT_name("CYASSL_WORD_BITS"), DW_AT_const_value(0x20)
	.dwattr $C$DW$131, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$131, DW_AT_decl_line(0x67)
	.dwattr $C$DW$131, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$486

	.dwattr $C$DW$T$486, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$486, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$486, DW_AT_decl_column(0x06)

$C$DW$T$487	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$487, DW_AT_byte_size(0x01)
$C$DW$132	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CA"), DW_AT_const_value(0x01)
	.dwattr $C$DW$132, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$132, DW_AT_decl_line(0xe7)
	.dwattr $C$DW$132, DW_AT_decl_column(0x05)
$C$DW$133	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CERT"), DW_AT_const_value(0x02)
	.dwattr $C$DW$133, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$133, DW_AT_decl_line(0xe8)
	.dwattr $C$DW$133, DW_AT_decl_column(0x05)
$C$DW$134	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_KEY"), DW_AT_const_value(0x03)
	.dwattr $C$DW$134, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$134, DW_AT_decl_line(0xe9)
	.dwattr $C$DW$134, DW_AT_decl_column(0x05)
$C$DW$135	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_FILE"), DW_AT_const_value(0x04)
	.dwattr $C$DW$135, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$135, DW_AT_decl_line(0xea)
	.dwattr $C$DW$135, DW_AT_decl_column(0x05)
$C$DW$136	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SUBJECT_CN"), DW_AT_const_value(0x05)
	.dwattr $C$DW$136, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$136, DW_AT_decl_line(0xeb)
	.dwattr $C$DW$136, DW_AT_decl_column(0x05)
$C$DW$137	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_PUBLIC_KEY"), DW_AT_const_value(0x06)
	.dwattr $C$DW$137, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$137, DW_AT_decl_line(0xec)
	.dwattr $C$DW$137, DW_AT_decl_column(0x05)
$C$DW$138	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SIGNER"), DW_AT_const_value(0x07)
	.dwattr $C$DW$138, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$138, DW_AT_decl_line(0xed)
	.dwattr $C$DW$138, DW_AT_decl_column(0x05)
$C$DW$139	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_NONE"), DW_AT_const_value(0x08)
	.dwattr $C$DW$139, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$139, DW_AT_decl_line(0xee)
	.dwattr $C$DW$139, DW_AT_decl_column(0x05)
$C$DW$140	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_BIGINT"), DW_AT_const_value(0x09)
	.dwattr $C$DW$140, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$140, DW_AT_decl_line(0xef)
	.dwattr $C$DW$140, DW_AT_decl_column(0x05)
$C$DW$141	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_RSA"), DW_AT_const_value(0x0a)
	.dwattr $C$DW$141, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$141, DW_AT_decl_line(0xf0)
	.dwattr $C$DW$141, DW_AT_decl_column(0x05)
$C$DW$142	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_METHOD"), DW_AT_const_value(0x0b)
	.dwattr $C$DW$142, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$142, DW_AT_decl_line(0xf1)
	.dwattr $C$DW$142, DW_AT_decl_column(0x05)
$C$DW$143	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_OUT_BUFFER"), DW_AT_const_value(0x0c)
	.dwattr $C$DW$143, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$143, DW_AT_decl_line(0xf2)
	.dwattr $C$DW$143, DW_AT_decl_column(0x05)
$C$DW$144	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_IN_BUFFER"), DW_AT_const_value(0x0d)
	.dwattr $C$DW$144, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$144, DW_AT_decl_line(0xf3)
	.dwattr $C$DW$144, DW_AT_decl_column(0x05)
$C$DW$145	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_INFO"), DW_AT_const_value(0x0e)
	.dwattr $C$DW$145, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$145, DW_AT_decl_line(0xf4)
	.dwattr $C$DW$145, DW_AT_decl_column(0x05)
$C$DW$146	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_DH"), DW_AT_const_value(0x0f)
	.dwattr $C$DW$146, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$146, DW_AT_decl_line(0xf5)
	.dwattr $C$DW$146, DW_AT_decl_column(0x05)
$C$DW$147	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_DOMAIN"), DW_AT_const_value(0x10)
	.dwattr $C$DW$147, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$147, DW_AT_decl_line(0xf6)
	.dwattr $C$DW$147, DW_AT_decl_column(0x05)
$C$DW$148	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SSL"), DW_AT_const_value(0x11)
	.dwattr $C$DW$148, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$148, DW_AT_decl_line(0xf7)
	.dwattr $C$DW$148, DW_AT_decl_column(0x05)
$C$DW$149	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CTX"), DW_AT_const_value(0x12)
	.dwattr $C$DW$149, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$149, DW_AT_decl_line(0xf8)
	.dwattr $C$DW$149, DW_AT_decl_column(0x05)
$C$DW$150	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_WRITEV"), DW_AT_const_value(0x13)
	.dwattr $C$DW$150, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$150, DW_AT_decl_line(0xf9)
	.dwattr $C$DW$150, DW_AT_decl_column(0x05)
$C$DW$151	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_OPENSSL"), DW_AT_const_value(0x14)
	.dwattr $C$DW$151, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$151, DW_AT_decl_line(0xfa)
	.dwattr $C$DW$151, DW_AT_decl_column(0x05)
$C$DW$152	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_DSA"), DW_AT_const_value(0x15)
	.dwattr $C$DW$152, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$152, DW_AT_decl_line(0xfb)
	.dwattr $C$DW$152, DW_AT_decl_column(0x05)
$C$DW$153	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CRL"), DW_AT_const_value(0x16)
	.dwattr $C$DW$153, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$153, DW_AT_decl_line(0xfc)
	.dwattr $C$DW$153, DW_AT_decl_column(0x05)
$C$DW$154	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_REVOKED"), DW_AT_const_value(0x17)
	.dwattr $C$DW$154, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$154, DW_AT_decl_line(0xfd)
	.dwattr $C$DW$154, DW_AT_decl_column(0x05)
$C$DW$155	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CRL_ENTRY"), DW_AT_const_value(0x18)
	.dwattr $C$DW$155, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$155, DW_AT_decl_line(0xfe)
	.dwattr $C$DW$155, DW_AT_decl_column(0x05)
$C$DW$156	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CERT_MANAGER"), DW_AT_const_value(0x19)
	.dwattr $C$DW$156, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$156, DW_AT_decl_line(0xff)
	.dwattr $C$DW$156, DW_AT_decl_column(0x05)
$C$DW$157	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CRL_MONITOR"), DW_AT_const_value(0x1a)
	.dwattr $C$DW$157, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$157, DW_AT_decl_line(0x100)
	.dwattr $C$DW$157, DW_AT_decl_column(0x05)
$C$DW$158	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_OCSP_STATUS"), DW_AT_const_value(0x1b)
	.dwattr $C$DW$158, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$158, DW_AT_decl_line(0x101)
	.dwattr $C$DW$158, DW_AT_decl_column(0x05)
$C$DW$159	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_OCSP_ENTRY"), DW_AT_const_value(0x1c)
	.dwattr $C$DW$159, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$159, DW_AT_decl_line(0x102)
	.dwattr $C$DW$159, DW_AT_decl_column(0x05)
$C$DW$160	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_ALTNAME"), DW_AT_const_value(0x1d)
	.dwattr $C$DW$160, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$160, DW_AT_decl_line(0x103)
	.dwattr $C$DW$160, DW_AT_decl_column(0x05)
$C$DW$161	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SUITES"), DW_AT_const_value(0x1e)
	.dwattr $C$DW$161, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$161, DW_AT_decl_line(0x104)
	.dwattr $C$DW$161, DW_AT_decl_column(0x05)
$C$DW$162	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CIPHER"), DW_AT_const_value(0x1f)
	.dwattr $C$DW$162, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$162, DW_AT_decl_line(0x105)
	.dwattr $C$DW$162, DW_AT_decl_column(0x05)
$C$DW$163	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_RNG"), DW_AT_const_value(0x20)
	.dwattr $C$DW$163, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$163, DW_AT_decl_line(0x106)
	.dwattr $C$DW$163, DW_AT_decl_column(0x05)
$C$DW$164	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_ARRAYS"), DW_AT_const_value(0x21)
	.dwattr $C$DW$164, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$164, DW_AT_decl_line(0x107)
	.dwattr $C$DW$164, DW_AT_decl_column(0x05)
$C$DW$165	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_DTLS_POOL"), DW_AT_const_value(0x22)
	.dwattr $C$DW$165, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$165, DW_AT_decl_line(0x108)
	.dwattr $C$DW$165, DW_AT_decl_column(0x05)
$C$DW$166	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SOCKADDR"), DW_AT_const_value(0x23)
	.dwattr $C$DW$166, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$166, DW_AT_decl_line(0x109)
	.dwattr $C$DW$166, DW_AT_decl_column(0x05)
$C$DW$167	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_LIBZ"), DW_AT_const_value(0x24)
	.dwattr $C$DW$167, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$167, DW_AT_decl_line(0x10a)
	.dwattr $C$DW$167, DW_AT_decl_column(0x05)
$C$DW$168	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_ECC"), DW_AT_const_value(0x25)
	.dwattr $C$DW$168, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$168, DW_AT_decl_line(0x10b)
	.dwattr $C$DW$168, DW_AT_decl_column(0x05)
$C$DW$169	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_TMP_BUFFER"), DW_AT_const_value(0x26)
	.dwattr $C$DW$169, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$169, DW_AT_decl_line(0x10c)
	.dwattr $C$DW$169, DW_AT_decl_column(0x05)
$C$DW$170	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_DTLS_MSG"), DW_AT_const_value(0x27)
	.dwattr $C$DW$170, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$170, DW_AT_decl_line(0x10d)
	.dwattr $C$DW$170, DW_AT_decl_column(0x05)
$C$DW$171	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CAVIUM_TMP"), DW_AT_const_value(0x28)
	.dwattr $C$DW$171, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$171, DW_AT_decl_line(0x10e)
	.dwattr $C$DW$171, DW_AT_decl_column(0x05)
$C$DW$172	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_CAVIUM_RSA"), DW_AT_const_value(0x29)
	.dwattr $C$DW$172, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$172, DW_AT_decl_line(0x10f)
	.dwattr $C$DW$172, DW_AT_decl_column(0x05)
$C$DW$173	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_X509"), DW_AT_const_value(0x2a)
	.dwattr $C$DW$173, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$173, DW_AT_decl_line(0x110)
	.dwattr $C$DW$173, DW_AT_decl_column(0x05)
$C$DW$174	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_TLSX"), DW_AT_const_value(0x2b)
	.dwattr $C$DW$174, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$174, DW_AT_decl_line(0x111)
	.dwattr $C$DW$174, DW_AT_decl_column(0x05)
$C$DW$175	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_OCSP"), DW_AT_const_value(0x2c)
	.dwattr $C$DW$175, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$175, DW_AT_decl_line(0x112)
	.dwattr $C$DW$175, DW_AT_decl_column(0x05)
$C$DW$176	.dwtag  DW_TAG_enumerator, DW_AT_name("DYNAMIC_TYPE_SIGNATURE"), DW_AT_const_value(0x2d)
	.dwattr $C$DW$176, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$176, DW_AT_decl_line(0x113)
	.dwattr $C$DW$176, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$487

	.dwattr $C$DW$T$487, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$487, DW_AT_decl_line(0xe6)
	.dwattr $C$DW$T$487, DW_AT_decl_column(0x06)

$C$DW$T$488	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$488, DW_AT_byte_size(0x01)
$C$DW$177	.dwtag  DW_TAG_enumerator, DW_AT_name("CYASSL_MAX_ERROR_SZ"), DW_AT_const_value(0x50)
	.dwattr $C$DW$177, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$177, DW_AT_decl_line(0x118)
	.dwattr $C$DW$177, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$488

	.dwattr $C$DW$T$488, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$488, DW_AT_decl_line(0x117)
	.dwattr $C$DW$T$488, DW_AT_decl_column(0x06)

$C$DW$T$489	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$489, DW_AT_byte_size(0x01)
$C$DW$178	.dwtag  DW_TAG_enumerator, DW_AT_name("MIN_STACK_BUFFER"), DW_AT_const_value(0x08)
	.dwattr $C$DW$178, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$178, DW_AT_decl_line(0x11d)
	.dwattr $C$DW$178, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$489

	.dwattr $C$DW$T$489, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$489, DW_AT_decl_line(0x11c)
	.dwattr $C$DW$T$489, DW_AT_decl_column(0x06)

$C$DW$T$490	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$490, DW_AT_byte_size(0x01)
$C$DW$179	.dwtag  DW_TAG_enumerator, DW_AT_name("CTC_SETTINGS"), DW_AT_const_value(0x20)
	.dwattr $C$DW$179, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$179, DW_AT_decl_line(0x131)
	.dwattr $C$DW$179, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$490

	.dwattr $C$DW$T$490, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$490, DW_AT_decl_line(0x123)
	.dwattr $C$DW$T$490, DW_AT_decl_column(0x06)

$C$DW$T$491	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$491, DW_AT_byte_size(0x01)
$C$DW$180	.dwtag  DW_TAG_enumerator, DW_AT_name("CHACHA_ENC_TYPE"), DW_AT_const_value(0x07)
	.dwattr $C$DW$180, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/chacha.h")
	.dwattr $C$DW$180, DW_AT_decl_line(0x21)
	.dwattr $C$DW$180, DW_AT_decl_column(0x02)
	.dwendtag $C$DW$T$491

	.dwattr $C$DW$T$491, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/chacha.h")
	.dwattr $C$DW$T$491, DW_AT_decl_line(0x20)
	.dwattr $C$DW$T$491, DW_AT_decl_column(0x06)

$C$DW$T$492	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$492, DW_AT_byte_size(0x02)
$C$DW$181	.dwtag  DW_TAG_enumerator, DW_AT_name("MAX_CODE_E"), DW_AT_const_value(-100)
	.dwattr $C$DW$181, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$181, DW_AT_decl_line(0x24)
	.dwattr $C$DW$181, DW_AT_decl_column(0x05)
$C$DW$182	.dwtag  DW_TAG_enumerator, DW_AT_name("OPEN_RAN_E"), DW_AT_const_value(-101)
	.dwattr $C$DW$182, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$182, DW_AT_decl_line(0x25)
	.dwattr $C$DW$182, DW_AT_decl_column(0x05)
$C$DW$183	.dwtag  DW_TAG_enumerator, DW_AT_name("READ_RAN_E"), DW_AT_const_value(-102)
	.dwattr $C$DW$183, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$183, DW_AT_decl_line(0x26)
	.dwattr $C$DW$183, DW_AT_decl_column(0x05)
$C$DW$184	.dwtag  DW_TAG_enumerator, DW_AT_name("WINCRYPT_E"), DW_AT_const_value(-103)
	.dwattr $C$DW$184, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$184, DW_AT_decl_line(0x27)
	.dwattr $C$DW$184, DW_AT_decl_column(0x05)
$C$DW$185	.dwtag  DW_TAG_enumerator, DW_AT_name("CRYPTGEN_E"), DW_AT_const_value(-104)
	.dwattr $C$DW$185, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$185, DW_AT_decl_line(0x28)
	.dwattr $C$DW$185, DW_AT_decl_column(0x05)
$C$DW$186	.dwtag  DW_TAG_enumerator, DW_AT_name("RAN_BLOCK_E"), DW_AT_const_value(-105)
	.dwattr $C$DW$186, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$186, DW_AT_decl_line(0x29)
	.dwattr $C$DW$186, DW_AT_decl_column(0x05)
$C$DW$187	.dwtag  DW_TAG_enumerator, DW_AT_name("BAD_MUTEX_E"), DW_AT_const_value(-106)
	.dwattr $C$DW$187, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$187, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$187, DW_AT_decl_column(0x05)
$C$DW$188	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_INIT_E"), DW_AT_const_value(-110)
	.dwattr $C$DW$188, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$188, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$188, DW_AT_decl_column(0x05)
$C$DW$189	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_READ_E"), DW_AT_const_value(-111)
	.dwattr $C$DW$189, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$189, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$189, DW_AT_decl_column(0x05)
$C$DW$190	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_EXPTMOD_E"), DW_AT_const_value(-112)
	.dwattr $C$DW$190, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$190, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$190, DW_AT_decl_column(0x05)
$C$DW$191	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_TO_E"), DW_AT_const_value(-113)
	.dwattr $C$DW$191, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$191, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$191, DW_AT_decl_column(0x05)
$C$DW$192	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_SUB_E"), DW_AT_const_value(-114)
	.dwattr $C$DW$192, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$192, DW_AT_decl_line(0x30)
	.dwattr $C$DW$192, DW_AT_decl_column(0x05)
$C$DW$193	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_ADD_E"), DW_AT_const_value(-115)
	.dwattr $C$DW$193, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$193, DW_AT_decl_line(0x31)
	.dwattr $C$DW$193, DW_AT_decl_column(0x05)
$C$DW$194	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_MUL_E"), DW_AT_const_value(-116)
	.dwattr $C$DW$194, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$194, DW_AT_decl_line(0x32)
	.dwattr $C$DW$194, DW_AT_decl_column(0x05)
$C$DW$195	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_MULMOD_E"), DW_AT_const_value(-117)
	.dwattr $C$DW$195, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$195, DW_AT_decl_line(0x33)
	.dwattr $C$DW$195, DW_AT_decl_column(0x05)
$C$DW$196	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_MOD_E"), DW_AT_const_value(-118)
	.dwattr $C$DW$196, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$196, DW_AT_decl_line(0x34)
	.dwattr $C$DW$196, DW_AT_decl_column(0x05)
$C$DW$197	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_INVMOD_E"), DW_AT_const_value(-119)
	.dwattr $C$DW$197, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$197, DW_AT_decl_line(0x35)
	.dwattr $C$DW$197, DW_AT_decl_column(0x05)
$C$DW$198	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_CMP_E"), DW_AT_const_value(-120)
	.dwattr $C$DW$198, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$198, DW_AT_decl_line(0x36)
	.dwattr $C$DW$198, DW_AT_decl_column(0x05)
$C$DW$199	.dwtag  DW_TAG_enumerator, DW_AT_name("MP_ZERO_E"), DW_AT_const_value(-121)
	.dwattr $C$DW$199, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$199, DW_AT_decl_line(0x37)
	.dwattr $C$DW$199, DW_AT_decl_column(0x05)
$C$DW$200	.dwtag  DW_TAG_enumerator, DW_AT_name("MEMORY_E"), DW_AT_const_value(-125)
	.dwattr $C$DW$200, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$200, DW_AT_decl_line(0x39)
	.dwattr $C$DW$200, DW_AT_decl_column(0x05)
$C$DW$201	.dwtag  DW_TAG_enumerator, DW_AT_name("RSA_WRONG_TYPE_E"), DW_AT_const_value(-130)
	.dwattr $C$DW$201, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$201, DW_AT_decl_line(0x3b)
	.dwattr $C$DW$201, DW_AT_decl_column(0x05)
$C$DW$202	.dwtag  DW_TAG_enumerator, DW_AT_name("RSA_BUFFER_E"), DW_AT_const_value(-131)
	.dwattr $C$DW$202, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$202, DW_AT_decl_line(0x3c)
	.dwattr $C$DW$202, DW_AT_decl_column(0x05)
$C$DW$203	.dwtag  DW_TAG_enumerator, DW_AT_name("BUFFER_E"), DW_AT_const_value(-132)
	.dwattr $C$DW$203, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$203, DW_AT_decl_line(0x3e)
	.dwattr $C$DW$203, DW_AT_decl_column(0x05)
$C$DW$204	.dwtag  DW_TAG_enumerator, DW_AT_name("ALGO_ID_E"), DW_AT_const_value(-133)
	.dwattr $C$DW$204, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$204, DW_AT_decl_line(0x3f)
	.dwattr $C$DW$204, DW_AT_decl_column(0x05)
$C$DW$205	.dwtag  DW_TAG_enumerator, DW_AT_name("PUBLIC_KEY_E"), DW_AT_const_value(-134)
	.dwattr $C$DW$205, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$205, DW_AT_decl_line(0x40)
	.dwattr $C$DW$205, DW_AT_decl_column(0x05)
$C$DW$206	.dwtag  DW_TAG_enumerator, DW_AT_name("DATE_E"), DW_AT_const_value(-135)
	.dwattr $C$DW$206, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$206, DW_AT_decl_line(0x41)
	.dwattr $C$DW$206, DW_AT_decl_column(0x05)
$C$DW$207	.dwtag  DW_TAG_enumerator, DW_AT_name("SUBJECT_E"), DW_AT_const_value(-136)
	.dwattr $C$DW$207, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$207, DW_AT_decl_line(0x42)
	.dwattr $C$DW$207, DW_AT_decl_column(0x05)
$C$DW$208	.dwtag  DW_TAG_enumerator, DW_AT_name("ISSUER_E"), DW_AT_const_value(-137)
	.dwattr $C$DW$208, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$208, DW_AT_decl_line(0x43)
	.dwattr $C$DW$208, DW_AT_decl_column(0x05)
$C$DW$209	.dwtag  DW_TAG_enumerator, DW_AT_name("CA_TRUE_E"), DW_AT_const_value(-138)
	.dwattr $C$DW$209, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$209, DW_AT_decl_line(0x44)
	.dwattr $C$DW$209, DW_AT_decl_column(0x05)
$C$DW$210	.dwtag  DW_TAG_enumerator, DW_AT_name("EXTENSIONS_E"), DW_AT_const_value(-139)
	.dwattr $C$DW$210, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$210, DW_AT_decl_line(0x45)
	.dwattr $C$DW$210, DW_AT_decl_column(0x05)
$C$DW$211	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_PARSE_E"), DW_AT_const_value(-140)
	.dwattr $C$DW$211, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$211, DW_AT_decl_line(0x47)
	.dwattr $C$DW$211, DW_AT_decl_column(0x05)
$C$DW$212	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_VERSION_E"), DW_AT_const_value(-141)
	.dwattr $C$DW$212, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$212, DW_AT_decl_line(0x48)
	.dwattr $C$DW$212, DW_AT_decl_column(0x05)
$C$DW$213	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_GETINT_E"), DW_AT_const_value(-142)
	.dwattr $C$DW$213, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$213, DW_AT_decl_line(0x49)
	.dwattr $C$DW$213, DW_AT_decl_column(0x05)
$C$DW$214	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_RSA_KEY_E"), DW_AT_const_value(-143)
	.dwattr $C$DW$214, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$214, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$214, DW_AT_decl_column(0x05)
$C$DW$215	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_OBJECT_ID_E"), DW_AT_const_value(-144)
	.dwattr $C$DW$215, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$215, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$215, DW_AT_decl_column(0x05)
$C$DW$216	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_TAG_NULL_E"), DW_AT_const_value(-145)
	.dwattr $C$DW$216, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$216, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$216, DW_AT_decl_column(0x05)
$C$DW$217	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_EXPECT_0_E"), DW_AT_const_value(-146)
	.dwattr $C$DW$217, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$217, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$217, DW_AT_decl_column(0x05)
$C$DW$218	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_BITSTR_E"), DW_AT_const_value(-147)
	.dwattr $C$DW$218, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$218, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$218, DW_AT_decl_column(0x05)
$C$DW$219	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_UNKNOWN_OID_E"), DW_AT_const_value(-148)
	.dwattr $C$DW$219, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$219, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$219, DW_AT_decl_column(0x05)
$C$DW$220	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_DATE_SZ_E"), DW_AT_const_value(-149)
	.dwattr $C$DW$220, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$220, DW_AT_decl_line(0x50)
	.dwattr $C$DW$220, DW_AT_decl_column(0x05)
$C$DW$221	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_BEFORE_DATE_E"), DW_AT_const_value(-150)
	.dwattr $C$DW$221, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$221, DW_AT_decl_line(0x51)
	.dwattr $C$DW$221, DW_AT_decl_column(0x05)
$C$DW$222	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_AFTER_DATE_E"), DW_AT_const_value(-151)
	.dwattr $C$DW$222, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$222, DW_AT_decl_line(0x52)
	.dwattr $C$DW$222, DW_AT_decl_column(0x05)
$C$DW$223	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_SIG_OID_E"), DW_AT_const_value(-152)
	.dwattr $C$DW$223, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$223, DW_AT_decl_line(0x53)
	.dwattr $C$DW$223, DW_AT_decl_column(0x05)
$C$DW$224	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_TIME_E"), DW_AT_const_value(-153)
	.dwattr $C$DW$224, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$224, DW_AT_decl_line(0x54)
	.dwattr $C$DW$224, DW_AT_decl_column(0x05)
$C$DW$225	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_INPUT_E"), DW_AT_const_value(-154)
	.dwattr $C$DW$225, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$225, DW_AT_decl_line(0x55)
	.dwattr $C$DW$225, DW_AT_decl_column(0x05)
$C$DW$226	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_SIG_CONFIRM_E"), DW_AT_const_value(-155)
	.dwattr $C$DW$226, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$226, DW_AT_decl_line(0x56)
	.dwattr $C$DW$226, DW_AT_decl_column(0x05)
$C$DW$227	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_SIG_HASH_E"), DW_AT_const_value(-156)
	.dwattr $C$DW$227, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$227, DW_AT_decl_line(0x57)
	.dwattr $C$DW$227, DW_AT_decl_column(0x05)
$C$DW$228	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_SIG_KEY_E"), DW_AT_const_value(-157)
	.dwattr $C$DW$228, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$228, DW_AT_decl_line(0x58)
	.dwattr $C$DW$228, DW_AT_decl_column(0x05)
$C$DW$229	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_DH_KEY_E"), DW_AT_const_value(-158)
	.dwattr $C$DW$229, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$229, DW_AT_decl_line(0x59)
	.dwattr $C$DW$229, DW_AT_decl_column(0x05)
$C$DW$230	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_NTRU_KEY_E"), DW_AT_const_value(-159)
	.dwattr $C$DW$230, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$230, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$230, DW_AT_decl_column(0x05)
$C$DW$231	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_CRIT_EXT_E"), DW_AT_const_value(-160)
	.dwattr $C$DW$231, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$231, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$231, DW_AT_decl_column(0x05)
$C$DW$232	.dwtag  DW_TAG_enumerator, DW_AT_name("ECC_BAD_ARG_E"), DW_AT_const_value(-170)
	.dwattr $C$DW$232, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$232, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$232, DW_AT_decl_column(0x05)
$C$DW$233	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_ECC_KEY_E"), DW_AT_const_value(-171)
	.dwattr $C$DW$233, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$233, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$233, DW_AT_decl_column(0x05)
$C$DW$234	.dwtag  DW_TAG_enumerator, DW_AT_name("ECC_CURVE_OID_E"), DW_AT_const_value(-172)
	.dwattr $C$DW$234, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$234, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$234, DW_AT_decl_column(0x05)
$C$DW$235	.dwtag  DW_TAG_enumerator, DW_AT_name("BAD_FUNC_ARG"), DW_AT_const_value(-173)
	.dwattr $C$DW$235, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$235, DW_AT_decl_line(0x60)
	.dwattr $C$DW$235, DW_AT_decl_column(0x05)
$C$DW$236	.dwtag  DW_TAG_enumerator, DW_AT_name("NOT_COMPILED_IN"), DW_AT_const_value(-174)
	.dwattr $C$DW$236, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$236, DW_AT_decl_line(0x61)
	.dwattr $C$DW$236, DW_AT_decl_column(0x05)
$C$DW$237	.dwtag  DW_TAG_enumerator, DW_AT_name("UNICODE_SIZE_E"), DW_AT_const_value(-175)
	.dwattr $C$DW$237, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$237, DW_AT_decl_line(0x62)
	.dwattr $C$DW$237, DW_AT_decl_column(0x05)
$C$DW$238	.dwtag  DW_TAG_enumerator, DW_AT_name("NO_PASSWORD"), DW_AT_const_value(-176)
	.dwattr $C$DW$238, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$238, DW_AT_decl_line(0x63)
	.dwattr $C$DW$238, DW_AT_decl_column(0x05)
$C$DW$239	.dwtag  DW_TAG_enumerator, DW_AT_name("ALT_NAME_E"), DW_AT_const_value(-177)
	.dwattr $C$DW$239, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$239, DW_AT_decl_line(0x64)
	.dwattr $C$DW$239, DW_AT_decl_column(0x05)
$C$DW$240	.dwtag  DW_TAG_enumerator, DW_AT_name("AES_GCM_AUTH_E"), DW_AT_const_value(-180)
	.dwattr $C$DW$240, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$240, DW_AT_decl_line(0x66)
	.dwattr $C$DW$240, DW_AT_decl_column(0x05)
$C$DW$241	.dwtag  DW_TAG_enumerator, DW_AT_name("AES_CCM_AUTH_E"), DW_AT_const_value(-181)
	.dwattr $C$DW$241, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$241, DW_AT_decl_line(0x67)
	.dwattr $C$DW$241, DW_AT_decl_column(0x05)
$C$DW$242	.dwtag  DW_TAG_enumerator, DW_AT_name("CAVIUM_INIT_E"), DW_AT_const_value(-182)
	.dwattr $C$DW$242, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$242, DW_AT_decl_line(0x69)
	.dwattr $C$DW$242, DW_AT_decl_column(0x05)
$C$DW$243	.dwtag  DW_TAG_enumerator, DW_AT_name("COMPRESS_INIT_E"), DW_AT_const_value(-183)
	.dwattr $C$DW$243, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$243, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$243, DW_AT_decl_column(0x05)
$C$DW$244	.dwtag  DW_TAG_enumerator, DW_AT_name("COMPRESS_E"), DW_AT_const_value(-184)
	.dwattr $C$DW$244, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$244, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$244, DW_AT_decl_column(0x05)
$C$DW$245	.dwtag  DW_TAG_enumerator, DW_AT_name("DECOMPRESS_INIT_E"), DW_AT_const_value(-185)
	.dwattr $C$DW$245, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$245, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$245, DW_AT_decl_column(0x05)
$C$DW$246	.dwtag  DW_TAG_enumerator, DW_AT_name("DECOMPRESS_E"), DW_AT_const_value(-186)
	.dwattr $C$DW$246, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$246, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$246, DW_AT_decl_column(0x05)
$C$DW$247	.dwtag  DW_TAG_enumerator, DW_AT_name("BAD_ALIGN_E"), DW_AT_const_value(-187)
	.dwattr $C$DW$247, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$247, DW_AT_decl_line(0x70)
	.dwattr $C$DW$247, DW_AT_decl_column(0x05)
$C$DW$248	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_NO_SIGNER_E"), DW_AT_const_value(-188)
	.dwattr $C$DW$248, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$248, DW_AT_decl_line(0x71)
	.dwattr $C$DW$248, DW_AT_decl_column(0x05)
$C$DW$249	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_CRL_CONFIRM_E"), DW_AT_const_value(-189)
	.dwattr $C$DW$249, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$249, DW_AT_decl_line(0x72)
	.dwattr $C$DW$249, DW_AT_decl_column(0x05)
$C$DW$250	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_CRL_NO_SIGNER_E"), DW_AT_const_value(-190)
	.dwattr $C$DW$250, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$250, DW_AT_decl_line(0x73)
	.dwattr $C$DW$250, DW_AT_decl_column(0x05)
$C$DW$251	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_OCSP_CONFIRM_E"), DW_AT_const_value(-191)
	.dwattr $C$DW$251, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$251, DW_AT_decl_line(0x74)
	.dwattr $C$DW$251, DW_AT_decl_column(0x05)
$C$DW$252	.dwtag  DW_TAG_enumerator, DW_AT_name("BAD_ENC_STATE_E"), DW_AT_const_value(-192)
	.dwattr $C$DW$252, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$252, DW_AT_decl_line(0x76)
	.dwattr $C$DW$252, DW_AT_decl_column(0x05)
$C$DW$253	.dwtag  DW_TAG_enumerator, DW_AT_name("BAD_PADDING_E"), DW_AT_const_value(-193)
	.dwattr $C$DW$253, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$253, DW_AT_decl_line(0x77)
	.dwattr $C$DW$253, DW_AT_decl_column(0x05)
$C$DW$254	.dwtag  DW_TAG_enumerator, DW_AT_name("REQ_ATTRIBUTE_E"), DW_AT_const_value(-194)
	.dwattr $C$DW$254, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$254, DW_AT_decl_line(0x79)
	.dwattr $C$DW$254, DW_AT_decl_column(0x05)
$C$DW$255	.dwtag  DW_TAG_enumerator, DW_AT_name("PKCS7_OID_E"), DW_AT_const_value(-195)
	.dwattr $C$DW$255, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$255, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$255, DW_AT_decl_column(0x05)
$C$DW$256	.dwtag  DW_TAG_enumerator, DW_AT_name("PKCS7_RECIP_E"), DW_AT_const_value(-196)
	.dwattr $C$DW$256, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$256, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$256, DW_AT_decl_column(0x05)
$C$DW$257	.dwtag  DW_TAG_enumerator, DW_AT_name("FIPS_NOT_ALLOWED_E"), DW_AT_const_value(-197)
	.dwattr $C$DW$257, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$257, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$257, DW_AT_decl_column(0x05)
$C$DW$258	.dwtag  DW_TAG_enumerator, DW_AT_name("ASN_NAME_INVALID_E"), DW_AT_const_value(-198)
	.dwattr $C$DW$258, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$258, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$258, DW_AT_decl_column(0x05)
$C$DW$259	.dwtag  DW_TAG_enumerator, DW_AT_name("RNG_FAILURE_E"), DW_AT_const_value(-199)
	.dwattr $C$DW$259, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$259, DW_AT_decl_line(0x80)
	.dwattr $C$DW$259, DW_AT_decl_column(0x05)
$C$DW$260	.dwtag  DW_TAG_enumerator, DW_AT_name("HMAC_MIN_KEYLEN_E"), DW_AT_const_value(-200)
	.dwattr $C$DW$260, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$260, DW_AT_decl_line(0x81)
	.dwattr $C$DW$260, DW_AT_decl_column(0x05)
$C$DW$261	.dwtag  DW_TAG_enumerator, DW_AT_name("RSA_PAD_E"), DW_AT_const_value(-201)
	.dwattr $C$DW$261, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$261, DW_AT_decl_line(0x82)
	.dwattr $C$DW$261, DW_AT_decl_column(0x05)
$C$DW$262	.dwtag  DW_TAG_enumerator, DW_AT_name("MIN_CODE_E"), DW_AT_const_value(-300)
	.dwattr $C$DW$262, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$262, DW_AT_decl_line(0x84)
	.dwattr $C$DW$262, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$492

	.dwattr $C$DW$T$492, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/error-crypt.h")
	.dwattr $C$DW$T$492, DW_AT_decl_line(0x23)
	.dwattr $C$DW$T$492, DW_AT_decl_column(0x06)

$C$DW$T$124	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$124, DW_AT_byte_size(0x08)
$C$DW$263	.dwtag  DW_TAG_member
	.dwattr $C$DW$263, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$263, DW_AT_name("length")
	.dwattr $C$DW$263, DW_AT_TI_symbol_name("length")
	.dwattr $C$DW$263, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$263, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$263, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$263, DW_AT_decl_line(0xe2)
	.dwattr $C$DW$263, DW_AT_decl_column(0x16)
$C$DW$264	.dwtag  DW_TAG_member
	.dwattr $C$DW$264, DW_AT_type(*$C$DW$T$123)
	.dwattr $C$DW$264, DW_AT_name("elem")
	.dwattr $C$DW$264, DW_AT_TI_symbol_name("elem")
	.dwattr $C$DW$264, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$264, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$264, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$264, DW_AT_decl_line(0xe2)
	.dwattr $C$DW$264, DW_AT_decl_column(0x3a)
	.dwendtag $C$DW$T$124

	.dwattr $C$DW$T$124, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$124, DW_AT_decl_line(0xe2)
	.dwattr $C$DW$T$124, DW_AT_decl_column(0x10)
$C$DW$T$493	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Swi_hooks")
	.dwattr $C$DW$T$493, DW_AT_type(*$C$DW$T$124)
	.dwattr $C$DW$T$493, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$493, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$493, DW_AT_decl_line(0xe2)
	.dwattr $C$DW$T$493, DW_AT_decl_column(0x42)
$C$DW$T$494	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Swi_hooks")
	.dwattr $C$DW$T$494, DW_AT_type(*$C$DW$T$493)
	.dwattr $C$DW$T$494, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$494, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$494, DW_AT_decl_line(0xe3)
	.dwattr $C$DW$T$494, DW_AT_decl_column(0x2b)
$C$DW$T$495	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_hooks")
	.dwattr $C$DW$T$495, DW_AT_type(*$C$DW$T$494)
	.dwattr $C$DW$T$495, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$495, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$495, DW_AT_decl_line(0xe4)
	.dwattr $C$DW$T$495, DW_AT_decl_column(0x27)

$C$DW$T$127	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$127, DW_AT_byte_size(0x08)
$C$DW$265	.dwtag  DW_TAG_member
	.dwattr $C$DW$265, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$265, DW_AT_name("length")
	.dwattr $C$DW$265, DW_AT_TI_symbol_name("length")
	.dwattr $C$DW$265, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$265, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$265, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$265, DW_AT_decl_line(0x19f)
	.dwattr $C$DW$265, DW_AT_decl_column(0x16)
$C$DW$266	.dwtag  DW_TAG_member
	.dwattr $C$DW$266, DW_AT_type(*$C$DW$T$126)
	.dwattr $C$DW$266, DW_AT_name("elem")
	.dwattr $C$DW$266, DW_AT_TI_symbol_name("elem")
	.dwattr $C$DW$266, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$266, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$266, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$266, DW_AT_decl_line(0x19f)
	.dwattr $C$DW$266, DW_AT_decl_column(0x3b)
	.dwendtag $C$DW$T$127

	.dwattr $C$DW$T$127, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$127, DW_AT_decl_line(0x19f)
	.dwattr $C$DW$T$127, DW_AT_decl_column(0x10)
$C$DW$T$496	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_hooks")
	.dwattr $C$DW$T$496, DW_AT_type(*$C$DW$T$127)
	.dwattr $C$DW$T$496, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$496, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$496, DW_AT_decl_line(0x19f)
	.dwattr $C$DW$T$496, DW_AT_decl_column(0x43)
$C$DW$T$497	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_hooks")
	.dwattr $C$DW$T$497, DW_AT_type(*$C$DW$T$496)
	.dwattr $C$DW$T$497, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$497, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$497, DW_AT_decl_line(0x1a0)
	.dwattr $C$DW$T$497, DW_AT_decl_column(0x2c)
$C$DW$T$498	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_hooks")
	.dwattr $C$DW$T$498, DW_AT_type(*$C$DW$T$497)
	.dwattr $C$DW$T$498, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$498, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$498, DW_AT_decl_line(0x1a1)
	.dwattr $C$DW$T$498, DW_AT_decl_column(0x28)

$C$DW$T$128	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$128, DW_AT_byte_size(0x08)
$C$DW$267	.dwtag  DW_TAG_member
	.dwattr $C$DW$267, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$267, DW_AT_name("quot")
	.dwattr $C$DW$267, DW_AT_TI_symbol_name("quot")
	.dwattr $C$DW$267, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$267, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$267, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$267, DW_AT_decl_line(0x50)
	.dwattr $C$DW$267, DW_AT_decl_column(0x16)
$C$DW$268	.dwtag  DW_TAG_member
	.dwattr $C$DW$268, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$268, DW_AT_name("rem")
	.dwattr $C$DW$268, DW_AT_TI_symbol_name("rem")
	.dwattr $C$DW$268, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$268, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$268, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$268, DW_AT_decl_line(0x50)
	.dwattr $C$DW$268, DW_AT_decl_column(0x1c)
	.dwendtag $C$DW$T$128

	.dwattr $C$DW$T$128, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$128, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$128, DW_AT_decl_column(0x10)
$C$DW$T$499	.dwtag  DW_TAG_typedef, DW_AT_name("div_t")
	.dwattr $C$DW$T$499, DW_AT_type(*$C$DW$T$128)
	.dwattr $C$DW$T$499, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$499, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$499, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$499, DW_AT_decl_column(0x23)

$C$DW$T$129	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$129, DW_AT_byte_size(0x08)
$C$DW$269	.dwtag  DW_TAG_member
	.dwattr $C$DW$269, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$269, DW_AT_name("quot")
	.dwattr $C$DW$269, DW_AT_TI_symbol_name("quot")
	.dwattr $C$DW$269, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$269, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$269, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$269, DW_AT_decl_line(0x52)
	.dwattr $C$DW$269, DW_AT_decl_column(0x16)
$C$DW$270	.dwtag  DW_TAG_member
	.dwattr $C$DW$270, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$270, DW_AT_name("rem")
	.dwattr $C$DW$270, DW_AT_TI_symbol_name("rem")
	.dwattr $C$DW$270, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$270, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$270, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$270, DW_AT_decl_line(0x52)
	.dwattr $C$DW$270, DW_AT_decl_column(0x1c)
	.dwendtag $C$DW$T$129

	.dwattr $C$DW$T$129, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$129, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$129, DW_AT_decl_column(0x10)
$C$DW$T$500	.dwtag  DW_TAG_typedef, DW_AT_name("ldiv_t")
	.dwattr $C$DW$T$500, DW_AT_type(*$C$DW$T$129)
	.dwattr $C$DW$T$500, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$500, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$500, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$500, DW_AT_decl_column(0x23)

$C$DW$T$130	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$130, DW_AT_byte_size(0x10)
$C$DW$271	.dwtag  DW_TAG_member
	.dwattr $C$DW$271, DW_AT_type(*$C$DW$T$14)
	.dwattr $C$DW$271, DW_AT_name("quot")
	.dwattr $C$DW$271, DW_AT_TI_symbol_name("quot")
	.dwattr $C$DW$271, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$271, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$271, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$271, DW_AT_decl_line(0x55)
	.dwattr $C$DW$271, DW_AT_decl_column(0x1c)
$C$DW$272	.dwtag  DW_TAG_member
	.dwattr $C$DW$272, DW_AT_type(*$C$DW$T$14)
	.dwattr $C$DW$272, DW_AT_name("rem")
	.dwattr $C$DW$272, DW_AT_TI_symbol_name("rem")
	.dwattr $C$DW$272, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$272, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$272, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$272, DW_AT_decl_line(0x55)
	.dwattr $C$DW$272, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$130

	.dwattr $C$DW$T$130, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$130, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$130, DW_AT_decl_column(0x10)
$C$DW$T$501	.dwtag  DW_TAG_typedef, DW_AT_name("lldiv_t")
	.dwattr $C$DW$T$501, DW_AT_type(*$C$DW$T$130)
	.dwattr $C$DW$T$501, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$501, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$501, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$501, DW_AT_decl_column(0x29)

$C$DW$T$134	.dwtag  DW_TAG_union_type
	.dwattr $C$DW$T$134, DW_AT_byte_size(0x04)
$C$DW$273	.dwtag  DW_TAG_member
	.dwattr $C$DW$273, DW_AT_type(*$C$DW$T$131)
	.dwattr $C$DW$273, DW_AT_name("f")
	.dwattr $C$DW$273, DW_AT_TI_symbol_name("f")
	.dwattr $C$DW$273, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$273, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$273, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$273, DW_AT_decl_line(0xac)
	.dwattr $C$DW$273, DW_AT_decl_column(0x0f)
$C$DW$274	.dwtag  DW_TAG_member
	.dwattr $C$DW$274, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$274, DW_AT_name("a")
	.dwattr $C$DW$274, DW_AT_TI_symbol_name("a")
	.dwattr $C$DW$274, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$274, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$274, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$274, DW_AT_decl_line(0xad)
	.dwattr $C$DW$274, DW_AT_decl_column(0x0f)
	.dwendtag $C$DW$T$134

	.dwattr $C$DW$T$134, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$134, DW_AT_decl_line(0xab)
	.dwattr $C$DW$T$134, DW_AT_decl_column(0x0f)
$C$DW$T$502	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_FloatData")
	.dwattr $C$DW$T$502, DW_AT_type(*$C$DW$T$134)
	.dwattr $C$DW$T$502, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$502, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$502, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$502, DW_AT_decl_column(0x03)

$C$DW$T$137	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$137, DW_AT_name(".ggroup1")
	.dwattr $C$DW$T$137, DW_AT_byte_size(0x20)
$C$DW$275	.dwtag  DW_TAG_member
	.dwattr $C$DW$275, DW_AT_type(*$C$DW$T$136)
	.dwattr $C$DW$275, DW_AT_name("sigma")
	.dwattr $C$DW$275, DW_AT_TI_symbol_name("sigma")
	.dwattr $C$DW$275, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$275, DW_AT_accessibility(DW_ACCESS_public)
$C$DW$276	.dwtag  DW_TAG_member
	.dwattr $C$DW$276, DW_AT_type(*$C$DW$T$136)
	.dwattr $C$DW$276, DW_AT_name("tau")
	.dwattr $C$DW$276, DW_AT_TI_symbol_name("tau")
	.dwattr $C$DW$276, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$276, DW_AT_accessibility(DW_ACCESS_public)
	.dwendtag $C$DW$T$137


$C$DW$T$505	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$505, DW_AT_name("CYA_Log_Levels")
	.dwattr $C$DW$T$505, DW_AT_byte_size(0x01)
$C$DW$277	.dwtag  DW_TAG_enumerator, DW_AT_name("ERROR_LOG"), DW_AT_const_value(0x00)
	.dwattr $C$DW$277, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$277, DW_AT_decl_line(0x23)
	.dwattr $C$DW$277, DW_AT_decl_column(0x05)
$C$DW$278	.dwtag  DW_TAG_enumerator, DW_AT_name("INFO_LOG"), DW_AT_const_value(0x01)
	.dwattr $C$DW$278, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$278, DW_AT_decl_line(0x24)
	.dwattr $C$DW$278, DW_AT_decl_column(0x05)
$C$DW$279	.dwtag  DW_TAG_enumerator, DW_AT_name("ENTER_LOG"), DW_AT_const_value(0x02)
	.dwattr $C$DW$279, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$279, DW_AT_decl_line(0x25)
	.dwattr $C$DW$279, DW_AT_decl_column(0x05)
$C$DW$280	.dwtag  DW_TAG_enumerator, DW_AT_name("LEAVE_LOG"), DW_AT_const_value(0x03)
	.dwattr $C$DW$280, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$280, DW_AT_decl_line(0x26)
	.dwattr $C$DW$280, DW_AT_decl_column(0x05)
$C$DW$281	.dwtag  DW_TAG_enumerator, DW_AT_name("OTHER_LOG"), DW_AT_const_value(0x04)
	.dwattr $C$DW$281, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$281, DW_AT_decl_line(0x27)
	.dwattr $C$DW$281, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$505

	.dwattr $C$DW$T$505, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$T$505, DW_AT_decl_line(0x22)
	.dwattr $C$DW$T$505, DW_AT_decl_column(0x07)

$C$DW$T$140	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$140, DW_AT_name("ChaCha")
	.dwattr $C$DW$T$140, DW_AT_byte_size(0x40)
$C$DW$282	.dwtag  DW_TAG_member
	.dwattr $C$DW$282, DW_AT_type(*$C$DW$T$139)
	.dwattr $C$DW$282, DW_AT_name("X")
	.dwattr $C$DW$282, DW_AT_TI_symbol_name("X")
	.dwattr $C$DW$282, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$282, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$282, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/chacha.h")
	.dwattr $C$DW$282, DW_AT_decl_line(0x25)
	.dwattr $C$DW$282, DW_AT_decl_column(0x0c)
	.dwendtag $C$DW$T$140

	.dwattr $C$DW$T$140, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/chacha.h")
	.dwattr $C$DW$T$140, DW_AT_decl_line(0x24)
	.dwattr $C$DW$T$140, DW_AT_decl_column(0x10)
$C$DW$T$506	.dwtag  DW_TAG_typedef, DW_AT_name("ChaCha")
	.dwattr $C$DW$T$506, DW_AT_type(*$C$DW$T$140)
	.dwattr $C$DW$T$506, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$506, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/chacha.h")
	.dwattr $C$DW$T$506, DW_AT_decl_line(0x26)
	.dwattr $C$DW$T$506, DW_AT_decl_column(0x03)
$C$DW$T$507	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$507, DW_AT_type(*$C$DW$T$506)
	.dwattr $C$DW$T$507, DW_AT_address_class(0x20)
$C$DW$T$508	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$508, DW_AT_type(*$C$DW$T$507)
$C$DW$T$2	.dwtag  DW_TAG_unspecified_type
	.dwattr $C$DW$T$2, DW_AT_name("void")
$C$DW$T$3	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$3, DW_AT_type(*$C$DW$T$2)
	.dwattr $C$DW$T$3, DW_AT_address_class(0x20)

$C$DW$T$514	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$514, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$T$514, DW_AT_language(DW_LANG_C)
$C$DW$283	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$283, DW_AT_type(*$C$DW$T$158)
	.dwendtag $C$DW$T$514

$C$DW$T$515	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$515, DW_AT_type(*$C$DW$T$514)
	.dwattr $C$DW$T$515, DW_AT_address_class(0x20)
$C$DW$T$516	.dwtag  DW_TAG_typedef, DW_AT_name("CyaSSL_Malloc_cb")
	.dwattr $C$DW$T$516, DW_AT_type(*$C$DW$T$515)
	.dwattr $C$DW$T$516, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$516, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/memory.h")
	.dwattr $C$DW$T$516, DW_AT_decl_line(0x23)
	.dwattr $C$DW$T$516, DW_AT_decl_column(0x11)

$C$DW$T$517	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$517, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$T$517, DW_AT_language(DW_LANG_C)
$C$DW$284	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$284, DW_AT_type(*$C$DW$T$3)
$C$DW$285	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$285, DW_AT_type(*$C$DW$T$158)
	.dwendtag $C$DW$T$517

$C$DW$T$518	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$518, DW_AT_type(*$C$DW$T$517)
	.dwattr $C$DW$T$518, DW_AT_address_class(0x20)
$C$DW$T$519	.dwtag  DW_TAG_typedef, DW_AT_name("CyaSSL_Realloc_cb")
	.dwattr $C$DW$T$519, DW_AT_type(*$C$DW$T$518)
	.dwattr $C$DW$T$519, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$519, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/memory.h")
	.dwattr $C$DW$T$519, DW_AT_decl_line(0x25)
	.dwattr $C$DW$T$519, DW_AT_decl_column(0x11)
$C$DW$T$177	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Ptr")
	.dwattr $C$DW$T$177, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$T$177, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$177, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$177, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$T$177, DW_AT_decl_column(0x1a)
$C$DW$T$520	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__gateObj")
	.dwattr $C$DW$T$520, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$520, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$520, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$520, DW_AT_decl_line(0x90)
	.dwattr $C$DW$T$520, DW_AT_decl_column(0x11)
$C$DW$T$521	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__gatePrms")
	.dwattr $C$DW$T$521, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$521, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$521, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$521, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$521, DW_AT_decl_column(0x11)
$C$DW$T$522	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerObj")
	.dwattr $C$DW$T$522, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$522, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$522, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$522, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$522, DW_AT_decl_column(0x11)
$C$DW$T$523	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Object__table")
	.dwattr $C$DW$T$523, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$523, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$523, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$523, DW_AT_decl_line(0xc8)
	.dwattr $C$DW$T$523, DW_AT_decl_column(0x11)
$C$DW$T$524	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__gateObj")
	.dwattr $C$DW$T$524, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$524, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$524, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$524, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$524, DW_AT_decl_column(0x11)
$C$DW$T$525	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__gatePrms")
	.dwattr $C$DW$T$525, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$525, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$525, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$525, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$525, DW_AT_decl_column(0x11)
$C$DW$T$526	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerObj")
	.dwattr $C$DW$T$526, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$526, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$526, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$526, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$526, DW_AT_decl_column(0x11)
$C$DW$T$527	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Object__table")
	.dwattr $C$DW$T$527, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$527, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$527, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$527, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$527, DW_AT_decl_column(0x11)
$C$DW$T$528	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__gateObj")
	.dwattr $C$DW$T$528, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$528, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$528, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$528, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$528, DW_AT_decl_column(0x11)
$C$DW$T$529	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__gatePrms")
	.dwattr $C$DW$T$529, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$529, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$529, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$529, DW_AT_decl_line(0x81)
	.dwattr $C$DW$T$529, DW_AT_decl_column(0x11)
$C$DW$T$530	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerObj")
	.dwattr $C$DW$T$530, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$530, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$530, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$530, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$530, DW_AT_decl_column(0x11)
$C$DW$T$531	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Object__table")
	.dwattr $C$DW$T$531, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$531, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$531, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$531, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$T$531, DW_AT_decl_column(0x11)
$C$DW$T$532	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__gateObj")
	.dwattr $C$DW$T$532, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$532, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$532, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$532, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$532, DW_AT_decl_column(0x11)
$C$DW$T$533	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__gatePrms")
	.dwattr $C$DW$T$533, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$533, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$533, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$533, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$533, DW_AT_decl_column(0x11)
$C$DW$T$534	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerObj")
	.dwattr $C$DW$T$534, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$534, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$534, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$534, DW_AT_decl_line(0x81)
	.dwattr $C$DW$T$534, DW_AT_decl_column(0x11)
$C$DW$T$535	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Object__table")
	.dwattr $C$DW$T$535, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$535, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$535, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$535, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$535, DW_AT_decl_column(0x11)
$C$DW$T$536	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__gateObj")
	.dwattr $C$DW$T$536, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$536, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$536, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$536, DW_AT_decl_line(0xd4)
	.dwattr $C$DW$T$536, DW_AT_decl_column(0x11)
$C$DW$T$537	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__gatePrms")
	.dwattr $C$DW$T$537, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$537, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$537, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$537, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$T$537, DW_AT_decl_column(0x11)
$C$DW$T$538	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerObj")
	.dwattr $C$DW$T$538, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$538, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$538, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$538, DW_AT_decl_line(0xe4)
	.dwattr $C$DW$T$538, DW_AT_decl_column(0x11)
$C$DW$T$539	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Object__table")
	.dwattr $C$DW$T$539, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$539, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$539, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$539, DW_AT_decl_line(0x10c)
	.dwattr $C$DW$T$539, DW_AT_decl_column(0x11)
$C$DW$T$540	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__gateObj")
	.dwattr $C$DW$T$540, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$540, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$540, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$540, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$540, DW_AT_decl_column(0x11)
$C$DW$T$541	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__gatePrms")
	.dwattr $C$DW$T$541, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$541, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$541, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$541, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$541, DW_AT_decl_column(0x11)
$C$DW$T$542	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerObj")
	.dwattr $C$DW$T$542, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$542, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$542, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$542, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$542, DW_AT_decl_column(0x11)
$C$DW$T$543	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Object__table")
	.dwattr $C$DW$T$543, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$543, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$543, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$543, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$543, DW_AT_decl_column(0x11)
$C$DW$T$544	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__gateObj")
	.dwattr $C$DW$T$544, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$544, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$544, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$544, DW_AT_decl_line(0x82)
	.dwattr $C$DW$T$544, DW_AT_decl_column(0x11)
$C$DW$T$545	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__gatePrms")
	.dwattr $C$DW$T$545, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$545, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$545, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$545, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$545, DW_AT_decl_column(0x11)
$C$DW$T$546	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerObj")
	.dwattr $C$DW$T$546, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$546, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$546, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$546, DW_AT_decl_line(0x92)
	.dwattr $C$DW$T$546, DW_AT_decl_column(0x11)
$C$DW$T$547	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Object__table")
	.dwattr $C$DW$T$547, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$547, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$547, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$547, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$547, DW_AT_decl_column(0x11)
$C$DW$T$548	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__gateObj")
	.dwattr $C$DW$T$548, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$548, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$548, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$548, DW_AT_decl_line(0x82)
	.dwattr $C$DW$T$548, DW_AT_decl_column(0x11)
$C$DW$T$549	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__gatePrms")
	.dwattr $C$DW$T$549, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$549, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$549, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$549, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$549, DW_AT_decl_column(0x11)
$C$DW$T$550	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerObj")
	.dwattr $C$DW$T$550, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$550, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$550, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$550, DW_AT_decl_line(0x92)
	.dwattr $C$DW$T$550, DW_AT_decl_column(0x11)
$C$DW$T$551	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Object__table")
	.dwattr $C$DW$T$551, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$551, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$551, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$551, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$551, DW_AT_decl_column(0x11)
$C$DW$T$552	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__gateObj")
	.dwattr $C$DW$T$552, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$552, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$552, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$552, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$T$552, DW_AT_decl_column(0x11)
$C$DW$T$553	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__gatePrms")
	.dwattr $C$DW$T$553, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$553, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$553, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$553, DW_AT_decl_line(0xc0)
	.dwattr $C$DW$T$553, DW_AT_decl_column(0x11)
$C$DW$T$554	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerObj")
	.dwattr $C$DW$T$554, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$554, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$554, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$554, DW_AT_decl_line(0xcc)
	.dwattr $C$DW$T$554, DW_AT_decl_column(0x11)
$C$DW$T$555	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Object__table")
	.dwattr $C$DW$T$555, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$555, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$555, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$555, DW_AT_decl_line(0xf4)
	.dwattr $C$DW$T$555, DW_AT_decl_column(0x11)
$C$DW$T$556	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__gateObj")
	.dwattr $C$DW$T$556, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$556, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$556, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$556, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$556, DW_AT_decl_column(0x11)
$C$DW$T$557	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__gatePrms")
	.dwattr $C$DW$T$557, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$557, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$557, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$557, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$557, DW_AT_decl_column(0x11)
$C$DW$T$558	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerObj")
	.dwattr $C$DW$T$558, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$558, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$558, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$558, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$558, DW_AT_decl_column(0x11)
$C$DW$T$559	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Object__table")
	.dwattr $C$DW$T$559, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$559, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$559, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$559, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$559, DW_AT_decl_column(0x11)
$C$DW$T$560	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__gateObj")
	.dwattr $C$DW$T$560, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$560, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$560, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$560, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$560, DW_AT_decl_column(0x11)
$C$DW$T$561	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__gatePrms")
	.dwattr $C$DW$T$561, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$561, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$561, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$561, DW_AT_decl_line(0x60)
	.dwattr $C$DW$T$561, DW_AT_decl_column(0x11)
$C$DW$T$562	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerObj")
	.dwattr $C$DW$T$562, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$562, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$562, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$562, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$562, DW_AT_decl_column(0x11)
$C$DW$T$563	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Object__table")
	.dwattr $C$DW$T$563, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$563, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$563, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$563, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$563, DW_AT_decl_column(0x11)
$C$DW$T$564	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__gateObj")
	.dwattr $C$DW$T$564, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$564, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$564, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$564, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$T$564, DW_AT_decl_column(0x11)
$C$DW$T$565	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__gatePrms")
	.dwattr $C$DW$T$565, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$565, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$565, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$565, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$T$565, DW_AT_decl_column(0x11)
$C$DW$T$566	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerObj")
	.dwattr $C$DW$T$566, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$566, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$566, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$566, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$T$566, DW_AT_decl_column(0x11)
$C$DW$T$567	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Object__table")
	.dwattr $C$DW$T$567, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$567, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$567, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$567, DW_AT_decl_line(0xe7)
	.dwattr $C$DW$T$567, DW_AT_decl_column(0x11)
$C$DW$T$568	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__gateObj")
	.dwattr $C$DW$T$568, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$568, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$568, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$568, DW_AT_decl_line(0x7f)
	.dwattr $C$DW$T$568, DW_AT_decl_column(0x11)
$C$DW$T$569	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__gatePrms")
	.dwattr $C$DW$T$569, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$569, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$569, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$569, DW_AT_decl_line(0x83)
	.dwattr $C$DW$T$569, DW_AT_decl_column(0x11)
$C$DW$T$570	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerObj")
	.dwattr $C$DW$T$570, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$570, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$570, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$570, DW_AT_decl_line(0x8f)
	.dwattr $C$DW$T$570, DW_AT_decl_column(0x11)
$C$DW$T$571	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Object__table")
	.dwattr $C$DW$T$571, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$571, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$571, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$571, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$571, DW_AT_decl_column(0x11)
$C$DW$T$572	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__gateObj")
	.dwattr $C$DW$T$572, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$572, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$572, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$572, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$572, DW_AT_decl_column(0x11)
$C$DW$T$573	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__gatePrms")
	.dwattr $C$DW$T$573, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$573, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$573, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$573, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$573, DW_AT_decl_column(0x11)
$C$DW$T$574	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerObj")
	.dwattr $C$DW$T$574, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$574, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$574, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$574, DW_AT_decl_line(0x80)
	.dwattr $C$DW$T$574, DW_AT_decl_column(0x11)
$C$DW$T$575	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Object__table")
	.dwattr $C$DW$T$575, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$575, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$575, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$575, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$575, DW_AT_decl_column(0x11)
$C$DW$T$576	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__gateObj")
	.dwattr $C$DW$T$576, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$576, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$576, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$576, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$576, DW_AT_decl_column(0x11)
$C$DW$T$577	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__gatePrms")
	.dwattr $C$DW$T$577, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$577, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$577, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$577, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$577, DW_AT_decl_column(0x11)
$C$DW$T$578	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerObj")
	.dwattr $C$DW$T$578, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$578, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$578, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$578, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$578, DW_AT_decl_column(0x11)
$C$DW$T$579	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Object__table")
	.dwattr $C$DW$T$579, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$579, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$579, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$579, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$579, DW_AT_decl_column(0x11)
$C$DW$T$580	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__gateObj")
	.dwattr $C$DW$T$580, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$580, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$580, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$580, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$580, DW_AT_decl_column(0x11)
$C$DW$T$581	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__gatePrms")
	.dwattr $C$DW$T$581, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$581, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$581, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$581, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$581, DW_AT_decl_column(0x11)
$C$DW$T$582	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerObj")
	.dwattr $C$DW$T$582, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$582, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$582, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$582, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$582, DW_AT_decl_column(0x11)
$C$DW$T$583	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Object__table")
	.dwattr $C$DW$T$583, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$583, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$583, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$583, DW_AT_decl_line(0x90)
	.dwattr $C$DW$T$583, DW_AT_decl_column(0x11)
$C$DW$T$584	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__gateObj")
	.dwattr $C$DW$T$584, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$584, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$584, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$584, DW_AT_decl_line(0x53)
	.dwattr $C$DW$T$584, DW_AT_decl_column(0x11)
$C$DW$T$585	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__gatePrms")
	.dwattr $C$DW$T$585, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$585, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$585, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$585, DW_AT_decl_line(0x57)
	.dwattr $C$DW$T$585, DW_AT_decl_column(0x11)
$C$DW$T$586	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerObj")
	.dwattr $C$DW$T$586, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$586, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$586, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$586, DW_AT_decl_line(0x63)
	.dwattr $C$DW$T$586, DW_AT_decl_column(0x11)
$C$DW$T$587	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Object__table")
	.dwattr $C$DW$T$587, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$587, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$587, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$587, DW_AT_decl_line(0x8b)
	.dwattr $C$DW$T$587, DW_AT_decl_column(0x11)
$C$DW$T$588	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__gateObj")
	.dwattr $C$DW$T$588, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$588, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$588, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$588, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$588, DW_AT_decl_column(0x11)
$C$DW$T$589	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__gatePrms")
	.dwattr $C$DW$T$589, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$589, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$589, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$589, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$589, DW_AT_decl_column(0x11)
$C$DW$T$590	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerObj")
	.dwattr $C$DW$T$590, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$590, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$590, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$590, DW_AT_decl_line(0x76)
	.dwattr $C$DW$T$590, DW_AT_decl_column(0x11)
$C$DW$T$591	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Object__table")
	.dwattr $C$DW$T$591, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$591, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$591, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$591, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$T$591, DW_AT_decl_column(0x11)
$C$DW$T$592	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__gateObj")
	.dwattr $C$DW$T$592, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$592, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$592, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$592, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$592, DW_AT_decl_column(0x11)
$C$DW$T$593	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__gatePrms")
	.dwattr $C$DW$T$593, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$593, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$593, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$593, DW_AT_decl_line(0x81)
	.dwattr $C$DW$T$593, DW_AT_decl_column(0x11)
$C$DW$T$594	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerObj")
	.dwattr $C$DW$T$594, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$594, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$594, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$594, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$594, DW_AT_decl_column(0x11)
$C$DW$T$595	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Object__table")
	.dwattr $C$DW$T$595, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$595, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$595, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$595, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$T$595, DW_AT_decl_column(0x11)
$C$DW$T$596	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__gateObj")
	.dwattr $C$DW$T$596, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$596, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$596, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$596, DW_AT_decl_line(0xe2)
	.dwattr $C$DW$T$596, DW_AT_decl_column(0x11)
$C$DW$T$597	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__gatePrms")
	.dwattr $C$DW$T$597, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$597, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$597, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$597, DW_AT_decl_line(0xe6)
	.dwattr $C$DW$T$597, DW_AT_decl_column(0x11)
$C$DW$T$598	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerObj")
	.dwattr $C$DW$T$598, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$598, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$598, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$598, DW_AT_decl_line(0xf2)
	.dwattr $C$DW$T$598, DW_AT_decl_column(0x11)
$C$DW$T$599	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Object__table")
	.dwattr $C$DW$T$599, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$599, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$599, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$599, DW_AT_decl_line(0x11a)
	.dwattr $C$DW$T$599, DW_AT_decl_column(0x11)
$C$DW$T$600	.dwtag  DW_TAG_typedef, DW_AT_name("Ptr")
	.dwattr $C$DW$T$600, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$600, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$600, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$600, DW_AT_decl_line(0xea)
	.dwattr $C$DW$T$600, DW_AT_decl_column(0x19)
$C$DW$T$601	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Swi_Instance_State__hookEnv")
	.dwattr $C$DW$T$601, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$601, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$601, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$601, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$601, DW_AT_decl_column(0x11)
$C$DW$T$602	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Instance_State__hookEnv")
	.dwattr $C$DW$T$602, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$602, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$602, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$602, DW_AT_decl_line(0x8f)
	.dwattr $C$DW$T$602, DW_AT_decl_column(0x11)

$C$DW$T$183	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$183, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$183, DW_AT_language(DW_LANG_C)
$C$DW$286	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$286, DW_AT_type(*$C$DW$T$177)
$C$DW$287	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$287, DW_AT_type(*$C$DW$T$180)
$C$DW$288	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$288, DW_AT_type(*$C$DW$T$180)
$C$DW$289	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$289, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$183

$C$DW$T$184	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$184, DW_AT_type(*$C$DW$T$183)
	.dwattr $C$DW$T$184, DW_AT_address_class(0x20)
$C$DW$T$603	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_start_FxnT")
	.dwattr $C$DW$T$603, DW_AT_type(*$C$DW$T$184)
	.dwattr $C$DW$T$603, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$603, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$603, DW_AT_decl_line(0x92)
	.dwattr $C$DW$T$603, DW_AT_decl_column(0x13)
$C$DW$T$185	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$185, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$185, DW_AT_address_class(0x20)
$C$DW$T$325	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Swi_Instance_State__hookEnv")
	.dwattr $C$DW$T$325, DW_AT_type(*$C$DW$T$185)
	.dwattr $C$DW$T$325, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$325, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$325, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$325, DW_AT_decl_column(0x12)
$C$DW$T$326	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Swi_Instance_State__hookEnv")
	.dwattr $C$DW$T$326, DW_AT_type(*$C$DW$T$325)
	.dwattr $C$DW$T$326, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$326, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$326, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$326, DW_AT_decl_column(0x3d)
$C$DW$T$354	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Instance_State__hookEnv")
	.dwattr $C$DW$T$354, DW_AT_type(*$C$DW$T$185)
	.dwattr $C$DW$T$354, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$354, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$354, DW_AT_decl_line(0x90)
	.dwattr $C$DW$T$354, DW_AT_decl_column(0x12)
$C$DW$T$355	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Instance_State__hookEnv")
	.dwattr $C$DW$T$355, DW_AT_type(*$C$DW$T$354)
	.dwattr $C$DW$T$355, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$355, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$355, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$355, DW_AT_decl_column(0x3e)

$C$DW$T$389	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$389, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$389, DW_AT_language(DW_LANG_C)
$C$DW$290	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$290, DW_AT_type(*$C$DW$T$3)
$C$DW$291	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$291, DW_AT_type(*$C$DW$T$191)
$C$DW$292	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$292, DW_AT_type(*$C$DW$T$191)
$C$DW$293	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$293, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$389

$C$DW$T$390	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$390, DW_AT_type(*$C$DW$T$389)
	.dwattr $C$DW$T$390, DW_AT_address_class(0x20)
$C$DW$T$604	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_alloc_FxnT")
	.dwattr $C$DW$T$604, DW_AT_type(*$C$DW$T$390)
	.dwattr $C$DW$T$604, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$604, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$604, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$T$604, DW_AT_decl_column(0x13)

$C$DW$T$431	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$431, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$431, DW_AT_language(DW_LANG_C)
$C$DW$294	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$294, DW_AT_type(*$C$DW$T$430)
$C$DW$295	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$295, DW_AT_type(*$C$DW$T$191)
$C$DW$296	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$296, DW_AT_type(*$C$DW$T$191)
$C$DW$297	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$297, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$431

$C$DW$T$432	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$432, DW_AT_type(*$C$DW$T$431)
	.dwattr $C$DW$T$432, DW_AT_address_class(0x20)

$C$DW$T$469	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$469, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$469, DW_AT_language(DW_LANG_C)
$C$DW$298	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$298, DW_AT_type(*$C$DW$T$177)
$C$DW$299	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$299, DW_AT_type(*$C$DW$T$191)
$C$DW$300	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$300, DW_AT_type(*$C$DW$T$177)
$C$DW$301	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$301, DW_AT_type(*$C$DW$T$468)
$C$DW$302	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$302, DW_AT_type(*$C$DW$T$191)
$C$DW$303	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$303, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$469

$C$DW$T$470	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$470, DW_AT_type(*$C$DW$T$469)
	.dwattr $C$DW$T$470, DW_AT_address_class(0x20)

$C$DW$T$481	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$481, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$T$481, DW_AT_language(DW_LANG_C)
$C$DW$304	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$304, DW_AT_type(*$C$DW$T$177)
$C$DW$305	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$305, DW_AT_type(*$C$DW$T$191)
$C$DW$306	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$306, DW_AT_type(*$C$DW$T$177)
$C$DW$307	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$307, DW_AT_type(*$C$DW$T$480)
$C$DW$308	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$308, DW_AT_type(*$C$DW$T$191)
$C$DW$309	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$309, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$481

$C$DW$T$482	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$482, DW_AT_type(*$C$DW$T$481)
	.dwattr $C$DW$T$482, DW_AT_address_class(0x20)
$C$DW$T$468	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$468, DW_AT_type(*$C$DW$T$177)

$C$DW$T$155	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$155, DW_AT_language(DW_LANG_C)
$C$DW$310	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$310, DW_AT_type(*$C$DW$T$152)
$C$DW$311	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$311, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$155

$C$DW$T$156	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$156, DW_AT_type(*$C$DW$T$155)
	.dwattr $C$DW$T$156, DW_AT_address_class(0x20)
$C$DW$T$159	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$159, DW_AT_type(*$C$DW$T$2)
$C$DW$T$160	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$160, DW_AT_type(*$C$DW$T$159)
	.dwattr $C$DW$T$160, DW_AT_address_class(0x20)
$C$DW$T$605	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_CPtr")
	.dwattr $C$DW$T$605, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$T$605, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$605, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$605, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$T$605, DW_AT_decl_column(0x1a)

$C$DW$T$178	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$178, DW_AT_language(DW_LANG_C)
$C$DW$T$179	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$179, DW_AT_type(*$C$DW$T$178)
	.dwattr $C$DW$T$179, DW_AT_address_class(0x20)
$C$DW$T$606	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_startupHookFunc")
	.dwattr $C$DW$T$606, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$606, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$606, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$606, DW_AT_decl_line(0x1af)
	.dwattr $C$DW$T$606, DW_AT_decl_column(0x14)
$C$DW$T$607	.dwtag  DW_TAG_typedef, DW_AT_name("__TI_atexit_fn")
	.dwattr $C$DW$T$607, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$607, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$607, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$607, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$607, DW_AT_decl_column(0x14)
$C$DW$T$608	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_StartFuncPtr")
	.dwattr $C$DW$T$608, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$608, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$608, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$608, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$608, DW_AT_decl_column(0x14)
$C$DW$T$609	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_StartupFuncPtr")
	.dwattr $C$DW$T$609, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$609, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$609, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$609, DW_AT_decl_line(0x67)
	.dwattr $C$DW$T$609, DW_AT_decl_column(0x14)
$C$DW$T$180	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_FuncPtr")
	.dwattr $C$DW$T$180, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$180, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$180, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$180, DW_AT_decl_line(0x3f)
	.dwattr $C$DW$T$180, DW_AT_decl_column(0x14)
$C$DW$T$610	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_SupportProxy_FuncPtr")
	.dwattr $C$DW$T$610, DW_AT_type(*$C$DW$T$180)
	.dwattr $C$DW$T$610, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$610, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$610, DW_AT_decl_line(0x40)
	.dwattr $C$DW$T$610, DW_AT_decl_column(0x34)
$C$DW$T$611	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_startup_FxnT")
	.dwattr $C$DW$T$611, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$611, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$611, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$611, DW_AT_decl_line(0x149)
	.dwattr $C$DW$T$611, DW_AT_decl_column(0x14)
$C$DW$T$612	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_AllBlockedFuncPtr")
	.dwattr $C$DW$T$612, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$T$612, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$612, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$612, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$612, DW_AT_decl_column(0x14)
$C$DW$T$613	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_allBlockedFunc")
	.dwattr $C$DW$T$613, DW_AT_type(*$C$DW$T$612)
	.dwattr $C$DW$T$613, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$613, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$613, DW_AT_decl_line(0x17e)
	.dwattr $C$DW$T$613, DW_AT_decl_column(0x2f)

$C$DW$T$186	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$186, DW_AT_language(DW_LANG_C)
$C$DW$312	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$312, DW_AT_type(*$C$DW$T$185)
$C$DW$313	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$313, DW_AT_type(*$C$DW$T$185)
	.dwendtag $C$DW$T$186

$C$DW$T$187	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$187, DW_AT_type(*$C$DW$T$186)
	.dwattr $C$DW$T$187, DW_AT_address_class(0x20)
$C$DW$T$614	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_swap_FxnT")
	.dwattr $C$DW$T$614, DW_AT_type(*$C$DW$T$187)
	.dwattr $C$DW$T$614, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$614, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$614, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$614, DW_AT_decl_column(0x14)

$C$DW$T$204	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$204, DW_AT_language(DW_LANG_C)
$C$DW$314	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$314, DW_AT_type(*$C$DW$T$203)
	.dwendtag $C$DW$T$204

$C$DW$T$205	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$205, DW_AT_type(*$C$DW$T$204)
	.dwattr $C$DW$T$205, DW_AT_address_class(0x20)
$C$DW$T$615	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_doTickFunc")
	.dwattr $C$DW$T$615, DW_AT_type(*$C$DW$T$205)
	.dwattr $C$DW$T$615, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$615, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$615, DW_AT_decl_line(0xf8)
	.dwattr $C$DW$T$615, DW_AT_decl_column(0x14)
$C$DW$T$206	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_FuncPtr")
	.dwattr $C$DW$T$206, DW_AT_type(*$C$DW$T$205)
	.dwattr $C$DW$T$206, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$206, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$206, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$206, DW_AT_decl_column(0x14)

$C$DW$T$227	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$227, DW_AT_type(*$C$DW$T$206)
	.dwattr $C$DW$T$227, DW_AT_language(DW_LANG_C)
$C$DW$315	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$315, DW_AT_type(*$C$DW$T$3)
$C$DW$316	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$316, DW_AT_type(*$C$DW$T$226)
	.dwendtag $C$DW$T$227

$C$DW$T$228	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$228, DW_AT_type(*$C$DW$T$227)
	.dwattr $C$DW$T$228, DW_AT_address_class(0x20)
$C$DW$T$616	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getFunc_FxnT")
	.dwattr $C$DW$T$616, DW_AT_type(*$C$DW$T$228)
	.dwattr $C$DW$T$616, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$616, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$616, DW_AT_decl_line(0x18f)
	.dwattr $C$DW$T$616, DW_AT_decl_column(0x30)

$C$DW$T$265	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$265, DW_AT_type(*$C$DW$T$206)
	.dwattr $C$DW$T$265, DW_AT_language(DW_LANG_C)
$C$DW$317	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$317, DW_AT_type(*$C$DW$T$254)
$C$DW$318	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$318, DW_AT_type(*$C$DW$T$226)
	.dwendtag $C$DW$T$265

$C$DW$T$266	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$266, DW_AT_type(*$C$DW$T$265)
	.dwattr $C$DW$T$266, DW_AT_address_class(0x20)
$C$DW$T$617	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_FuncPtr")
	.dwattr $C$DW$T$617, DW_AT_type(*$C$DW$T$206)
	.dwattr $C$DW$T$617, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$617, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$617, DW_AT_decl_line(0x43)
	.dwattr $C$DW$T$617, DW_AT_decl_column(0x2e)
$C$DW$T$246	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_FuncPtr")
	.dwattr $C$DW$T$246, DW_AT_type(*$C$DW$T$205)
	.dwattr $C$DW$T$246, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$246, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$246, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$246, DW_AT_decl_column(0x14)

$C$DW$T$216	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$216, DW_AT_language(DW_LANG_C)
$C$DW$319	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$319, DW_AT_type(*$C$DW$T$3)
$C$DW$320	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$320, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$216

$C$DW$T$217	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$217, DW_AT_type(*$C$DW$T$216)
	.dwattr $C$DW$T$217, DW_AT_address_class(0x20)
$C$DW$T$618	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_setNextTick_FxnT")
	.dwattr $C$DW$T$618, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$T$618, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$618, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$618, DW_AT_decl_line(0x157)
	.dwattr $C$DW$T$618, DW_AT_decl_column(0x14)
$C$DW$T$619	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_setPeriod_FxnT")
	.dwattr $C$DW$T$619, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$T$619, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$619, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$619, DW_AT_decl_line(0x16c)
	.dwattr $C$DW$T$619, DW_AT_decl_column(0x14)
$C$DW$T$620	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_trigger_FxnT")
	.dwattr $C$DW$T$620, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$T$620, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$620, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$620, DW_AT_decl_line(0x19d)
	.dwattr $C$DW$T$620, DW_AT_decl_column(0x14)

$C$DW$T$218	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$218, DW_AT_language(DW_LANG_C)
$C$DW$321	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$321, DW_AT_type(*$C$DW$T$3)
	.dwendtag $C$DW$T$218

$C$DW$T$219	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$219, DW_AT_type(*$C$DW$T$218)
	.dwattr $C$DW$T$219, DW_AT_address_class(0x20)
$C$DW$T$621	.dwtag  DW_TAG_typedef, DW_AT_name("CyaSSL_Free_cb")
	.dwattr $C$DW$T$621, DW_AT_type(*$C$DW$T$219)
	.dwattr $C$DW$T$621, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$621, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/memory.h")
	.dwattr $C$DW$T$621, DW_AT_decl_line(0x24)
	.dwattr $C$DW$T$621, DW_AT_decl_column(0x10)
$C$DW$T$622	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_start_FxnT")
	.dwattr $C$DW$T$622, DW_AT_type(*$C$DW$T$219)
	.dwattr $C$DW$T$622, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$622, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$622, DW_AT_decl_line(0x15e)
	.dwattr $C$DW$T$622, DW_AT_decl_column(0x14)
$C$DW$T$623	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_stop_FxnT")
	.dwattr $C$DW$T$623, DW_AT_type(*$C$DW$T$219)
	.dwattr $C$DW$T$623, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$623, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$623, DW_AT_decl_line(0x165)
	.dwattr $C$DW$T$623, DW_AT_decl_column(0x14)

$C$DW$T$224	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$224, DW_AT_language(DW_LANG_C)
$C$DW$322	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$322, DW_AT_type(*$C$DW$T$3)
$C$DW$323	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$323, DW_AT_type(*$C$DW$T$223)
	.dwendtag $C$DW$T$224

$C$DW$T$225	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$225, DW_AT_type(*$C$DW$T$224)
	.dwattr $C$DW$T$225, DW_AT_address_class(0x20)
$C$DW$T$624	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getFreq_FxnT")
	.dwattr $C$DW$T$624, DW_AT_type(*$C$DW$T$225)
	.dwattr $C$DW$T$624, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$624, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$624, DW_AT_decl_line(0x188)
	.dwattr $C$DW$T$624, DW_AT_decl_column(0x14)

$C$DW$T$229	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$229, DW_AT_language(DW_LANG_C)
$C$DW$324	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$324, DW_AT_type(*$C$DW$T$3)
$C$DW$325	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$325, DW_AT_type(*$C$DW$T$206)
$C$DW$326	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$326, DW_AT_type(*$C$DW$T$203)
	.dwendtag $C$DW$T$229

$C$DW$T$230	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$230, DW_AT_type(*$C$DW$T$229)
	.dwattr $C$DW$T$230, DW_AT_address_class(0x20)
$C$DW$T$625	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_setFunc_FxnT")
	.dwattr $C$DW$T$625, DW_AT_type(*$C$DW$T$230)
	.dwattr $C$DW$T$625, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$625, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$625, DW_AT_decl_line(0x196)
	.dwattr $C$DW$T$625, DW_AT_decl_column(0x14)

$C$DW$T$257	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$257, DW_AT_language(DW_LANG_C)
$C$DW$327	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$327, DW_AT_type(*$C$DW$T$254)
$C$DW$328	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$328, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$257

$C$DW$T$258	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$258, DW_AT_type(*$C$DW$T$257)
	.dwattr $C$DW$T$258, DW_AT_address_class(0x20)

$C$DW$T$259	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$259, DW_AT_language(DW_LANG_C)
$C$DW$329	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$329, DW_AT_type(*$C$DW$T$254)
	.dwendtag $C$DW$T$259

$C$DW$T$260	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$260, DW_AT_type(*$C$DW$T$259)
	.dwattr $C$DW$T$260, DW_AT_address_class(0x20)

$C$DW$T$263	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$263, DW_AT_language(DW_LANG_C)
$C$DW$330	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$330, DW_AT_type(*$C$DW$T$254)
$C$DW$331	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$331, DW_AT_type(*$C$DW$T$223)
	.dwendtag $C$DW$T$263

$C$DW$T$264	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$264, DW_AT_type(*$C$DW$T$263)
	.dwattr $C$DW$T$264, DW_AT_address_class(0x20)

$C$DW$T$267	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$267, DW_AT_language(DW_LANG_C)
$C$DW$332	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$332, DW_AT_type(*$C$DW$T$254)
$C$DW$333	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$333, DW_AT_type(*$C$DW$T$206)
$C$DW$334	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$334, DW_AT_type(*$C$DW$T$203)
	.dwendtag $C$DW$T$267

$C$DW$T$268	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$268, DW_AT_type(*$C$DW$T$267)
	.dwattr $C$DW$T$268, DW_AT_address_class(0x20)

$C$DW$T$307	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$307, DW_AT_language(DW_LANG_C)
$C$DW$335	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$335, DW_AT_type(*$C$DW$T$203)
$C$DW$336	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$336, DW_AT_type(*$C$DW$T$203)
	.dwendtag $C$DW$T$307

$C$DW$T$308	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$308, DW_AT_type(*$C$DW$T$307)
	.dwattr $C$DW$T$308, DW_AT_address_class(0x20)
$C$DW$T$309	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_FuncPtr")
	.dwattr $C$DW$T$309, DW_AT_type(*$C$DW$T$308)
	.dwattr $C$DW$T$309, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$309, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$309, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$309, DW_AT_decl_column(0x14)
$C$DW$T$328	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_FuncPtr")
	.dwattr $C$DW$T$328, DW_AT_type(*$C$DW$T$308)
	.dwattr $C$DW$T$328, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$328, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$328, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$328, DW_AT_decl_column(0x14)

$C$DW$T$311	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$311, DW_AT_language(DW_LANG_C)
$C$DW$337	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$337, DW_AT_type(*$C$DW$T$148)
	.dwendtag $C$DW$T$311

$C$DW$T$312	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$312, DW_AT_type(*$C$DW$T$311)
	.dwattr $C$DW$T$312, DW_AT_address_class(0x20)
$C$DW$T$626	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_ExitFuncPtr")
	.dwattr $C$DW$T$626, DW_AT_type(*$C$DW$T$312)
	.dwattr $C$DW$T$626, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$626, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$626, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$626, DW_AT_decl_column(0x14)

$C$DW$T$316	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$316, DW_AT_language(DW_LANG_C)
$C$DW$338	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$338, DW_AT_type(*$C$DW$T$315)
$C$DW$339	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$339, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$316

$C$DW$T$317	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$317, DW_AT_type(*$C$DW$T$316)
	.dwattr $C$DW$T$317, DW_AT_address_class(0x20)

$C$DW$T$318	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$318, DW_AT_language(DW_LANG_C)
$C$DW$340	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$340, DW_AT_type(*$C$DW$T$315)
	.dwendtag $C$DW$T$318

$C$DW$T$319	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$319, DW_AT_type(*$C$DW$T$318)
	.dwattr $C$DW$T$319, DW_AT_address_class(0x20)

$C$DW$T$333	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$333, DW_AT_language(DW_LANG_C)
$C$DW$341	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$341, DW_AT_type(*$C$DW$T$332)
$C$DW$342	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$342, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$333

$C$DW$T$334	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$334, DW_AT_type(*$C$DW$T$333)
	.dwattr $C$DW$T$334, DW_AT_address_class(0x20)

$C$DW$T$335	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$335, DW_AT_language(DW_LANG_C)
$C$DW$343	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$343, DW_AT_type(*$C$DW$T$332)
	.dwendtag $C$DW$T$335

$C$DW$T$336	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$336, DW_AT_type(*$C$DW$T$335)
	.dwattr $C$DW$T$336, DW_AT_address_class(0x20)

$C$DW$T$337	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$337, DW_AT_language(DW_LANG_C)
$C$DW$344	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$344, DW_AT_type(*$C$DW$T$332)
$C$DW$345	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$345, DW_AT_type(*$C$DW$T$332)
	.dwendtag $C$DW$T$337

$C$DW$T$338	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$338, DW_AT_type(*$C$DW$T$337)
	.dwattr $C$DW$T$338, DW_AT_address_class(0x20)

$C$DW$T$382	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$382, DW_AT_language(DW_LANG_C)
$C$DW$346	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$346, DW_AT_type(*$C$DW$T$3)
$C$DW$347	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$347, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$382

$C$DW$T$383	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$383, DW_AT_type(*$C$DW$T$382)
	.dwattr $C$DW$T$383, DW_AT_address_class(0x20)
$C$DW$T$627	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_leave_FxnT")
	.dwattr $C$DW$T$627, DW_AT_type(*$C$DW$T$383)
	.dwattr $C$DW$T$627, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$627, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$T$627, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$T$627, DW_AT_decl_column(0x14)

$C$DW$T$391	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$391, DW_AT_language(DW_LANG_C)
$C$DW$348	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$348, DW_AT_type(*$C$DW$T$3)
$C$DW$349	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$349, DW_AT_type(*$C$DW$T$177)
$C$DW$350	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$350, DW_AT_type(*$C$DW$T$191)
	.dwendtag $C$DW$T$391

$C$DW$T$392	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$392, DW_AT_type(*$C$DW$T$391)
	.dwattr $C$DW$T$392, DW_AT_address_class(0x20)
$C$DW$T$628	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_free_FxnT")
	.dwattr $C$DW$T$628, DW_AT_type(*$C$DW$T$392)
	.dwattr $C$DW$T$628, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$628, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$628, DW_AT_decl_line(0xac)
	.dwattr $C$DW$T$628, DW_AT_decl_column(0x14)

$C$DW$T$397	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$397, DW_AT_language(DW_LANG_C)
$C$DW$351	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$351, DW_AT_type(*$C$DW$T$3)
$C$DW$352	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$352, DW_AT_type(*$C$DW$T$396)
	.dwendtag $C$DW$T$397

$C$DW$T$398	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$398, DW_AT_type(*$C$DW$T$397)
	.dwattr $C$DW$T$398, DW_AT_address_class(0x20)
$C$DW$T$629	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_getStats_FxnT")
	.dwattr $C$DW$T$629, DW_AT_type(*$C$DW$T$398)
	.dwattr $C$DW$T$629, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$629, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$629, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$629, DW_AT_decl_column(0x14)

$C$DW$T$422	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$422, DW_AT_language(DW_LANG_C)
$C$DW$353	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$353, DW_AT_type(*$C$DW$T$419)
$C$DW$354	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$354, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$422

$C$DW$T$423	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$423, DW_AT_type(*$C$DW$T$422)
	.dwattr $C$DW$T$423, DW_AT_address_class(0x20)

$C$DW$T$433	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$433, DW_AT_language(DW_LANG_C)
$C$DW$355	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$355, DW_AT_type(*$C$DW$T$430)
$C$DW$356	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$356, DW_AT_type(*$C$DW$T$177)
$C$DW$357	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$357, DW_AT_type(*$C$DW$T$191)
	.dwendtag $C$DW$T$433

$C$DW$T$434	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$434, DW_AT_type(*$C$DW$T$433)
	.dwattr $C$DW$T$434, DW_AT_address_class(0x20)

$C$DW$T$437	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$437, DW_AT_language(DW_LANG_C)
$C$DW$358	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$358, DW_AT_type(*$C$DW$T$430)
$C$DW$359	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$359, DW_AT_type(*$C$DW$T$396)
	.dwendtag $C$DW$T$437

$C$DW$T$438	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$438, DW_AT_type(*$C$DW$T$437)
	.dwattr $C$DW$T$438, DW_AT_address_class(0x20)

$C$DW$T$471	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$471, DW_AT_language(DW_LANG_C)
$C$DW$360	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$360, DW_AT_type(*$C$DW$T$177)
	.dwendtag $C$DW$T$471

$C$DW$T$472	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$472, DW_AT_type(*$C$DW$T$471)
	.dwattr $C$DW$T$472, DW_AT_address_class(0x20)

$C$DW$T$641	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$641, DW_AT_language(DW_LANG_C)
$C$DW$361	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$361, DW_AT_type(*$C$DW$T$177)
$C$DW$362	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$362, DW_AT_type(*$C$DW$T$640)
$C$DW$363	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$363, DW_AT_type(*$C$DW$T$359)
	.dwendtag $C$DW$T$641

$C$DW$T$642	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$642, DW_AT_type(*$C$DW$T$641)
	.dwattr $C$DW$T$642, DW_AT_address_class(0x20)
$C$DW$T$643	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LoggerFxn0")
	.dwattr $C$DW$T$643, DW_AT_type(*$C$DW$T$642)
	.dwattr $C$DW$T$643, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$643, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$643, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$643, DW_AT_decl_column(0x14)
$C$DW$T$644	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerFxn0")
	.dwattr $C$DW$T$644, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$644, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$644, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$644, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$T$644, DW_AT_decl_column(0x26)
$C$DW$T$645	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerFxn0")
	.dwattr $C$DW$T$645, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$645, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$645, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$645, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$645, DW_AT_decl_column(0x26)
$C$DW$T$646	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerFxn0")
	.dwattr $C$DW$T$646, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$646, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$646, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$646, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$646, DW_AT_decl_column(0x26)
$C$DW$T$647	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerFxn0")
	.dwattr $C$DW$T$647, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$647, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$647, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$647, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$647, DW_AT_decl_column(0x26)
$C$DW$T$648	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerFxn0")
	.dwattr $C$DW$T$648, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$648, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$648, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$648, DW_AT_decl_line(0xe8)
	.dwattr $C$DW$T$648, DW_AT_decl_column(0x26)
$C$DW$T$649	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerFxn0")
	.dwattr $C$DW$T$649, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$649, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$649, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$649, DW_AT_decl_line(0x72)
	.dwattr $C$DW$T$649, DW_AT_decl_column(0x26)
$C$DW$T$650	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerFxn0")
	.dwattr $C$DW$T$650, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$650, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$650, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$650, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$650, DW_AT_decl_column(0x26)
$C$DW$T$651	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerFxn0")
	.dwattr $C$DW$T$651, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$651, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$651, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$651, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$651, DW_AT_decl_column(0x26)
$C$DW$T$652	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerFxn0")
	.dwattr $C$DW$T$652, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$652, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$652, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$652, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$T$652, DW_AT_decl_column(0x26)
$C$DW$T$653	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerFxn0")
	.dwattr $C$DW$T$653, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$653, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$653, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$653, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$653, DW_AT_decl_column(0x26)
$C$DW$T$654	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerFxn0")
	.dwattr $C$DW$T$654, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$654, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$654, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$654, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$654, DW_AT_decl_column(0x26)
$C$DW$T$655	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerFxn0")
	.dwattr $C$DW$T$655, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$655, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$655, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$655, DW_AT_decl_line(0xc3)
	.dwattr $C$DW$T$655, DW_AT_decl_column(0x26)
$C$DW$T$656	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerFxn0")
	.dwattr $C$DW$T$656, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$656, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$656, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$656, DW_AT_decl_line(0x93)
	.dwattr $C$DW$T$656, DW_AT_decl_column(0x26)
$C$DW$T$657	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerFxn0")
	.dwattr $C$DW$T$657, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$657, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$657, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$657, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$657, DW_AT_decl_column(0x26)
$C$DW$T$658	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerFxn0")
	.dwattr $C$DW$T$658, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$658, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$658, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$658, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$658, DW_AT_decl_column(0x26)
$C$DW$T$659	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerFxn0")
	.dwattr $C$DW$T$659, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$659, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$659, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$659, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$659, DW_AT_decl_column(0x26)
$C$DW$T$660	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerFxn0")
	.dwattr $C$DW$T$660, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$660, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$660, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$660, DW_AT_decl_line(0x67)
	.dwattr $C$DW$T$660, DW_AT_decl_column(0x26)
$C$DW$T$661	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerFxn0")
	.dwattr $C$DW$T$661, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$661, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$661, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$661, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$661, DW_AT_decl_column(0x26)
$C$DW$T$662	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerFxn0")
	.dwattr $C$DW$T$662, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$662, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$662, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$662, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$662, DW_AT_decl_column(0x26)
$C$DW$T$663	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerFxn0")
	.dwattr $C$DW$T$663, DW_AT_type(*$C$DW$T$643)
	.dwattr $C$DW$T$663, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$663, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$663, DW_AT_decl_line(0xf6)
	.dwattr $C$DW$T$663, DW_AT_decl_column(0x26)

$C$DW$T$664	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$664, DW_AT_language(DW_LANG_C)
$C$DW$364	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$364, DW_AT_type(*$C$DW$T$177)
$C$DW$365	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$365, DW_AT_type(*$C$DW$T$640)
$C$DW$366	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$366, DW_AT_type(*$C$DW$T$359)
$C$DW$367	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$367, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$664

$C$DW$T$665	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$665, DW_AT_type(*$C$DW$T$664)
	.dwattr $C$DW$T$665, DW_AT_address_class(0x20)
$C$DW$T$666	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LoggerFxn1")
	.dwattr $C$DW$T$666, DW_AT_type(*$C$DW$T$665)
	.dwattr $C$DW$T$666, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$666, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$666, DW_AT_decl_line(0x97)
	.dwattr $C$DW$T$666, DW_AT_decl_column(0x14)
$C$DW$T$667	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerFxn1")
	.dwattr $C$DW$T$667, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$667, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$667, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$667, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$667, DW_AT_decl_column(0x26)
$C$DW$T$668	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerFxn1")
	.dwattr $C$DW$T$668, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$668, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$668, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$668, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$668, DW_AT_decl_column(0x26)
$C$DW$T$669	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerFxn1")
	.dwattr $C$DW$T$669, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$669, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$669, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$669, DW_AT_decl_line(0x95)
	.dwattr $C$DW$T$669, DW_AT_decl_column(0x26)
$C$DW$T$670	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerFxn1")
	.dwattr $C$DW$T$670, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$670, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$670, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$670, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$670, DW_AT_decl_column(0x26)
$C$DW$T$671	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerFxn1")
	.dwattr $C$DW$T$671, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$671, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$671, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$671, DW_AT_decl_line(0xec)
	.dwattr $C$DW$T$671, DW_AT_decl_column(0x26)
$C$DW$T$672	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerFxn1")
	.dwattr $C$DW$T$672, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$672, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$672, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$672, DW_AT_decl_line(0x76)
	.dwattr $C$DW$T$672, DW_AT_decl_column(0x26)
$C$DW$T$673	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerFxn1")
	.dwattr $C$DW$T$673, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$673, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$673, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$673, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$673, DW_AT_decl_column(0x26)
$C$DW$T$674	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerFxn1")
	.dwattr $C$DW$T$674, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$674, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$674, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$674, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$674, DW_AT_decl_column(0x26)
$C$DW$T$675	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerFxn1")
	.dwattr $C$DW$T$675, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$675, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$675, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$675, DW_AT_decl_line(0xd4)
	.dwattr $C$DW$T$675, DW_AT_decl_column(0x26)
$C$DW$T$676	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerFxn1")
	.dwattr $C$DW$T$676, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$676, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$676, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$676, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$676, DW_AT_decl_column(0x26)
$C$DW$T$677	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerFxn1")
	.dwattr $C$DW$T$677, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$677, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$677, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$677, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$677, DW_AT_decl_column(0x26)
$C$DW$T$678	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerFxn1")
	.dwattr $C$DW$T$678, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$678, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$678, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$678, DW_AT_decl_line(0xc7)
	.dwattr $C$DW$T$678, DW_AT_decl_column(0x26)
$C$DW$T$679	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerFxn1")
	.dwattr $C$DW$T$679, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$679, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$679, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$679, DW_AT_decl_line(0x97)
	.dwattr $C$DW$T$679, DW_AT_decl_column(0x26)
$C$DW$T$680	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerFxn1")
	.dwattr $C$DW$T$680, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$680, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$680, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$680, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$680, DW_AT_decl_column(0x26)
$C$DW$T$681	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerFxn1")
	.dwattr $C$DW$T$681, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$681, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$681, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$681, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$681, DW_AT_decl_column(0x26)
$C$DW$T$682	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerFxn1")
	.dwattr $C$DW$T$682, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$682, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$682, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$682, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$682, DW_AT_decl_column(0x26)
$C$DW$T$683	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerFxn1")
	.dwattr $C$DW$T$683, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$683, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$683, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$683, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$T$683, DW_AT_decl_column(0x26)
$C$DW$T$684	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerFxn1")
	.dwattr $C$DW$T$684, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$684, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$684, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$684, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$684, DW_AT_decl_column(0x26)
$C$DW$T$685	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerFxn1")
	.dwattr $C$DW$T$685, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$685, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$685, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$685, DW_AT_decl_line(0x95)
	.dwattr $C$DW$T$685, DW_AT_decl_column(0x26)
$C$DW$T$686	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerFxn1")
	.dwattr $C$DW$T$686, DW_AT_type(*$C$DW$T$666)
	.dwattr $C$DW$T$686, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$686, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$686, DW_AT_decl_line(0xfa)
	.dwattr $C$DW$T$686, DW_AT_decl_column(0x26)

$C$DW$T$687	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$687, DW_AT_language(DW_LANG_C)
$C$DW$368	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$368, DW_AT_type(*$C$DW$T$177)
$C$DW$369	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$369, DW_AT_type(*$C$DW$T$640)
$C$DW$370	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$370, DW_AT_type(*$C$DW$T$359)
$C$DW$371	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$371, DW_AT_type(*$C$DW$T$133)
$C$DW$372	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$372, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$687

$C$DW$T$688	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$688, DW_AT_type(*$C$DW$T$687)
	.dwattr $C$DW$T$688, DW_AT_address_class(0x20)
$C$DW$T$689	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LoggerFxn2")
	.dwattr $C$DW$T$689, DW_AT_type(*$C$DW$T$688)
	.dwattr $C$DW$T$689, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$689, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$689, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$689, DW_AT_decl_column(0x14)
$C$DW$T$690	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerFxn2")
	.dwattr $C$DW$T$690, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$690, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$690, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$690, DW_AT_decl_line(0xac)
	.dwattr $C$DW$T$690, DW_AT_decl_column(0x26)
$C$DW$T$691	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerFxn2")
	.dwattr $C$DW$T$691, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$691, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$691, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$691, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$691, DW_AT_decl_column(0x26)
$C$DW$T$692	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerFxn2")
	.dwattr $C$DW$T$692, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$692, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$692, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$692, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$692, DW_AT_decl_column(0x26)
$C$DW$T$693	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerFxn2")
	.dwattr $C$DW$T$693, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$693, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$693, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$693, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$693, DW_AT_decl_column(0x26)
$C$DW$T$694	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerFxn2")
	.dwattr $C$DW$T$694, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$694, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$694, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$694, DW_AT_decl_line(0xf0)
	.dwattr $C$DW$T$694, DW_AT_decl_column(0x26)
$C$DW$T$695	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerFxn2")
	.dwattr $C$DW$T$695, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$695, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$695, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$695, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$695, DW_AT_decl_column(0x26)
$C$DW$T$696	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerFxn2")
	.dwattr $C$DW$T$696, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$696, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$696, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$696, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$T$696, DW_AT_decl_column(0x26)
$C$DW$T$697	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerFxn2")
	.dwattr $C$DW$T$697, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$697, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$697, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$697, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$T$697, DW_AT_decl_column(0x26)
$C$DW$T$698	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerFxn2")
	.dwattr $C$DW$T$698, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$698, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$698, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$698, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$T$698, DW_AT_decl_column(0x26)
$C$DW$T$699	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerFxn2")
	.dwattr $C$DW$T$699, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$699, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$699, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$699, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$699, DW_AT_decl_column(0x26)
$C$DW$T$700	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerFxn2")
	.dwattr $C$DW$T$700, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$700, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$700, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$700, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$700, DW_AT_decl_column(0x26)
$C$DW$T$701	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerFxn2")
	.dwattr $C$DW$T$701, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$701, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$701, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$701, DW_AT_decl_line(0xcb)
	.dwattr $C$DW$T$701, DW_AT_decl_column(0x26)
$C$DW$T$702	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerFxn2")
	.dwattr $C$DW$T$702, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$702, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$702, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$702, DW_AT_decl_line(0x9b)
	.dwattr $C$DW$T$702, DW_AT_decl_column(0x26)
$C$DW$T$703	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerFxn2")
	.dwattr $C$DW$T$703, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$703, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$703, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$703, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$703, DW_AT_decl_column(0x26)
$C$DW$T$704	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerFxn2")
	.dwattr $C$DW$T$704, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$704, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$704, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$704, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$704, DW_AT_decl_column(0x26)
$C$DW$T$705	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerFxn2")
	.dwattr $C$DW$T$705, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$705, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$705, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$705, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$705, DW_AT_decl_column(0x26)
$C$DW$T$706	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerFxn2")
	.dwattr $C$DW$T$706, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$706, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$706, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$706, DW_AT_decl_line(0x6f)
	.dwattr $C$DW$T$706, DW_AT_decl_column(0x26)
$C$DW$T$707	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerFxn2")
	.dwattr $C$DW$T$707, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$707, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$707, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$707, DW_AT_decl_line(0x82)
	.dwattr $C$DW$T$707, DW_AT_decl_column(0x26)
$C$DW$T$708	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerFxn2")
	.dwattr $C$DW$T$708, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$708, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$708, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$708, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$708, DW_AT_decl_column(0x26)
$C$DW$T$709	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerFxn2")
	.dwattr $C$DW$T$709, DW_AT_type(*$C$DW$T$689)
	.dwattr $C$DW$T$709, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$709, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$709, DW_AT_decl_line(0xfe)
	.dwattr $C$DW$T$709, DW_AT_decl_column(0x26)

$C$DW$T$710	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$710, DW_AT_language(DW_LANG_C)
$C$DW$373	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$373, DW_AT_type(*$C$DW$T$177)
$C$DW$374	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$374, DW_AT_type(*$C$DW$T$640)
$C$DW$375	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$375, DW_AT_type(*$C$DW$T$359)
$C$DW$376	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$376, DW_AT_type(*$C$DW$T$133)
$C$DW$377	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$377, DW_AT_type(*$C$DW$T$133)
$C$DW$378	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$378, DW_AT_type(*$C$DW$T$133)
$C$DW$379	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$379, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$710

$C$DW$T$711	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$711, DW_AT_type(*$C$DW$T$710)
	.dwattr $C$DW$T$711, DW_AT_address_class(0x20)
$C$DW$T$712	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LoggerFxn4")
	.dwattr $C$DW$T$712, DW_AT_type(*$C$DW$T$711)
	.dwattr $C$DW$T$712, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$712, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$712, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$712, DW_AT_decl_column(0x14)
$C$DW$T$713	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerFxn4")
	.dwattr $C$DW$T$713, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$713, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$713, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$713, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$T$713, DW_AT_decl_column(0x26)
$C$DW$T$714	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerFxn4")
	.dwattr $C$DW$T$714, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$714, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$714, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$714, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$714, DW_AT_decl_column(0x26)
$C$DW$T$715	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerFxn4")
	.dwattr $C$DW$T$715, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$715, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$715, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$715, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$715, DW_AT_decl_column(0x26)
$C$DW$T$716	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerFxn4")
	.dwattr $C$DW$T$716, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$716, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$716, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$716, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$716, DW_AT_decl_column(0x26)
$C$DW$T$717	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerFxn4")
	.dwattr $C$DW$T$717, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$717, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$717, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$717, DW_AT_decl_line(0xf4)
	.dwattr $C$DW$T$717, DW_AT_decl_column(0x26)
$C$DW$T$718	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerFxn4")
	.dwattr $C$DW$T$718, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$718, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$718, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$718, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$718, DW_AT_decl_column(0x26)
$C$DW$T$719	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerFxn4")
	.dwattr $C$DW$T$719, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$719, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$719, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$719, DW_AT_decl_line(0xa2)
	.dwattr $C$DW$T$719, DW_AT_decl_column(0x26)
$C$DW$T$720	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerFxn4")
	.dwattr $C$DW$T$720, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$720, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$720, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$720, DW_AT_decl_line(0xa2)
	.dwattr $C$DW$T$720, DW_AT_decl_column(0x26)
$C$DW$T$721	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerFxn4")
	.dwattr $C$DW$T$721, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$721, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$721, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$721, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$721, DW_AT_decl_column(0x26)
$C$DW$T$722	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerFxn4")
	.dwattr $C$DW$T$722, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$722, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$722, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$722, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$722, DW_AT_decl_column(0x26)
$C$DW$T$723	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerFxn4")
	.dwattr $C$DW$T$723, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$723, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$723, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$723, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$723, DW_AT_decl_column(0x26)
$C$DW$T$724	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerFxn4")
	.dwattr $C$DW$T$724, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$724, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$724, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$724, DW_AT_decl_line(0xcf)
	.dwattr $C$DW$T$724, DW_AT_decl_column(0x26)
$C$DW$T$725	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerFxn4")
	.dwattr $C$DW$T$725, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$725, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$725, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$725, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$T$725, DW_AT_decl_column(0x26)
$C$DW$T$726	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerFxn4")
	.dwattr $C$DW$T$726, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$726, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$726, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$726, DW_AT_decl_line(0x90)
	.dwattr $C$DW$T$726, DW_AT_decl_column(0x26)
$C$DW$T$727	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerFxn4")
	.dwattr $C$DW$T$727, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$727, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$727, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$727, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$727, DW_AT_decl_column(0x26)
$C$DW$T$728	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerFxn4")
	.dwattr $C$DW$T$728, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$728, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$728, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$728, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$728, DW_AT_decl_column(0x26)
$C$DW$T$729	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerFxn4")
	.dwattr $C$DW$T$729, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$729, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$729, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$729, DW_AT_decl_line(0x73)
	.dwattr $C$DW$T$729, DW_AT_decl_column(0x26)
$C$DW$T$730	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerFxn4")
	.dwattr $C$DW$T$730, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$730, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$730, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$730, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$730, DW_AT_decl_column(0x26)
$C$DW$T$731	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerFxn4")
	.dwattr $C$DW$T$731, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$731, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$731, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$731, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$731, DW_AT_decl_column(0x26)
$C$DW$T$732	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerFxn4")
	.dwattr $C$DW$T$732, DW_AT_type(*$C$DW$T$712)
	.dwattr $C$DW$T$732, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$732, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$732, DW_AT_decl_line(0x102)
	.dwattr $C$DW$T$732, DW_AT_decl_column(0x26)

$C$DW$T$733	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$733, DW_AT_language(DW_LANG_C)
$C$DW$380	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$380, DW_AT_type(*$C$DW$T$177)
$C$DW$381	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$381, DW_AT_type(*$C$DW$T$640)
$C$DW$382	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$382, DW_AT_type(*$C$DW$T$359)
$C$DW$383	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$383, DW_AT_type(*$C$DW$T$133)
$C$DW$384	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$384, DW_AT_type(*$C$DW$T$133)
$C$DW$385	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$385, DW_AT_type(*$C$DW$T$133)
$C$DW$386	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$386, DW_AT_type(*$C$DW$T$133)
$C$DW$387	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$387, DW_AT_type(*$C$DW$T$133)
$C$DW$388	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$388, DW_AT_type(*$C$DW$T$133)
$C$DW$389	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$389, DW_AT_type(*$C$DW$T$133)
$C$DW$390	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$390, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$733

$C$DW$T$734	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$734, DW_AT_type(*$C$DW$T$733)
	.dwattr $C$DW$T$734, DW_AT_address_class(0x20)
$C$DW$T$735	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LoggerFxn8")
	.dwattr $C$DW$T$735, DW_AT_type(*$C$DW$T$734)
	.dwattr $C$DW$T$735, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$735, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$735, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$735, DW_AT_decl_column(0x14)
$C$DW$T$736	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerFxn8")
	.dwattr $C$DW$T$736, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$736, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$736, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$736, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$T$736, DW_AT_decl_column(0x26)
$C$DW$T$737	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerFxn8")
	.dwattr $C$DW$T$737, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$737, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$737, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$737, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$737, DW_AT_decl_column(0x26)
$C$DW$T$738	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerFxn8")
	.dwattr $C$DW$T$738, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$738, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$738, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$738, DW_AT_decl_line(0xa1)
	.dwattr $C$DW$T$738, DW_AT_decl_column(0x26)
$C$DW$T$739	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerFxn8")
	.dwattr $C$DW$T$739, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$739, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$739, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$739, DW_AT_decl_line(0x95)
	.dwattr $C$DW$T$739, DW_AT_decl_column(0x26)
$C$DW$T$740	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerFxn8")
	.dwattr $C$DW$T$740, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$740, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$740, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$740, DW_AT_decl_line(0xf8)
	.dwattr $C$DW$T$740, DW_AT_decl_column(0x26)
$C$DW$T$741	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerFxn8")
	.dwattr $C$DW$T$741, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$741, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$741, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$741, DW_AT_decl_line(0x82)
	.dwattr $C$DW$T$741, DW_AT_decl_column(0x26)
$C$DW$T$742	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerFxn8")
	.dwattr $C$DW$T$742, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$742, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$742, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$742, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$742, DW_AT_decl_column(0x26)
$C$DW$T$743	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerFxn8")
	.dwattr $C$DW$T$743, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$743, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$743, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$743, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$743, DW_AT_decl_column(0x26)
$C$DW$T$744	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerFxn8")
	.dwattr $C$DW$T$744, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$744, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$744, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$744, DW_AT_decl_line(0xe0)
	.dwattr $C$DW$T$744, DW_AT_decl_column(0x26)
$C$DW$T$745	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerFxn8")
	.dwattr $C$DW$T$745, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$745, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$745, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$745, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$745, DW_AT_decl_column(0x26)
$C$DW$T$746	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerFxn8")
	.dwattr $C$DW$T$746, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$746, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$746, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$746, DW_AT_decl_line(0x80)
	.dwattr $C$DW$T$746, DW_AT_decl_column(0x26)
$C$DW$T$747	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerFxn8")
	.dwattr $C$DW$T$747, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$747, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$747, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$747, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$747, DW_AT_decl_column(0x26)
$C$DW$T$748	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerFxn8")
	.dwattr $C$DW$T$748, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$748, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$748, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$748, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$748, DW_AT_decl_column(0x26)
$C$DW$T$749	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerFxn8")
	.dwattr $C$DW$T$749, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$749, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$749, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$749, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$749, DW_AT_decl_column(0x26)
$C$DW$T$750	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerFxn8")
	.dwattr $C$DW$T$750, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$750, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$750, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$750, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$750, DW_AT_decl_column(0x26)
$C$DW$T$751	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerFxn8")
	.dwattr $C$DW$T$751, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$751, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$751, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$751, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$751, DW_AT_decl_column(0x26)
$C$DW$T$752	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerFxn8")
	.dwattr $C$DW$T$752, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$752, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$752, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$752, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$752, DW_AT_decl_column(0x26)
$C$DW$T$753	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerFxn8")
	.dwattr $C$DW$T$753, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$753, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$753, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$753, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$753, DW_AT_decl_column(0x26)
$C$DW$T$754	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerFxn8")
	.dwattr $C$DW$T$754, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$754, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$754, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$754, DW_AT_decl_line(0xa1)
	.dwattr $C$DW$T$754, DW_AT_decl_column(0x26)
$C$DW$T$755	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerFxn8")
	.dwattr $C$DW$T$755, DW_AT_type(*$C$DW$T$735)
	.dwattr $C$DW$T$755, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$755, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$755, DW_AT_decl_line(0x106)
	.dwattr $C$DW$T$755, DW_AT_decl_column(0x26)

$C$DW$T$756	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$756, DW_AT_language(DW_LANG_C)
$C$DW$391	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$391, DW_AT_type(*$C$DW$T$182)
	.dwendtag $C$DW$T$756

$C$DW$T$757	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$757, DW_AT_type(*$C$DW$T$756)
	.dwattr $C$DW$T$757, DW_AT_address_class(0x20)
$C$DW$T$758	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_installedErrorHook")
	.dwattr $C$DW$T$758, DW_AT_type(*$C$DW$T$757)
	.dwattr $C$DW$T$758, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$758, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$758, DW_AT_decl_line(0x11f)
	.dwattr $C$DW$T$758, DW_AT_decl_column(0x14)
$C$DW$T$759	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_HookFxn")
	.dwattr $C$DW$T$759, DW_AT_type(*$C$DW$T$757)
	.dwattr $C$DW$T$759, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$759, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$759, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$759, DW_AT_decl_column(0x14)
$C$DW$T$760	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_raiseHook")
	.dwattr $C$DW$T$760, DW_AT_type(*$C$DW$T$759)
	.dwattr $C$DW$T$760, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$760, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$760, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$760, DW_AT_decl_column(0x23)

$C$DW$T$761	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$761, DW_AT_language(DW_LANG_C)
$C$DW$392	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$392, DW_AT_type(*$C$DW$T$182)
$C$DW$393	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$393, DW_AT_type(*$C$DW$T$359)
$C$DW$394	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$394, DW_AT_type(*$C$DW$T$449)
$C$DW$395	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$395, DW_AT_type(*$C$DW$T$148)
$C$DW$396	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$396, DW_AT_type(*$C$DW$T$365)
$C$DW$397	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$397, DW_AT_type(*$C$DW$T$133)
$C$DW$398	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$398, DW_AT_type(*$C$DW$T$133)
	.dwendtag $C$DW$T$761

$C$DW$T$762	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$762, DW_AT_type(*$C$DW$T$761)
	.dwattr $C$DW$T$762, DW_AT_address_class(0x20)
$C$DW$T$763	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_PolicyFxn")
	.dwattr $C$DW$T$763, DW_AT_type(*$C$DW$T$762)
	.dwattr $C$DW$T$763, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$763, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$763, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$763, DW_AT_decl_column(0x14)
$C$DW$T$764	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_policyFxn")
	.dwattr $C$DW$T$764, DW_AT_type(*$C$DW$T$763)
	.dwattr $C$DW$T$764, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$764, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$764, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$T$764, DW_AT_decl_column(0x25)

$C$DW$T$769	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$769, DW_AT_language(DW_LANG_C)
$C$DW$399	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$399, DW_AT_type(*$C$DW$T$765)
$C$DW$400	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$400, DW_AT_type(*$C$DW$T$768)
$C$DW$401	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$401, DW_AT_type(*$C$DW$T$177)
	.dwendtag $C$DW$T$769

$C$DW$T$770	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$770, DW_AT_type(*$C$DW$T$769)
	.dwattr $C$DW$T$770, DW_AT_address_class(0x20)
$C$DW$T$771	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_VisitRopeFxn")
	.dwattr $C$DW$T$771, DW_AT_type(*$C$DW$T$770)
	.dwattr $C$DW$T$771, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$771, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$771, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$771, DW_AT_decl_column(0x14)
$C$DW$T$772	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_visitRopeFxn")
	.dwattr $C$DW$T$772, DW_AT_type(*$C$DW$T$771)
	.dwattr $C$DW$T$772, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$772, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$772, DW_AT_decl_line(0x106)
	.dwattr $C$DW$T$772, DW_AT_decl_column(0x27)

$C$DW$T$774	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$774, DW_AT_language(DW_LANG_C)
$C$DW$402	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$402, DW_AT_type(*$C$DW$T$765)
$C$DW$403	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$403, DW_AT_type(*$C$DW$T$768)
$C$DW$404	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$404, DW_AT_type(*$C$DW$T$177)
$C$DW$405	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$405, DW_AT_type(*$C$DW$T$773)
	.dwendtag $C$DW$T$774

$C$DW$T$775	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$775, DW_AT_type(*$C$DW$T$774)
	.dwattr $C$DW$T$775, DW_AT_address_class(0x20)
$C$DW$T$776	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_VisitRopeFxn2")
	.dwattr $C$DW$T$776, DW_AT_type(*$C$DW$T$775)
	.dwattr $C$DW$T$776, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$776, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$776, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$776, DW_AT_decl_column(0x14)
$C$DW$T$777	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_visitRopeFxn2")
	.dwattr $C$DW$T$777, DW_AT_type(*$C$DW$T$776)
	.dwattr $C$DW$T$777, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$777, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$777, DW_AT_decl_line(0x10b)
	.dwattr $C$DW$T$777, DW_AT_decl_column(0x28)

$C$DW$T$778	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$778, DW_AT_language(DW_LANG_C)
$C$DW$406	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$406, DW_AT_type(*$C$DW$T$196)
	.dwendtag $C$DW$T$778

$C$DW$T$779	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$779, DW_AT_type(*$C$DW$T$778)
	.dwattr $C$DW$T$779, DW_AT_address_class(0x20)
$C$DW$T$780	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_taskRestore")
	.dwattr $C$DW$T$780, DW_AT_type(*$C$DW$T$779)
	.dwattr $C$DW$T$780, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$780, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$780, DW_AT_decl_line(0xee)
	.dwattr $C$DW$T$780, DW_AT_decl_column(0x14)

$C$DW$T$781	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$781, DW_AT_language(DW_LANG_C)
$C$DW$407	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$407, DW_AT_type(*$C$DW$T$295)
$C$DW$408	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$408, DW_AT_type(*$C$DW$T$196)
	.dwendtag $C$DW$T$781

$C$DW$T$782	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$782, DW_AT_type(*$C$DW$T$781)
	.dwattr $C$DW$T$782, DW_AT_address_class(0x20)
$C$DW$T$783	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_eventPost")
	.dwattr $C$DW$T$783, DW_AT_type(*$C$DW$T$782)
	.dwattr $C$DW$T$783, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$783, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$783, DW_AT_decl_line(0xf4)
	.dwattr $C$DW$T$783, DW_AT_decl_column(0x14)

$C$DW$T$784	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$784, DW_AT_language(DW_LANG_C)
$C$DW$409	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$409, DW_AT_type(*$C$DW$T$295)
$C$DW$410	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$410, DW_AT_type(*$C$DW$T$196)
$C$DW$411	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$411, DW_AT_type(*$C$DW$T$196)
	.dwendtag $C$DW$T$784

$C$DW$T$785	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$785, DW_AT_type(*$C$DW$T$784)
	.dwattr $C$DW$T$785, DW_AT_address_class(0x20)
$C$DW$T$786	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_eventSync")
	.dwattr $C$DW$T$786, DW_AT_type(*$C$DW$T$785)
	.dwattr $C$DW$T$786, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$786, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$786, DW_AT_decl_line(0xf9)
	.dwattr $C$DW$T$786, DW_AT_decl_column(0x14)

$C$DW$T$789	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$789, DW_AT_language(DW_LANG_C)
$C$DW$412	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$412, DW_AT_type(*$C$DW$T$787)
$C$DW$413	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$413, DW_AT_type(*$C$DW$T$788)
	.dwendtag $C$DW$T$789

$C$DW$T$790	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$790, DW_AT_type(*$C$DW$T$789)
	.dwattr $C$DW$T$790, DW_AT_address_class(0x20)
$C$DW$T$791	.dwtag  DW_TAG_typedef, DW_AT_name("CyaSSL_Logging_cb")
	.dwattr $C$DW$T$791, DW_AT_type(*$C$DW$T$790)
	.dwattr $C$DW$T$791, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$791, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/logging.h")
	.dwattr $C$DW$T$791, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$T$791, DW_AT_decl_column(0x10)
$C$DW$T$4	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$4, DW_AT_encoding(DW_ATE_boolean)
	.dwattr $C$DW$T$4, DW_AT_name("bool")
	.dwattr $C$DW$T$4, DW_AT_byte_size(0x01)
$C$DW$T$5	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$5, DW_AT_encoding(DW_ATE_signed_char)
	.dwattr $C$DW$T$5, DW_AT_name("signed char")
	.dwattr $C$DW$T$5, DW_AT_byte_size(0x01)
$C$DW$T$792	.dwtag  DW_TAG_typedef, DW_AT_name("int8_t")
	.dwattr $C$DW$T$792, DW_AT_type(*$C$DW$T$5)
	.dwattr $C$DW$T$792, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$792, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$792, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$T$792, DW_AT_decl_column(0x1d)
$C$DW$T$793	.dwtag  DW_TAG_typedef, DW_AT_name("int_least8_t")
	.dwattr $C$DW$T$793, DW_AT_type(*$C$DW$T$792)
	.dwattr $C$DW$T$793, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$793, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$793, DW_AT_decl_line(0x37)
	.dwattr $C$DW$T$793, DW_AT_decl_column(0x17)
$C$DW$T$794	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Int8")
	.dwattr $C$DW$T$794, DW_AT_type(*$C$DW$T$793)
	.dwattr $C$DW$T$794, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$794, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$794, DW_AT_decl_line(0x60)
	.dwattr $C$DW$T$794, DW_AT_decl_column(0x19)
$C$DW$T$795	.dwtag  DW_TAG_typedef, DW_AT_name("Int8")
	.dwattr $C$DW$T$795, DW_AT_type(*$C$DW$T$794)
	.dwattr $C$DW$T$795, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$795, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$795, DW_AT_decl_line(0xe6)
	.dwattr $C$DW$T$795, DW_AT_decl_column(0x19)
$C$DW$T$6	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$6, DW_AT_encoding(DW_ATE_unsigned_char)
	.dwattr $C$DW$T$6, DW_AT_name("unsigned char")
	.dwattr $C$DW$T$6, DW_AT_byte_size(0x01)
$C$DW$T$796	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$796, DW_AT_type(*$C$DW$T$6)
$C$DW$T$797	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$797, DW_AT_type(*$C$DW$T$796)
	.dwattr $C$DW$T$797, DW_AT_address_class(0x20)
$C$DW$T$799	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$799, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$799, DW_AT_address_class(0x20)
$C$DW$T$634	.dwtag  DW_TAG_typedef, DW_AT_name("byte")
	.dwattr $C$DW$T$634, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$634, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$634, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$634, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$T$634, DW_AT_decl_column(0x20)
$C$DW$T$637	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$637, DW_AT_type(*$C$DW$T$634)
	.dwattr $C$DW$T$637, DW_AT_address_class(0x20)
$C$DW$T$801	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$801, DW_AT_type(*$C$DW$T$637)
$C$DW$T$635	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$635, DW_AT_type(*$C$DW$T$634)
$C$DW$T$636	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$636, DW_AT_type(*$C$DW$T$635)
	.dwattr $C$DW$T$636, DW_AT_address_class(0x20)
$C$DW$T$802	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$802, DW_AT_type(*$C$DW$T$636)
$C$DW$T$803	.dwtag  DW_TAG_typedef, DW_AT_name("uint8_t")
	.dwattr $C$DW$T$803, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$803, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$803, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$803, DW_AT_decl_line(0x2b)
	.dwattr $C$DW$T$803, DW_AT_decl_column(0x1c)
$C$DW$T$804	.dwtag  DW_TAG_typedef, DW_AT_name("uint_least8_t")
	.dwattr $C$DW$T$804, DW_AT_type(*$C$DW$T$803)
	.dwattr $C$DW$T$804, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$804, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$804, DW_AT_decl_line(0x38)
	.dwattr $C$DW$T$804, DW_AT_decl_column(0x16)
$C$DW$T$805	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UInt8")
	.dwattr $C$DW$T$805, DW_AT_type(*$C$DW$T$804)
	.dwattr $C$DW$T$805, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$805, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$805, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$805, DW_AT_decl_column(0x19)
$C$DW$T$806	.dwtag  DW_TAG_typedef, DW_AT_name("UInt8")
	.dwattr $C$DW$T$806, DW_AT_type(*$C$DW$T$805)
	.dwattr $C$DW$T$806, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$806, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$806, DW_AT_decl_line(0xee)
	.dwattr $C$DW$T$806, DW_AT_decl_column(0x19)
$C$DW$T$807	.dwtag  DW_TAG_typedef, DW_AT_name("Uint8")
	.dwattr $C$DW$T$807, DW_AT_type(*$C$DW$T$805)
	.dwattr $C$DW$T$807, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$807, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$807, DW_AT_decl_line(0xfb)
	.dwattr $C$DW$T$807, DW_AT_decl_column(0x19)
$C$DW$T$808	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Bits8")
	.dwattr $C$DW$T$808, DW_AT_type(*$C$DW$T$803)
	.dwattr $C$DW$T$808, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$808, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$808, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$808, DW_AT_decl_column(0x19)
$C$DW$T$809	.dwtag  DW_TAG_typedef, DW_AT_name("Bits8")
	.dwattr $C$DW$T$809, DW_AT_type(*$C$DW$T$808)
	.dwattr $C$DW$T$809, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$809, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$809, DW_AT_decl_line(0x10f)
	.dwattr $C$DW$T$809, DW_AT_decl_column(0x19)
$C$DW$T$478	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UChar")
	.dwattr $C$DW$T$478, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$478, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$478, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$478, DW_AT_decl_line(0x1e)
	.dwattr $C$DW$T$478, DW_AT_decl_column(0x19)
$C$DW$T$810	.dwtag  DW_TAG_typedef, DW_AT_name("UChar")
	.dwattr $C$DW$T$810, DW_AT_type(*$C$DW$T$478)
	.dwattr $C$DW$T$810, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$810, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$810, DW_AT_decl_line(0xd4)
	.dwattr $C$DW$T$810, DW_AT_decl_column(0x19)
$C$DW$T$479	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$479, DW_AT_type(*$C$DW$T$478)
$C$DW$T$480	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$480, DW_AT_type(*$C$DW$T$479)
	.dwattr $C$DW$T$480, DW_AT_address_class(0x20)
$C$DW$T$7	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$7, DW_AT_encoding(DW_ATE_signed_char)
	.dwattr $C$DW$T$7, DW_AT_name("wchar_t")
	.dwattr $C$DW$T$7, DW_AT_byte_size(0x02)
$C$DW$T$8	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$8, DW_AT_encoding(DW_ATE_signed)
	.dwattr $C$DW$T$8, DW_AT_name("short")
	.dwattr $C$DW$T$8, DW_AT_byte_size(0x02)
$C$DW$T$811	.dwtag  DW_TAG_typedef, DW_AT_name("int16_t")
	.dwattr $C$DW$T$811, DW_AT_type(*$C$DW$T$8)
	.dwattr $C$DW$T$811, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$811, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$811, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$T$811, DW_AT_decl_column(0x1d)
$C$DW$T$812	.dwtag  DW_TAG_typedef, DW_AT_name("int_least16_t")
	.dwattr $C$DW$T$812, DW_AT_type(*$C$DW$T$811)
	.dwattr $C$DW$T$812, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$812, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$812, DW_AT_decl_line(0x3a)
	.dwattr $C$DW$T$812, DW_AT_decl_column(0x17)
$C$DW$T$813	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Int16")
	.dwattr $C$DW$T$813, DW_AT_type(*$C$DW$T$812)
	.dwattr $C$DW$T$813, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$813, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$813, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$813, DW_AT_decl_column(0x19)
$C$DW$T$814	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_charCnt")
	.dwattr $C$DW$T$814, DW_AT_type(*$C$DW$T$813)
	.dwattr $C$DW$T$814, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$814, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$814, DW_AT_decl_line(0xe5)
	.dwattr $C$DW$T$814, DW_AT_decl_column(0x13)
$C$DW$T$815	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_nodeCnt")
	.dwattr $C$DW$T$815, DW_AT_type(*$C$DW$T$813)
	.dwattr $C$DW$T$815, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$815, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$815, DW_AT_decl_line(0xee)
	.dwattr $C$DW$T$815, DW_AT_decl_column(0x13)
$C$DW$T$816	.dwtag  DW_TAG_typedef, DW_AT_name("Int16")
	.dwattr $C$DW$T$816, DW_AT_type(*$C$DW$T$813)
	.dwattr $C$DW$T$816, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$816, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$816, DW_AT_decl_line(0xe7)
	.dwattr $C$DW$T$816, DW_AT_decl_column(0x19)
$C$DW$T$817	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Short")
	.dwattr $C$DW$T$817, DW_AT_type(*$C$DW$T$8)
	.dwattr $C$DW$T$817, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$817, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$817, DW_AT_decl_line(0x1f)
	.dwattr $C$DW$T$817, DW_AT_decl_column(0x19)
$C$DW$T$818	.dwtag  DW_TAG_typedef, DW_AT_name("Short")
	.dwattr $C$DW$T$818, DW_AT_type(*$C$DW$T$817)
	.dwattr $C$DW$T$818, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$818, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$818, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$818, DW_AT_decl_column(0x19)
$C$DW$T$9	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$9, DW_AT_encoding(DW_ATE_unsigned)
	.dwattr $C$DW$T$9, DW_AT_name("unsigned short")
	.dwattr $C$DW$T$9, DW_AT_byte_size(0x02)
$C$DW$T$302	.dwtag  DW_TAG_typedef, DW_AT_name("uint16_t")
	.dwattr $C$DW$T$302, DW_AT_type(*$C$DW$T$9)
	.dwattr $C$DW$T$302, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$302, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$302, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$T$302, DW_AT_decl_column(0x1c)
$C$DW$T$303	.dwtag  DW_TAG_typedef, DW_AT_name("uint_least16_t")
	.dwattr $C$DW$T$303, DW_AT_type(*$C$DW$T$302)
	.dwattr $C$DW$T$303, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$303, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$303, DW_AT_decl_line(0x3b)
	.dwattr $C$DW$T$303, DW_AT_decl_column(0x16)
$C$DW$T$304	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UInt16")
	.dwattr $C$DW$T$304, DW_AT_type(*$C$DW$T$303)
	.dwattr $C$DW$T$304, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$304, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$304, DW_AT_decl_line(0x63)
	.dwattr $C$DW$T$304, DW_AT_decl_column(0x19)
$C$DW$T$819	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_maxDepth")
	.dwattr $C$DW$T$819, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$T$819, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$819, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$819, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$T$819, DW_AT_decl_column(0x14)
$C$DW$T$820	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_registryModsLastId")
	.dwattr $C$DW$T$820, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$T$820, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$820, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$820, DW_AT_decl_line(0x100)
	.dwattr $C$DW$T$820, DW_AT_decl_column(0x14)
$C$DW$T$821	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_unnamedModsLastId")
	.dwattr $C$DW$T$821, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$T$821, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$821, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$821, DW_AT_decl_line(0xf7)
	.dwattr $C$DW$T$821, DW_AT_decl_column(0x14)
$C$DW$T$822	.dwtag  DW_TAG_typedef, DW_AT_name("UInt16")
	.dwattr $C$DW$T$822, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$T$822, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$822, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$822, DW_AT_decl_line(0xef)
	.dwattr $C$DW$T$822, DW_AT_decl_column(0x19)
$C$DW$T$823	.dwtag  DW_TAG_typedef, DW_AT_name("Uint16")
	.dwattr $C$DW$T$823, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$T$823, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$823, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$823, DW_AT_decl_line(0xfc)
	.dwattr $C$DW$T$823, DW_AT_decl_column(0x19)
$C$DW$T$305	.dwtag  DW_TAG_volatile_type
	.dwattr $C$DW$T$305, DW_AT_type(*$C$DW$T$304)
$C$DW$T$358	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Bits16")
	.dwattr $C$DW$T$358, DW_AT_type(*$C$DW$T$302)
	.dwattr $C$DW$T$358, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$358, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$358, DW_AT_decl_line(0x80)
	.dwattr $C$DW$T$358, DW_AT_decl_column(0x19)
$C$DW$T$824	.dwtag  DW_TAG_typedef, DW_AT_name("Bits16")
	.dwattr $C$DW$T$824, DW_AT_type(*$C$DW$T$358)
	.dwattr $C$DW$T$824, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$824, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$824, DW_AT_decl_line(0x113)
	.dwattr $C$DW$T$824, DW_AT_decl_column(0x19)
$C$DW$T$825	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$825, DW_AT_type(*$C$DW$T$358)
	.dwattr $C$DW$T$825, DW_AT_address_class(0x20)
$C$DW$T$826	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__diagsMask")
	.dwattr $C$DW$T$826, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$826, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$826, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$826, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$826, DW_AT_decl_column(0x15)
$C$DW$T$827	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__diagsMask")
	.dwattr $C$DW$T$827, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$827, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$827, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$827, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$827, DW_AT_decl_column(0x15)
$C$DW$T$828	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__diagsMask")
	.dwattr $C$DW$T$828, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$828, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$828, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$828, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$828, DW_AT_decl_column(0x15)
$C$DW$T$829	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__diagsMask")
	.dwattr $C$DW$T$829, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$829, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$829, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$829, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$829, DW_AT_decl_column(0x15)
$C$DW$T$830	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__diagsMask")
	.dwattr $C$DW$T$830, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$830, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$830, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$830, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$T$830, DW_AT_decl_column(0x15)
$C$DW$T$831	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__diagsMask")
	.dwattr $C$DW$T$831, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$831, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$831, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$831, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$831, DW_AT_decl_column(0x15)
$C$DW$T$832	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__diagsMask")
	.dwattr $C$DW$T$832, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$832, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$832, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$832, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$832, DW_AT_decl_column(0x15)
$C$DW$T$833	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__diagsMask")
	.dwattr $C$DW$T$833, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$833, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$833, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$833, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$833, DW_AT_decl_column(0x15)
$C$DW$T$834	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__diagsMask")
	.dwattr $C$DW$T$834, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$834, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$834, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$834, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$T$834, DW_AT_decl_column(0x15)
$C$DW$T$835	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__diagsMask")
	.dwattr $C$DW$T$835, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$835, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$835, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$835, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$835, DW_AT_decl_column(0x15)
$C$DW$T$836	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__diagsMask")
	.dwattr $C$DW$T$836, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$836, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$836, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$836, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$836, DW_AT_decl_column(0x15)
$C$DW$T$837	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__diagsMask")
	.dwattr $C$DW$T$837, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$837, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$837, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$837, DW_AT_decl_line(0xab)
	.dwattr $C$DW$T$837, DW_AT_decl_column(0x15)
$C$DW$T$838	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__diagsMask")
	.dwattr $C$DW$T$838, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$838, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$838, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$838, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$838, DW_AT_decl_column(0x15)
$C$DW$T$839	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__diagsMask")
	.dwattr $C$DW$T$839, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$839, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$839, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$839, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$839, DW_AT_decl_column(0x15)
$C$DW$T$840	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__diagsMask")
	.dwattr $C$DW$T$840, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$840, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$840, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$840, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$840, DW_AT_decl_column(0x15)
$C$DW$T$841	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__diagsMask")
	.dwattr $C$DW$T$841, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$841, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$841, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$841, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$841, DW_AT_decl_column(0x15)
$C$DW$T$842	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__diagsMask")
	.dwattr $C$DW$T$842, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$842, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$842, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$842, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$842, DW_AT_decl_column(0x15)
$C$DW$T$843	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__diagsMask")
	.dwattr $C$DW$T$843, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$843, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$843, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$843, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$843, DW_AT_decl_column(0x15)
$C$DW$T$844	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__diagsMask")
	.dwattr $C$DW$T$844, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$844, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$844, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$844, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$844, DW_AT_decl_column(0x15)
$C$DW$T$845	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__diagsMask")
	.dwattr $C$DW$T$845, DW_AT_type(*$C$DW$T$825)
	.dwattr $C$DW$T$845, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$845, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$845, DW_AT_decl_line(0xde)
	.dwattr $C$DW$T$845, DW_AT_decl_column(0x15)
$C$DW$T$360	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_DiagsMask")
	.dwattr $C$DW$T$360, DW_AT_type(*$C$DW$T$358)
	.dwattr $C$DW$T$360, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$360, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$360, DW_AT_decl_line(0x41)
	.dwattr $C$DW$T$360, DW_AT_decl_column(0x14)
$C$DW$T$361	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Diags_Mask")
	.dwattr $C$DW$T$361, DW_AT_type(*$C$DW$T$360)
	.dwattr $C$DW$T$361, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$361, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$361, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$361, DW_AT_decl_column(0x25)
$C$DW$T$362	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$362, DW_AT_type(*$C$DW$T$361)
	.dwattr $C$DW$T$362, DW_AT_address_class(0x20)
$C$DW$T$359	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_ModuleId")
	.dwattr $C$DW$T$359, DW_AT_type(*$C$DW$T$358)
	.dwattr $C$DW$T$359, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$359, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$359, DW_AT_decl_line(0x3e)
	.dwattr $C$DW$T$359, DW_AT_decl_column(0x14)
$C$DW$T$846	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__id")
	.dwattr $C$DW$T$846, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$846, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$846, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$846, DW_AT_decl_line(0x98)
	.dwattr $C$DW$T$846, DW_AT_decl_column(0x24)
$C$DW$T$847	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__id")
	.dwattr $C$DW$T$847, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$847, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$847, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$847, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$847, DW_AT_decl_column(0x24)
$C$DW$T$848	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__id")
	.dwattr $C$DW$T$848, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$848, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$848, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$848, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$848, DW_AT_decl_column(0x24)
$C$DW$T$849	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__id")
	.dwattr $C$DW$T$849, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$849, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$849, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$849, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$849, DW_AT_decl_column(0x24)
$C$DW$T$850	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__id")
	.dwattr $C$DW$T$850, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$850, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$850, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$850, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$850, DW_AT_decl_column(0x24)
$C$DW$T$851	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__id")
	.dwattr $C$DW$T$851, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$851, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$851, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$851, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$851, DW_AT_decl_column(0x24)
$C$DW$T$852	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__id")
	.dwattr $C$DW$T$852, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$852, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$852, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$852, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$852, DW_AT_decl_column(0x24)
$C$DW$T$853	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__id")
	.dwattr $C$DW$T$853, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$853, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$853, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$853, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$853, DW_AT_decl_column(0x24)
$C$DW$T$854	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__id")
	.dwattr $C$DW$T$854, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$854, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$854, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$854, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$854, DW_AT_decl_column(0x24)
$C$DW$T$855	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__id")
	.dwattr $C$DW$T$855, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$855, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$855, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$855, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$855, DW_AT_decl_column(0x24)
$C$DW$T$856	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__id")
	.dwattr $C$DW$T$856, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$856, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$856, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$856, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$856, DW_AT_decl_column(0x24)
$C$DW$T$857	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__id")
	.dwattr $C$DW$T$857, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$857, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$857, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$857, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$857, DW_AT_decl_column(0x24)
$C$DW$T$858	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__id")
	.dwattr $C$DW$T$858, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$858, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$858, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$858, DW_AT_decl_line(0x87)
	.dwattr $C$DW$T$858, DW_AT_decl_column(0x24)
$C$DW$T$859	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__id")
	.dwattr $C$DW$T$859, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$859, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$859, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$859, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$859, DW_AT_decl_column(0x24)
$C$DW$T$860	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__id")
	.dwattr $C$DW$T$860, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$860, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$860, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$860, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$860, DW_AT_decl_column(0x24)
$C$DW$T$861	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__id")
	.dwattr $C$DW$T$861, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$861, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$861, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$861, DW_AT_decl_line(0x60)
	.dwattr $C$DW$T$861, DW_AT_decl_column(0x24)
$C$DW$T$862	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__id")
	.dwattr $C$DW$T$862, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$862, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$862, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$862, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$T$862, DW_AT_decl_column(0x24)
$C$DW$T$863	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__id")
	.dwattr $C$DW$T$863, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$863, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$863, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$863, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$863, DW_AT_decl_column(0x24)
$C$DW$T$864	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__id")
	.dwattr $C$DW$T$864, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$864, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$864, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$864, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$864, DW_AT_decl_column(0x24)
$C$DW$T$865	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__id")
	.dwattr $C$DW$T$865, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$T$865, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$865, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$865, DW_AT_decl_line(0xea)
	.dwattr $C$DW$T$865, DW_AT_decl_column(0x24)
$C$DW$T$452	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_RopeId")
	.dwattr $C$DW$T$452, DW_AT_type(*$C$DW$T$358)
	.dwattr $C$DW$T$452, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$452, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$452, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$452, DW_AT_decl_column(0x14)
$C$DW$T$866	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Log_EventId")
	.dwattr $C$DW$T$866, DW_AT_type(*$C$DW$T$452)
	.dwattr $C$DW$T$866, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$866, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$866, DW_AT_decl_line(0x57)
	.dwattr $C$DW$T$866, DW_AT_decl_column(0x22)
$C$DW$T$765	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_RopeId")
	.dwattr $C$DW$T$765, DW_AT_type(*$C$DW$T$452)
	.dwattr $C$DW$T$765, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$765, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$765, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$765, DW_AT_decl_column(0x22)
$C$DW$T$867	.dwtag  DW_TAG_typedef, DW_AT_name("wchar_t")
	.dwattr $C$DW$T$867, DW_AT_type(*$C$DW$T$9)
	.dwattr $C$DW$T$867, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$867, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stddef.h")
	.dwattr $C$DW$T$867, DW_AT_decl_line(0x3c)
	.dwattr $C$DW$T$867, DW_AT_decl_column(0x1a)
$C$DW$T$868	.dwtag  DW_TAG_typedef, DW_AT_name("word16")
	.dwattr $C$DW$T$868, DW_AT_type(*$C$DW$T$9)
	.dwattr $C$DW$T$868, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$868, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$868, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$T$868, DW_AT_decl_column(0x1c)
$C$DW$T$147	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Bool")
	.dwattr $C$DW$T$147, DW_AT_type(*$C$DW$T$9)
	.dwattr $C$DW$T$147, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$147, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$147, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$T$147, DW_AT_decl_column(0x19)
$C$DW$T$869	.dwtag  DW_TAG_typedef, DW_AT_name("Bool")
	.dwattr $C$DW$T$869, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$869, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$869, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$869, DW_AT_decl_line(0xe5)
	.dwattr $C$DW$T$869, DW_AT_decl_column(0x19)
$C$DW$T$870	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__loggerDefined")
	.dwattr $C$DW$T$870, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$870, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$870, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$870, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$T$870, DW_AT_decl_column(0x12)
$C$DW$T$871	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__loggerDefined")
	.dwattr $C$DW$T$871, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$871, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$871, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$871, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$871, DW_AT_decl_column(0x12)
$C$DW$T$872	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_clockEnabled")
	.dwattr $C$DW$T$872, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$872, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$872, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$872, DW_AT_decl_line(0xf9)
	.dwattr $C$DW$T$872, DW_AT_decl_column(0x12)
$C$DW$T$873	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_heapTrackEnabled")
	.dwattr $C$DW$T$873, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$873, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$873, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$873, DW_AT_decl_line(0x110)
	.dwattr $C$DW$T$873, DW_AT_decl_column(0x12)
$C$DW$T$874	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_runtimeCreatesEnabled")
	.dwattr $C$DW$T$874, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$874, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$874, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$874, DW_AT_decl_line(0xde)
	.dwattr $C$DW$T$874, DW_AT_decl_column(0x12)
$C$DW$T$875	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_smpEnabled")
	.dwattr $C$DW$T$875, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$875, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$875, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$875, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$T$875, DW_AT_decl_column(0x12)
$C$DW$T$876	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_swiEnabled")
	.dwattr $C$DW$T$876, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$876, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$876, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$876, DW_AT_decl_line(0xf0)
	.dwattr $C$DW$T$876, DW_AT_decl_column(0x12)
$C$DW$T$877	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_taskEnabled")
	.dwattr $C$DW$T$877, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$877, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$877, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$877, DW_AT_decl_line(0xe7)
	.dwattr $C$DW$T$877, DW_AT_decl_column(0x12)
$C$DW$T$878	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_useSK")
	.dwattr $C$DW$T$878, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$878, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$878, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$878, DW_AT_decl_line(0x119)
	.dwattr $C$DW$T$878, DW_AT_decl_column(0x12)
$C$DW$T$879	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__loggerDefined")
	.dwattr $C$DW$T$879, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$879, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$879, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$879, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$879, DW_AT_decl_column(0x12)
$C$DW$T$880	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__loggerDefined")
	.dwattr $C$DW$T$880, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$880, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$880, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$880, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$880, DW_AT_decl_column(0x12)
$C$DW$T$881	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__loggerDefined")
	.dwattr $C$DW$T$881, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$881, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$881, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$881, DW_AT_decl_line(0xe0)
	.dwattr $C$DW$T$881, DW_AT_decl_column(0x12)
$C$DW$T$882	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__loggerDefined")
	.dwattr $C$DW$T$882, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$882, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$882, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$882, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$882, DW_AT_decl_column(0x12)
$C$DW$T$883	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__loggerDefined")
	.dwattr $C$DW$T$883, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$883, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$883, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$883, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$T$883, DW_AT_decl_column(0x12)
$C$DW$T$884	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_supportsEvents")
	.dwattr $C$DW$T$884, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$884, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$884, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$884, DW_AT_decl_line(0xe5)
	.dwattr $C$DW$T$884, DW_AT_decl_column(0x12)
$C$DW$T$885	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_supportsPriority")
	.dwattr $C$DW$T$885, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$885, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$885, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$885, DW_AT_decl_line(0xee)
	.dwattr $C$DW$T$885, DW_AT_decl_column(0x12)
$C$DW$T$886	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__loggerDefined")
	.dwattr $C$DW$T$886, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$886, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$886, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$886, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$T$886, DW_AT_decl_column(0x12)
$C$DW$T$887	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__loggerDefined")
	.dwattr $C$DW$T$887, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$887, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$887, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$887, DW_AT_decl_line(0xc8)
	.dwattr $C$DW$T$887, DW_AT_decl_column(0x12)
$C$DW$T$888	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__loggerDefined")
	.dwattr $C$DW$T$888, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$888, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$888, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$888, DW_AT_decl_line(0x60)
	.dwattr $C$DW$T$888, DW_AT_decl_column(0x12)
$C$DW$T$889	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_checkStackFlag")
	.dwattr $C$DW$T$889, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$889, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$889, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$889, DW_AT_decl_line(0x18f)
	.dwattr $C$DW$T$889, DW_AT_decl_column(0x12)
$C$DW$T$890	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_deleteTerminatedTasks")
	.dwattr $C$DW$T$890, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$890, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$890, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$890, DW_AT_decl_line(0x198)
	.dwattr $C$DW$T$890, DW_AT_decl_column(0x12)
$C$DW$T$891	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_initStackFlag")
	.dwattr $C$DW$T$891, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$891, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$891, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$891, DW_AT_decl_line(0x186)
	.dwattr $C$DW$T$891, DW_AT_decl_column(0x12)
$C$DW$T$892	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__loggerDefined")
	.dwattr $C$DW$T$892, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$892, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$892, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$892, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$892, DW_AT_decl_column(0x12)
$C$DW$T$893	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__loggerDefined")
	.dwattr $C$DW$T$893, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$893, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$893, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$893, DW_AT_decl_line(0xbb)
	.dwattr $C$DW$T$893, DW_AT_decl_column(0x12)
$C$DW$T$894	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_setMaskEnabled")
	.dwattr $C$DW$T$894, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$894, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$894, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$894, DW_AT_decl_line(0xef)
	.dwattr $C$DW$T$894, DW_AT_decl_column(0x12)
$C$DW$T$895	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__loggerDefined")
	.dwattr $C$DW$T$895, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$895, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$895, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$895, DW_AT_decl_line(0x8b)
	.dwattr $C$DW$T$895, DW_AT_decl_column(0x12)
$C$DW$T$896	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__loggerDefined")
	.dwattr $C$DW$T$896, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$896, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$896, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$896, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$896, DW_AT_decl_column(0x12)
$C$DW$T$897	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__loggerDefined")
	.dwattr $C$DW$T$897, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$897, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$897, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$897, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$897, DW_AT_decl_column(0x12)
$C$DW$T$898	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__loggerDefined")
	.dwattr $C$DW$T$898, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$898, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$898, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$898, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$898, DW_AT_decl_column(0x12)
$C$DW$T$899	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__loggerDefined")
	.dwattr $C$DW$T$899, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$899, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$899, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$899, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$T$899, DW_AT_decl_column(0x12)
$C$DW$T$900	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__loggerDefined")
	.dwattr $C$DW$T$900, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$900, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$900, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$900, DW_AT_decl_line(0x72)
	.dwattr $C$DW$T$900, DW_AT_decl_column(0x12)
$C$DW$T$901	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__loggerDefined")
	.dwattr $C$DW$T$901, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$901, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$901, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$901, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$901, DW_AT_decl_column(0x12)
$C$DW$T$902	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_isLoaded")
	.dwattr $C$DW$T$902, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$902, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$902, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$902, DW_AT_decl_line(0xcc)
	.dwattr $C$DW$T$902, DW_AT_decl_column(0x12)
$C$DW$T$903	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__loggerDefined")
	.dwattr $C$DW$T$903, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$903, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$903, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$903, DW_AT_decl_line(0xee)
	.dwattr $C$DW$T$903, DW_AT_decl_column(0x12)

$C$DW$T$149	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$149, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$149, DW_AT_language(DW_LANG_C)
$C$DW$414	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$414, DW_AT_type(*$C$DW$T$148)
	.dwendtag $C$DW$T$149

$C$DW$T$150	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$150, DW_AT_type(*$C$DW$T$149)
	.dwattr $C$DW$T$150, DW_AT_address_class(0x20)
$C$DW$T$904	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_query_FxnT")
	.dwattr $C$DW$T$904, DW_AT_type(*$C$DW$T$150)
	.dwattr $C$DW$T$904, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$904, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$T$904, DW_AT_decl_line(0xa2)
	.dwattr $C$DW$T$904, DW_AT_decl_column(0x14)

$C$DW$T$192	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$192, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$192, DW_AT_language(DW_LANG_C)
$C$DW$415	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$415, DW_AT_type(*$C$DW$T$190)
$C$DW$416	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$416, DW_AT_type(*$C$DW$T$191)
	.dwendtag $C$DW$T$192

$C$DW$T$193	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$193, DW_AT_type(*$C$DW$T$192)
	.dwattr $C$DW$T$193, DW_AT_address_class(0x20)
$C$DW$T$905	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_checkStack_FxnT")
	.dwattr $C$DW$T$905, DW_AT_type(*$C$DW$T$193)
	.dwattr $C$DW$T$905, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$905, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$905, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$905, DW_AT_decl_column(0x14)

$C$DW$T$220	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$220, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$220, DW_AT_language(DW_LANG_C)
$C$DW$417	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$417, DW_AT_type(*$C$DW$T$3)
$C$DW$418	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$418, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$220

$C$DW$T$221	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$221, DW_AT_type(*$C$DW$T$220)
	.dwattr $C$DW$T$221, DW_AT_address_class(0x20)
$C$DW$T$906	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_setPeriodMicroSecs_FxnT")
	.dwattr $C$DW$T$906, DW_AT_type(*$C$DW$T$221)
	.dwattr $C$DW$T$906, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$906, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$906, DW_AT_decl_line(0x173)
	.dwattr $C$DW$T$906, DW_AT_decl_column(0x14)

$C$DW$T$261	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$261, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$261, DW_AT_language(DW_LANG_C)
$C$DW$419	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$419, DW_AT_type(*$C$DW$T$254)
$C$DW$420	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$420, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$261

$C$DW$T$262	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$262, DW_AT_type(*$C$DW$T$261)
	.dwattr $C$DW$T$262, DW_AT_address_class(0x20)

$C$DW$T$393	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$393, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$393, DW_AT_language(DW_LANG_C)
$C$DW$421	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$421, DW_AT_type(*$C$DW$T$3)
	.dwendtag $C$DW$T$393

$C$DW$T$394	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$394, DW_AT_type(*$C$DW$T$393)
	.dwattr $C$DW$T$394, DW_AT_address_class(0x20)
$C$DW$T$907	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_isBlocking_FxnT")
	.dwattr $C$DW$T$907, DW_AT_type(*$C$DW$T$394)
	.dwattr $C$DW$T$907, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$907, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$907, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$T$907, DW_AT_decl_column(0x14)

$C$DW$T$435	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$435, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$435, DW_AT_language(DW_LANG_C)
$C$DW$422	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$422, DW_AT_type(*$C$DW$T$430)
	.dwendtag $C$DW$T$435

$C$DW$T$436	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$436, DW_AT_type(*$C$DW$T$435)
	.dwattr $C$DW$T$436, DW_AT_address_class(0x20)

$C$DW$T$908	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$908, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$908, DW_AT_language(DW_LANG_C)
$C$DW$T$909	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$909, DW_AT_type(*$C$DW$T$908)
	.dwattr $C$DW$T$909, DW_AT_address_class(0x20)
$C$DW$T$910	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__startupDoneFxn")
	.dwattr $C$DW$T$910, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$910, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$910, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$910, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$T$910, DW_AT_decl_column(0x14)
$C$DW$T$911	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__startupDoneFxn")
	.dwattr $C$DW$T$911, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$911, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$911, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$911, DW_AT_decl_line(0x81)
	.dwattr $C$DW$T$911, DW_AT_decl_column(0x14)
$C$DW$T$912	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__startupDoneFxn")
	.dwattr $C$DW$T$912, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$912, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$912, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$912, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$T$912, DW_AT_decl_column(0x14)
$C$DW$T$913	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__startupDoneFxn")
	.dwattr $C$DW$T$913, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$913, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$913, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$913, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$913, DW_AT_decl_column(0x14)
$C$DW$T$914	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__startupDoneFxn")
	.dwattr $C$DW$T$914, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$914, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$914, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$914, DW_AT_decl_line(0xfc)
	.dwattr $C$DW$T$914, DW_AT_decl_column(0x14)
$C$DW$T$915	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__startupDoneFxn")
	.dwattr $C$DW$T$915, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$915, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$915, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$915, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$915, DW_AT_decl_column(0x14)
$C$DW$T$916	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__startupDoneFxn")
	.dwattr $C$DW$T$916, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$916, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$916, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$916, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$T$916, DW_AT_decl_column(0x14)
$C$DW$T$917	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__startupDoneFxn")
	.dwattr $C$DW$T$917, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$917, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$917, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$917, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$T$917, DW_AT_decl_column(0x14)
$C$DW$T$918	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__startupDoneFxn")
	.dwattr $C$DW$T$918, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$918, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$918, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$918, DW_AT_decl_line(0xe4)
	.dwattr $C$DW$T$918, DW_AT_decl_column(0x14)
$C$DW$T$919	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__startupDoneFxn")
	.dwattr $C$DW$T$919, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$919, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$919, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$919, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$919, DW_AT_decl_column(0x14)
$C$DW$T$920	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__startupDoneFxn")
	.dwattr $C$DW$T$920, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$920, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$920, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$920, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$920, DW_AT_decl_column(0x14)
$C$DW$T$921	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__startupDoneFxn")
	.dwattr $C$DW$T$921, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$921, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$921, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$921, DW_AT_decl_line(0xd7)
	.dwattr $C$DW$T$921, DW_AT_decl_column(0x14)
$C$DW$T$922	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__startupDoneFxn")
	.dwattr $C$DW$T$922, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$922, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$922, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$922, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$922, DW_AT_decl_column(0x14)
$C$DW$T$923	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__startupDoneFxn")
	.dwattr $C$DW$T$923, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$923, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$923, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$923, DW_AT_decl_line(0x98)
	.dwattr $C$DW$T$923, DW_AT_decl_column(0x14)
$C$DW$T$924	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__startupDoneFxn")
	.dwattr $C$DW$T$924, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$924, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$924, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$924, DW_AT_decl_line(0x81)
	.dwattr $C$DW$T$924, DW_AT_decl_column(0x14)
$C$DW$T$925	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__startupDoneFxn")
	.dwattr $C$DW$T$925, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$925, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$925, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$925, DW_AT_decl_line(0x80)
	.dwattr $C$DW$T$925, DW_AT_decl_column(0x14)
$C$DW$T$926	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__startupDoneFxn")
	.dwattr $C$DW$T$926, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$926, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$926, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$926, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$926, DW_AT_decl_column(0x14)
$C$DW$T$927	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__startupDoneFxn")
	.dwattr $C$DW$T$927, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$927, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$927, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$927, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$T$927, DW_AT_decl_column(0x14)
$C$DW$T$928	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__startupDoneFxn")
	.dwattr $C$DW$T$928, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$928, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$928, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$928, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$T$928, DW_AT_decl_column(0x14)
$C$DW$T$929	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__startupDoneFxn")
	.dwattr $C$DW$T$929, DW_AT_type(*$C$DW$T$909)
	.dwattr $C$DW$T$929, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$929, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$929, DW_AT_decl_line(0x10a)
	.dwattr $C$DW$T$929, DW_AT_decl_column(0x14)

$C$DW$T$930	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$930, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$T$930, DW_AT_language(DW_LANG_C)
$C$DW$423	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$423, DW_AT_type(*$C$DW$T$177)
$C$DW$424	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$424, DW_AT_type(*$C$DW$T$367)
	.dwendtag $C$DW$T$930

$C$DW$T$931	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$931, DW_AT_type(*$C$DW$T$930)
	.dwattr $C$DW$T$931, DW_AT_address_class(0x20)
$C$DW$T$932	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_RopeVisitor")
	.dwattr $C$DW$T$932, DW_AT_type(*$C$DW$T$931)
	.dwattr $C$DW$T$932, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$932, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$932, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$932, DW_AT_decl_column(0x14)
$C$DW$T$250	.dwtag  DW_TAG_volatile_type
	.dwattr $C$DW$T$250, DW_AT_type(*$C$DW$T$147)
$C$DW$T$933	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UShort")
	.dwattr $C$DW$T$933, DW_AT_type(*$C$DW$T$9)
	.dwattr $C$DW$T$933, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$933, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$933, DW_AT_decl_line(0x20)
	.dwattr $C$DW$T$933, DW_AT_decl_column(0x19)
$C$DW$T$934	.dwtag  DW_TAG_typedef, DW_AT_name("UShort")
	.dwattr $C$DW$T$934, DW_AT_type(*$C$DW$T$933)
	.dwattr $C$DW$T$934, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$934, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$934, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$T$934, DW_AT_decl_column(0x19)
$C$DW$T$10	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$10, DW_AT_encoding(DW_ATE_signed)
	.dwattr $C$DW$T$10, DW_AT_name("int")
	.dwattr $C$DW$T$10, DW_AT_byte_size(0x04)

$C$DW$T$766	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$766, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$766, DW_AT_language(DW_LANG_C)
$C$DW$T$767	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$767, DW_AT_type(*$C$DW$T$766)
	.dwattr $C$DW$T$767, DW_AT_address_class(0x20)
$C$DW$T$768	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Fxn")
	.dwattr $C$DW$T$768, DW_AT_type(*$C$DW$T$767)
	.dwattr $C$DW$T$768, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$768, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$768, DW_AT_decl_line(0x43)
	.dwattr $C$DW$T$768, DW_AT_decl_column(0x1f)
$C$DW$T$935	.dwtag  DW_TAG_typedef, DW_AT_name("Fxn")
	.dwattr $C$DW$T$935, DW_AT_type(*$C$DW$T$768)
	.dwattr $C$DW$T$935, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$935, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$935, DW_AT_decl_line(0xe9)
	.dwattr $C$DW$T$935, DW_AT_decl_column(0x19)
$C$DW$T$787	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$787, DW_AT_type(*$C$DW$T$10)

$C$DW$T$938	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$938, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$938, DW_AT_language(DW_LANG_C)
$C$DW$425	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$425, DW_AT_type(*$C$DW$T$160)
$C$DW$426	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$426, DW_AT_type(*$C$DW$T$160)
	.dwendtag $C$DW$T$938

$C$DW$T$939	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$939, DW_AT_type(*$C$DW$T$938)
	.dwattr $C$DW$T$939, DW_AT_address_class(0x20)
$C$DW$T$940	.dwtag  DW_TAG_typedef, DW_AT_name("__TI_compar_fn")
	.dwattr $C$DW$T$940, DW_AT_type(*$C$DW$T$939)
	.dwattr $C$DW$T$940, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$940, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdlib.h")
	.dwattr $C$DW$T$940, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$940, DW_AT_decl_column(0x13)
$C$DW$T$941	.dwtag  DW_TAG_typedef, DW_AT_name("int32_t")
	.dwattr $C$DW$T$941, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$941, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$941, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$941, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$T$941, DW_AT_decl_column(0x1d)
$C$DW$T$942	.dwtag  DW_TAG_typedef, DW_AT_name("int_fast16_t")
	.dwattr $C$DW$T$942, DW_AT_type(*$C$DW$T$941)
	.dwattr $C$DW$T$942, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$942, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$942, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$942, DW_AT_decl_column(0x17)
$C$DW$T$943	.dwtag  DW_TAG_typedef, DW_AT_name("int_fast32_t")
	.dwattr $C$DW$T$943, DW_AT_type(*$C$DW$T$941)
	.dwattr $C$DW$T$943, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$943, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$943, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$T$943, DW_AT_decl_column(0x17)
$C$DW$T$944	.dwtag  DW_TAG_typedef, DW_AT_name("int_fast8_t")
	.dwattr $C$DW$T$944, DW_AT_type(*$C$DW$T$941)
	.dwattr $C$DW$T$944, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$944, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$944, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$944, DW_AT_decl_column(0x17)
$C$DW$T$945	.dwtag  DW_TAG_typedef, DW_AT_name("int_least32_t")
	.dwattr $C$DW$T$945, DW_AT_type(*$C$DW$T$941)
	.dwattr $C$DW$T$945, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$945, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$945, DW_AT_decl_line(0x3c)
	.dwattr $C$DW$T$945, DW_AT_decl_column(0x17)
$C$DW$T$946	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Int32")
	.dwattr $C$DW$T$946, DW_AT_type(*$C$DW$T$945)
	.dwattr $C$DW$T$946, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$946, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$946, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$946, DW_AT_decl_column(0x19)
$C$DW$T$947	.dwtag  DW_TAG_typedef, DW_AT_name("Int32")
	.dwattr $C$DW$T$947, DW_AT_type(*$C$DW$T$946)
	.dwattr $C$DW$T$947, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$947, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$947, DW_AT_decl_line(0xe8)
	.dwattr $C$DW$T$947, DW_AT_decl_column(0x19)
$C$DW$T$132	.dwtag  DW_TAG_typedef, DW_AT_name("intptr_t")
	.dwattr $C$DW$T$132, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$132, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$132, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$132, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$132, DW_AT_decl_column(0x1a)
$C$DW$T$133	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_IArg")
	.dwattr $C$DW$T$133, DW_AT_type(*$C$DW$T$132)
	.dwattr $C$DW$T$133, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$133, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$133, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$133, DW_AT_decl_column(0x19)
$C$DW$T$948	.dwtag  DW_TAG_typedef, DW_AT_name("IArg")
	.dwattr $C$DW$T$948, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$948, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$948, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$948, DW_AT_decl_line(0xe3)
	.dwattr $C$DW$T$948, DW_AT_decl_column(0x19)
$C$DW$T$949	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_xdc_runtime_Error_Block__xtra")
	.dwattr $C$DW$T$949, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$949, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$949, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$949, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$949, DW_AT_decl_column(0x12)
$C$DW$T$950	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_xdc_runtime_Error_Data__arg")
	.dwattr $C$DW$T$950, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$950, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$950, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$950, DW_AT_decl_line(0x51)
	.dwattr $C$DW$T$950, DW_AT_decl_column(0x12)
$C$DW$T$951	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_xdc_runtime_Log_EventRec__arg")
	.dwattr $C$DW$T$951, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$951, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$951, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$951, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$T$951, DW_AT_decl_column(0x12)

$C$DW$T$153	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$153, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$153, DW_AT_language(DW_LANG_C)
$C$DW$427	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$427, DW_AT_type(*$C$DW$T$152)
	.dwendtag $C$DW$T$153

$C$DW$T$154	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$154, DW_AT_type(*$C$DW$T$153)
	.dwattr $C$DW$T$154, DW_AT_address_class(0x20)

$C$DW$T$369	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$369, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$369, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$369, DW_AT_byte_size(0x10)
$C$DW$428	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$428, DW_AT_upper_bound(0x03)
	.dwendtag $C$DW$T$369

$C$DW$T$370	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_xdc_runtime_Error_Block__xtra")
	.dwattr $C$DW$T$370, DW_AT_type(*$C$DW$T$369)
	.dwattr $C$DW$T$370, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$370, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$370, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$370, DW_AT_decl_column(0x12)
$C$DW$T$371	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_xdc_runtime_Error_Block__xtra")
	.dwattr $C$DW$T$371, DW_AT_type(*$C$DW$T$370)
	.dwattr $C$DW$T$371, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$371, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$371, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$T$371, DW_AT_decl_column(0x30)

$C$DW$T$373	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$373, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$373, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$373, DW_AT_byte_size(0x08)
$C$DW$429	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$429, DW_AT_upper_bound(0x01)
	.dwendtag $C$DW$T$373

$C$DW$T$374	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_xdc_runtime_Error_Data__arg")
	.dwattr $C$DW$T$374, DW_AT_type(*$C$DW$T$373)
	.dwattr $C$DW$T$374, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$374, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$374, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$374, DW_AT_decl_column(0x12)
$C$DW$T$375	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_xdc_runtime_Error_Data__arg")
	.dwattr $C$DW$T$375, DW_AT_type(*$C$DW$T$374)
	.dwattr $C$DW$T$375, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$375, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$375, DW_AT_decl_line(0x53)
	.dwattr $C$DW$T$375, DW_AT_decl_column(0x2e)

$C$DW$T$380	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$380, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$380, DW_AT_language(DW_LANG_C)
$C$DW$430	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$430, DW_AT_type(*$C$DW$T$3)
	.dwendtag $C$DW$T$380

$C$DW$T$381	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$381, DW_AT_type(*$C$DW$T$380)
	.dwattr $C$DW$T$381, DW_AT_address_class(0x20)
$C$DW$T$952	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_enter_FxnT")
	.dwattr $C$DW$T$952, DW_AT_type(*$C$DW$T$381)
	.dwattr $C$DW$T$952, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$952, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$T$952, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$952, DW_AT_decl_column(0x14)

$C$DW$T$415	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$415, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$415, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$415, DW_AT_byte_size(0x20)
$C$DW$431	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$431, DW_AT_upper_bound(0x07)
	.dwendtag $C$DW$T$415

$C$DW$T$416	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_xdc_runtime_Log_EventRec__arg")
	.dwattr $C$DW$T$416, DW_AT_type(*$C$DW$T$415)
	.dwattr $C$DW$T$416, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$416, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$416, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$416, DW_AT_decl_column(0x12)
$C$DW$T$417	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_xdc_runtime_Log_EventRec__arg")
	.dwattr $C$DW$T$417, DW_AT_type(*$C$DW$T$416)
	.dwattr $C$DW$T$417, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$417, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$417, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$417, DW_AT_decl_column(0x30)

$C$DW$T$420	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$420, DW_AT_type(*$C$DW$T$133)
	.dwattr $C$DW$T$420, DW_AT_language(DW_LANG_C)
$C$DW$432	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$432, DW_AT_type(*$C$DW$T$419)
	.dwendtag $C$DW$T$420

$C$DW$T$421	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$421, DW_AT_type(*$C$DW$T$420)
	.dwattr $C$DW$T$421, DW_AT_address_class(0x20)
$C$DW$T$953	.dwtag  DW_TAG_typedef, DW_AT_name("ptrdiff_t")
	.dwattr $C$DW$T$953, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$953, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$953, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stddef.h")
	.dwattr $C$DW$T$953, DW_AT_decl_line(0x31)
	.dwattr $C$DW$T$953, DW_AT_decl_column(0x1c)
$C$DW$T$148	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Int")
	.dwattr $C$DW$T$148, DW_AT_type(*$C$DW$T$10)
	.dwattr $C$DW$T$148, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$148, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$148, DW_AT_decl_line(0x21)
	.dwattr $C$DW$T$148, DW_AT_decl_column(0x19)
$C$DW$T$954	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Object__count")
	.dwattr $C$DW$T$954, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$954, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$954, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$954, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$T$954, DW_AT_decl_column(0x11)
$C$DW$T$955	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Object__count")
	.dwattr $C$DW$T$955, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$955, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$955, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$955, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$955, DW_AT_decl_column(0x11)
$C$DW$T$956	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Object__count")
	.dwattr $C$DW$T$956, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$956, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$956, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$956, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$956, DW_AT_decl_column(0x11)
$C$DW$T$957	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Object__count")
	.dwattr $C$DW$T$957, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$957, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$957, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$957, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$957, DW_AT_decl_column(0x11)
$C$DW$T$958	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Object__count")
	.dwattr $C$DW$T$958, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$958, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$958, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$958, DW_AT_decl_line(0x100)
	.dwattr $C$DW$T$958, DW_AT_decl_column(0x11)
$C$DW$T$959	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Object__count")
	.dwattr $C$DW$T$959, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$959, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$959, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$959, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$959, DW_AT_decl_column(0x11)
$C$DW$T$960	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Object__count")
	.dwattr $C$DW$T$960, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$960, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$960, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$960, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$960, DW_AT_decl_column(0x11)
$C$DW$T$961	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Object__count")
	.dwattr $C$DW$T$961, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$961, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$961, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$961, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$961, DW_AT_decl_column(0x11)
$C$DW$T$962	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Object__count")
	.dwattr $C$DW$T$962, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$962, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$962, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$962, DW_AT_decl_line(0xe8)
	.dwattr $C$DW$T$962, DW_AT_decl_column(0x11)
$C$DW$T$963	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Object__count")
	.dwattr $C$DW$T$963, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$963, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$963, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$963, DW_AT_decl_line(0x80)
	.dwattr $C$DW$T$963, DW_AT_decl_column(0x11)
$C$DW$T$964	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Object__count")
	.dwattr $C$DW$T$964, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$964, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$964, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$964, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$964, DW_AT_decl_column(0x11)
$C$DW$T$965	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Object__count")
	.dwattr $C$DW$T$965, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$965, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$965, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$965, DW_AT_decl_line(0xdb)
	.dwattr $C$DW$T$965, DW_AT_decl_column(0x11)
$C$DW$T$966	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Object__count")
	.dwattr $C$DW$T$966, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$966, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$966, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$966, DW_AT_decl_line(0xab)
	.dwattr $C$DW$T$966, DW_AT_decl_column(0x11)
$C$DW$T$967	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Object__count")
	.dwattr $C$DW$T$967, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$967, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$967, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$967, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$T$967, DW_AT_decl_column(0x11)
$C$DW$T$968	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Object__count")
	.dwattr $C$DW$T$968, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$968, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$968, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$968, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$968, DW_AT_decl_column(0x11)
$C$DW$T$969	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Object__count")
	.dwattr $C$DW$T$969, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$969, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$969, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$969, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$969, DW_AT_decl_column(0x11)
$C$DW$T$970	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Object__count")
	.dwattr $C$DW$T$970, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$970, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$970, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$970, DW_AT_decl_line(0x7f)
	.dwattr $C$DW$T$970, DW_AT_decl_column(0x11)
$C$DW$T$971	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Object__count")
	.dwattr $C$DW$T$971, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$971, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$971, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$971, DW_AT_decl_line(0x92)
	.dwattr $C$DW$T$971, DW_AT_decl_column(0x11)
$C$DW$T$972	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Object__count")
	.dwattr $C$DW$T$972, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$972, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$972, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$972, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$972, DW_AT_decl_column(0x11)
$C$DW$T$973	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Object__count")
	.dwattr $C$DW$T$973, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$973, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$973, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$973, DW_AT_decl_line(0x10e)
	.dwattr $C$DW$T$973, DW_AT_decl_column(0x11)
$C$DW$T$974	.dwtag  DW_TAG_typedef, DW_AT_name("Int")
	.dwattr $C$DW$T$974, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$974, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$974, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$974, DW_AT_decl_line(0xd7)
	.dwattr $C$DW$T$974, DW_AT_decl_column(0x19)
$C$DW$T$450	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$450, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$T$450, DW_AT_address_class(0x20)
$C$DW$T$350	.dwtag  DW_TAG_volatile_type
	.dwattr $C$DW$T$350, DW_AT_type(*$C$DW$T$148)
$C$DW$T$11	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$11, DW_AT_encoding(DW_ATE_unsigned)
	.dwattr $C$DW$T$11, DW_AT_name("unsigned int")
	.dwattr $C$DW$T$11, DW_AT_byte_size(0x04)
$C$DW$T$135	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$135, DW_AT_type(*$C$DW$T$11)

$C$DW$T$136	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$136, DW_AT_type(*$C$DW$T$135)
	.dwattr $C$DW$T$136, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$136, DW_AT_byte_size(0x10)
$C$DW$433	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$433, DW_AT_upper_bound(0x03)
	.dwendtag $C$DW$T$136

$C$DW$T$158	.dwtag  DW_TAG_typedef, DW_AT_name("size_t")
	.dwattr $C$DW$T$158, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$T$158, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$158, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stddef.h")
	.dwattr $C$DW$T$158, DW_AT_decl_line(0x35)
	.dwattr $C$DW$T$158, DW_AT_decl_column(0x19)
$C$DW$T$191	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_SizeT")
	.dwattr $C$DW$T$191, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$T$191, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$191, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$191, DW_AT_decl_line(0x28)
	.dwattr $C$DW$T$191, DW_AT_decl_column(0x19)
$C$DW$T$981	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Object__sizeof")
	.dwattr $C$DW$T$981, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$981, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$981, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$981, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$981, DW_AT_decl_column(0x13)
$C$DW$T$982	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Object__sizeof")
	.dwattr $C$DW$T$982, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$982, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$982, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$982, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$982, DW_AT_decl_column(0x13)
$C$DW$T$983	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_heapSize")
	.dwattr $C$DW$T$983, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$983, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$983, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$983, DW_AT_decl_line(0x102)
	.dwattr $C$DW$T$983, DW_AT_decl_column(0x13)
$C$DW$T$984	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Object__sizeof")
	.dwattr $C$DW$T$984, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$984, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$984, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$984, DW_AT_decl_line(0xb1)
	.dwattr $C$DW$T$984, DW_AT_decl_column(0x13)
$C$DW$T$985	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Object__sizeof")
	.dwattr $C$DW$T$985, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$985, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$985, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$985, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$T$985, DW_AT_decl_column(0x13)
$C$DW$T$986	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Object__sizeof")
	.dwattr $C$DW$T$986, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$986, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$986, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$986, DW_AT_decl_line(0x108)
	.dwattr $C$DW$T$986, DW_AT_decl_column(0x13)
$C$DW$T$987	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Object__sizeof")
	.dwattr $C$DW$T$987, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$987, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$987, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$987, DW_AT_decl_line(0x92)
	.dwattr $C$DW$T$987, DW_AT_decl_column(0x13)
$C$DW$T$988	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Object__sizeof")
	.dwattr $C$DW$T$988, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$988, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$988, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$988, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$T$988, DW_AT_decl_column(0x13)
$C$DW$T$989	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Object__sizeof")
	.dwattr $C$DW$T$989, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$989, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$989, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$989, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$T$989, DW_AT_decl_column(0x13)
$C$DW$T$990	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Object__sizeof")
	.dwattr $C$DW$T$990, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$990, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$990, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$990, DW_AT_decl_line(0xf0)
	.dwattr $C$DW$T$990, DW_AT_decl_column(0x13)
$C$DW$T$991	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Object__sizeof")
	.dwattr $C$DW$T$991, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$991, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$991, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$991, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$991, DW_AT_decl_column(0x13)
$C$DW$T$992	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_defaultStackSize")
	.dwattr $C$DW$T$992, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$992, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$992, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$992, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$992, DW_AT_decl_column(0x13)
$C$DW$T$993	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_defaultStackSize")
	.dwattr $C$DW$T$993, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$993, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$993, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$993, DW_AT_decl_line(0x173)
	.dwattr $C$DW$T$993, DW_AT_decl_column(0x13)
$C$DW$T$994	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Object__sizeof")
	.dwattr $C$DW$T$994, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$994, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$994, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$994, DW_AT_decl_line(0x90)
	.dwattr $C$DW$T$994, DW_AT_decl_column(0x13)
$C$DW$T$995	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Object__sizeof")
	.dwattr $C$DW$T$995, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$995, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$995, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$995, DW_AT_decl_line(0xe3)
	.dwattr $C$DW$T$995, DW_AT_decl_column(0x13)
$C$DW$T$996	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Object__sizeof")
	.dwattr $C$DW$T$996, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$996, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$996, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$996, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$T$996, DW_AT_decl_column(0x13)
$C$DW$T$997	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Object__sizeof")
	.dwattr $C$DW$T$997, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$997, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$997, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$997, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$T$997, DW_AT_decl_column(0x13)
$C$DW$T$998	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Object__sizeof")
	.dwattr $C$DW$T$998, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$998, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$998, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$998, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$998, DW_AT_decl_column(0x13)
$C$DW$T$999	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Object__sizeof")
	.dwattr $C$DW$T$999, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$999, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$999, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$999, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$999, DW_AT_decl_column(0x13)
$C$DW$T$1000	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Object__sizeof")
	.dwattr $C$DW$T$1000, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$1000, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1000, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$1000, DW_AT_decl_line(0x87)
	.dwattr $C$DW$T$1000, DW_AT_decl_column(0x13)
$C$DW$T$1001	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Object__sizeof")
	.dwattr $C$DW$T$1001, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$1001, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1001, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$1001, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$1001, DW_AT_decl_column(0x13)
$C$DW$T$1002	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Object__sizeof")
	.dwattr $C$DW$T$1002, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$1002, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1002, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1002, DW_AT_decl_line(0xb1)
	.dwattr $C$DW$T$1002, DW_AT_decl_column(0x13)
$C$DW$T$1003	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Object__sizeof")
	.dwattr $C$DW$T$1003, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$1003, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1003, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1003, DW_AT_decl_line(0x116)
	.dwattr $C$DW$T$1003, DW_AT_decl_column(0x13)
$C$DW$T$1004	.dwtag  DW_TAG_typedef, DW_AT_name("SizeT")
	.dwattr $C$DW$T$1004, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$1004, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1004, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1004, DW_AT_decl_line(0xe0)
	.dwattr $C$DW$T$1004, DW_AT_decl_column(0x19)

$C$DW$T$194	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$194, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$194, DW_AT_language(DW_LANG_C)
$C$DW$434	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$434, DW_AT_type(*$C$DW$T$190)
$C$DW$435	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$435, DW_AT_type(*$C$DW$T$191)
	.dwendtag $C$DW$T$194

$C$DW$T$195	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$195, DW_AT_type(*$C$DW$T$194)
	.dwattr $C$DW$T$195, DW_AT_address_class(0x20)
$C$DW$T$1005	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_stackUsed_FxnT")
	.dwattr $C$DW$T$1005, DW_AT_type(*$C$DW$T$195)
	.dwattr $C$DW$T$1005, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1005, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$1005, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$1005, DW_AT_decl_column(0x15)

$C$DW$T$199	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$199, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$T$199, DW_AT_language(DW_LANG_C)
$C$DW$T$200	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$200, DW_AT_type(*$C$DW$T$199)
	.dwattr $C$DW$T$200, DW_AT_address_class(0x20)
$C$DW$T$1006	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_getDefaultStackSize_FxnT")
	.dwattr $C$DW$T$1006, DW_AT_type(*$C$DW$T$200)
	.dwattr $C$DW$T$1006, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1006, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$1006, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$T$1006, DW_AT_decl_column(0x15)
$C$DW$T$174	.dwtag  DW_TAG_typedef, DW_AT_name("uint32_t")
	.dwattr $C$DW$T$174, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$T$174, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$174, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$174, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$T$174, DW_AT_decl_column(0x1c)
$C$DW$T$1007	.dwtag  DW_TAG_typedef, DW_AT_name("uint_fast16_t")
	.dwattr $C$DW$T$1007, DW_AT_type(*$C$DW$T$174)
	.dwattr $C$DW$T$1007, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1007, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1007, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$1007, DW_AT_decl_column(0x16)
$C$DW$T$1008	.dwtag  DW_TAG_typedef, DW_AT_name("uint_fast32_t")
	.dwattr $C$DW$T$1008, DW_AT_type(*$C$DW$T$174)
	.dwattr $C$DW$T$1008, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1008, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1008, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$1008, DW_AT_decl_column(0x16)
$C$DW$T$1009	.dwtag  DW_TAG_typedef, DW_AT_name("uint_fast8_t")
	.dwattr $C$DW$T$1009, DW_AT_type(*$C$DW$T$174)
	.dwattr $C$DW$T$1009, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1009, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1009, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$1009, DW_AT_decl_column(0x16)
$C$DW$T$212	.dwtag  DW_TAG_typedef, DW_AT_name("uint_least32_t")
	.dwattr $C$DW$T$212, DW_AT_type(*$C$DW$T$174)
	.dwattr $C$DW$T$212, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$212, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$212, DW_AT_decl_line(0x3d)
	.dwattr $C$DW$T$212, DW_AT_decl_column(0x16)
$C$DW$T$213	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UInt32")
	.dwattr $C$DW$T$213, DW_AT_type(*$C$DW$T$212)
	.dwattr $C$DW$T$213, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$213, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$213, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$213, DW_AT_decl_column(0x19)
$C$DW$T$1010	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_serviceMargin")
	.dwattr $C$DW$T$1010, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$1010, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1010, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1010, DW_AT_decl_line(0xf2)
	.dwattr $C$DW$T$1010, DW_AT_decl_column(0x14)
$C$DW$T$1011	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_tickPeriod")
	.dwattr $C$DW$T$1011, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$1011, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1011, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1011, DW_AT_decl_line(0xe9)
	.dwattr $C$DW$T$1011, DW_AT_decl_column(0x14)
$C$DW$T$1012	.dwtag  DW_TAG_typedef, DW_AT_name("UInt32")
	.dwattr $C$DW$T$1012, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$1012, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1012, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1012, DW_AT_decl_line(0xf0)
	.dwattr $C$DW$T$1012, DW_AT_decl_column(0x19)
$C$DW$T$1013	.dwtag  DW_TAG_typedef, DW_AT_name("Uint32")
	.dwattr $C$DW$T$1013, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$1013, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1013, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1013, DW_AT_decl_line(0xfd)
	.dwattr $C$DW$T$1013, DW_AT_decl_column(0x19)

$C$DW$T$214	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$214, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$214, DW_AT_language(DW_LANG_C)
$C$DW$436	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$436, DW_AT_type(*$C$DW$T$3)
	.dwendtag $C$DW$T$214

$C$DW$T$215	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$215, DW_AT_type(*$C$DW$T$214)
	.dwattr $C$DW$T$215, DW_AT_address_class(0x20)
$C$DW$T$1014	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getCount_FxnT")
	.dwattr $C$DW$T$1014, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$T$1014, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1014, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1014, DW_AT_decl_line(0x181)
	.dwattr $C$DW$T$1014, DW_AT_decl_column(0x16)
$C$DW$T$1015	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getExpiredCounts_FxnT")
	.dwattr $C$DW$T$1015, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$T$1015, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1015, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1015, DW_AT_decl_line(0x1a4)
	.dwattr $C$DW$T$1015, DW_AT_decl_column(0x16)
$C$DW$T$1016	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getMaxTicks_FxnT")
	.dwattr $C$DW$T$1016, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$T$1016, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1016, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1016, DW_AT_decl_line(0x150)
	.dwattr $C$DW$T$1016, DW_AT_decl_column(0x16)
$C$DW$T$1017	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getPeriod_FxnT")
	.dwattr $C$DW$T$1017, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$T$1017, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1017, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1017, DW_AT_decl_line(0x17a)
	.dwattr $C$DW$T$1017, DW_AT_decl_column(0x16)

$C$DW$T$231	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$231, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$231, DW_AT_language(DW_LANG_C)
$C$DW$437	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$437, DW_AT_type(*$C$DW$T$3)
$C$DW$438	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$438, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$231

$C$DW$T$232	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$232, DW_AT_type(*$C$DW$T$231)
	.dwattr $C$DW$T$232, DW_AT_address_class(0x20)
$C$DW$T$1018	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getExpiredTicks_FxnT")
	.dwattr $C$DW$T$1018, DW_AT_type(*$C$DW$T$232)
	.dwattr $C$DW$T$1018, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1018, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1018, DW_AT_decl_line(0x1ab)
	.dwattr $C$DW$T$1018, DW_AT_decl_column(0x16)

$C$DW$T$233	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$233, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$233, DW_AT_language(DW_LANG_C)
$C$DW$439	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$439, DW_AT_type(*$C$DW$T$3)
$C$DW$440	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$440, DW_AT_type(*$C$DW$T$147)
	.dwendtag $C$DW$T$233

$C$DW$T$234	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$234, DW_AT_type(*$C$DW$T$233)
	.dwattr $C$DW$T$234, DW_AT_address_class(0x20)
$C$DW$T$1019	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getCurrentTick_FxnT")
	.dwattr $C$DW$T$1019, DW_AT_type(*$C$DW$T$234)
	.dwattr $C$DW$T$1019, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1019, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1019, DW_AT_decl_line(0x1b2)
	.dwattr $C$DW$T$1019, DW_AT_decl_column(0x16)

$C$DW$T$255	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$255, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$255, DW_AT_language(DW_LANG_C)
$C$DW$441	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$441, DW_AT_type(*$C$DW$T$254)
	.dwendtag $C$DW$T$255

$C$DW$T$256	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$256, DW_AT_type(*$C$DW$T$255)
	.dwattr $C$DW$T$256, DW_AT_address_class(0x20)

$C$DW$T$269	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$269, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$269, DW_AT_language(DW_LANG_C)
$C$DW$442	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$442, DW_AT_type(*$C$DW$T$254)
$C$DW$443	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$443, DW_AT_type(*$C$DW$T$213)
	.dwendtag $C$DW$T$269

$C$DW$T$270	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$270, DW_AT_type(*$C$DW$T$269)
	.dwattr $C$DW$T$270, DW_AT_address_class(0x20)

$C$DW$T$271	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$271, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$T$271, DW_AT_language(DW_LANG_C)
$C$DW$444	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$444, DW_AT_type(*$C$DW$T$254)
$C$DW$445	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$445, DW_AT_type(*$C$DW$T$147)
	.dwendtag $C$DW$T$271

$C$DW$T$272	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$272, DW_AT_type(*$C$DW$T$271)
	.dwattr $C$DW$T$272, DW_AT_address_class(0x20)
$C$DW$T$175	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Bits32")
	.dwattr $C$DW$T$175, DW_AT_type(*$C$DW$T$174)
	.dwattr $C$DW$T$175, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$175, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$175, DW_AT_decl_line(0x83)
	.dwattr $C$DW$T$175, DW_AT_decl_column(0x19)
$C$DW$T$1020	.dwtag  DW_TAG_typedef, DW_AT_name("Bits32")
	.dwattr $C$DW$T$1020, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1020, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1020, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1020, DW_AT_decl_line(0x117)
	.dwattr $C$DW$T$1020, DW_AT_decl_column(0x19)
$C$DW$T$1021	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__diagsEnabled")
	.dwattr $C$DW$T$1021, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1021, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1021, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1021, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1021, DW_AT_decl_column(0x14)
$C$DW$T$1022	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Module__diagsIncluded")
	.dwattr $C$DW$T$1022, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1022, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1022, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1022, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$1022, DW_AT_decl_column(0x14)
$C$DW$T$1023	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__diagsEnabled")
	.dwattr $C$DW$T$1023, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1023, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1023, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$1023, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$1023, DW_AT_decl_column(0x14)
$C$DW$T$1024	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Module__diagsIncluded")
	.dwattr $C$DW$T$1024, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1024, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1024, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$1024, DW_AT_decl_line(0x51)
	.dwattr $C$DW$T$1024, DW_AT_decl_column(0x14)
$C$DW$T$1025	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__diagsEnabled")
	.dwattr $C$DW$T$1025, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1025, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1025, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1025, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$1025, DW_AT_decl_column(0x14)
$C$DW$T$1026	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Module__diagsIncluded")
	.dwattr $C$DW$T$1026, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1026, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1026, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1026, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$1026, DW_AT_decl_column(0x14)
$C$DW$T$1027	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__diagsEnabled")
	.dwattr $C$DW$T$1027, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1027, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1027, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1027, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$1027, DW_AT_decl_column(0x14)
$C$DW$T$1028	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Module__diagsIncluded")
	.dwattr $C$DW$T$1028, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1028, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1028, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1028, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$1028, DW_AT_decl_column(0x14)
$C$DW$T$1029	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__diagsEnabled")
	.dwattr $C$DW$T$1029, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1029, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1029, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1029, DW_AT_decl_line(0xc8)
	.dwattr $C$DW$T$1029, DW_AT_decl_column(0x14)
$C$DW$T$1030	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Module__diagsIncluded")
	.dwattr $C$DW$T$1030, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1030, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1030, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1030, DW_AT_decl_line(0xcc)
	.dwattr $C$DW$T$1030, DW_AT_decl_column(0x14)
$C$DW$T$1031	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__diagsEnabled")
	.dwattr $C$DW$T$1031, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1031, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1031, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$1031, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$1031, DW_AT_decl_column(0x14)
$C$DW$T$1032	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Module__diagsIncluded")
	.dwattr $C$DW$T$1032, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1032, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1032, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$1032, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$1032, DW_AT_decl_column(0x14)
$C$DW$T$1033	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__diagsEnabled")
	.dwattr $C$DW$T$1033, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1033, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1033, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1033, DW_AT_decl_line(0x76)
	.dwattr $C$DW$T$1033, DW_AT_decl_column(0x14)
$C$DW$T$1034	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Module__diagsIncluded")
	.dwattr $C$DW$T$1034, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1034, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1034, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1034, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$1034, DW_AT_decl_column(0x14)
$C$DW$T$1035	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__diagsEnabled")
	.dwattr $C$DW$T$1035, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1035, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1035, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1035, DW_AT_decl_line(0x76)
	.dwattr $C$DW$T$1035, DW_AT_decl_column(0x14)
$C$DW$T$1036	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Module__diagsIncluded")
	.dwattr $C$DW$T$1036, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1036, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1036, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1036, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$1036, DW_AT_decl_column(0x14)
$C$DW$T$1037	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__diagsEnabled")
	.dwattr $C$DW$T$1037, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1037, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1037, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1037, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$T$1037, DW_AT_decl_column(0x14)
$C$DW$T$1038	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Module__diagsIncluded")
	.dwattr $C$DW$T$1038, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1038, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1038, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1038, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$T$1038, DW_AT_decl_column(0x14)
$C$DW$T$1039	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__diagsEnabled")
	.dwattr $C$DW$T$1039, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1039, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1039, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$1039, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$1039, DW_AT_decl_column(0x14)
$C$DW$T$1040	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Module__diagsIncluded")
	.dwattr $C$DW$T$1040, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1040, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1040, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$1040, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$1040, DW_AT_decl_column(0x14)
$C$DW$T$1041	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__diagsEnabled")
	.dwattr $C$DW$T$1041, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1041, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1041, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$1041, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$1041, DW_AT_decl_column(0x14)
$C$DW$T$1042	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Module__diagsIncluded")
	.dwattr $C$DW$T$1042, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1042, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1042, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$1042, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$1042, DW_AT_decl_column(0x14)
$C$DW$T$1043	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__diagsEnabled")
	.dwattr $C$DW$T$1043, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1043, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1043, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1043, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$1043, DW_AT_decl_column(0x14)
$C$DW$T$1044	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Module__diagsIncluded")
	.dwattr $C$DW$T$1044, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1044, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1044, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1044, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$1044, DW_AT_decl_column(0x14)
$C$DW$T$1045	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__diagsEnabled")
	.dwattr $C$DW$T$1045, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1045, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1045, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1045, DW_AT_decl_line(0x73)
	.dwattr $C$DW$T$1045, DW_AT_decl_column(0x14)
$C$DW$T$1046	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Module__diagsIncluded")
	.dwattr $C$DW$T$1046, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1046, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1046, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1046, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$1046, DW_AT_decl_column(0x14)
$C$DW$T$1047	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__diagsEnabled")
	.dwattr $C$DW$T$1047, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1047, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1047, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1047, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$1047, DW_AT_decl_column(0x14)
$C$DW$T$1048	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Module__diagsIncluded")
	.dwattr $C$DW$T$1048, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1048, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1048, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1048, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$1048, DW_AT_decl_column(0x14)
$C$DW$T$1049	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__diagsEnabled")
	.dwattr $C$DW$T$1049, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1049, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1049, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$1049, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$1049, DW_AT_decl_column(0x14)
$C$DW$T$1050	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Module__diagsIncluded")
	.dwattr $C$DW$T$1050, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1050, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1050, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$1050, DW_AT_decl_line(0x51)
	.dwattr $C$DW$T$1050, DW_AT_decl_column(0x14)
$C$DW$T$1051	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__diagsEnabled")
	.dwattr $C$DW$T$1051, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1051, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1051, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$1051, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$1051, DW_AT_decl_column(0x14)
$C$DW$T$1052	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module__diagsIncluded")
	.dwattr $C$DW$T$1052, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1052, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1052, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$1052, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$1052, DW_AT_decl_column(0x14)
$C$DW$T$1053	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__diagsEnabled")
	.dwattr $C$DW$T$1053, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1053, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1053, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$1053, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$1053, DW_AT_decl_column(0x14)
$C$DW$T$1054	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Module__diagsIncluded")
	.dwattr $C$DW$T$1054, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1054, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1054, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$1054, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$1054, DW_AT_decl_column(0x14)
$C$DW$T$1055	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__diagsEnabled")
	.dwattr $C$DW$T$1055, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1055, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1055, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$1055, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$1055, DW_AT_decl_column(0x14)
$C$DW$T$1056	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Module__diagsIncluded")
	.dwattr $C$DW$T$1056, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1056, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1056, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$1056, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$1056, DW_AT_decl_column(0x14)
$C$DW$T$1057	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__diagsEnabled")
	.dwattr $C$DW$T$1057, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1057, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1057, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1057, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$1057, DW_AT_decl_column(0x14)
$C$DW$T$1058	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Module__diagsIncluded")
	.dwattr $C$DW$T$1058, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1058, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1058, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1058, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$1058, DW_AT_decl_column(0x14)
$C$DW$T$1059	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__diagsEnabled")
	.dwattr $C$DW$T$1059, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1059, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1059, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1059, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$T$1059, DW_AT_decl_column(0x14)
$C$DW$T$1060	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Module__diagsIncluded")
	.dwattr $C$DW$T$1060, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1060, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1060, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1060, DW_AT_decl_line(0xda)
	.dwattr $C$DW$T$1060, DW_AT_decl_column(0x14)
$C$DW$T$1061	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Assert_Id")
	.dwattr $C$DW$T$1061, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1061, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1061, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert__prologue.h")
	.dwattr $C$DW$T$1061, DW_AT_decl_line(0x16)
	.dwattr $C$DW$T$1061, DW_AT_decl_column(0x14)
$C$DW$T$1062	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_A_badThreadType")
	.dwattr $C$DW$T$1062, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1062, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1062, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1062, DW_AT_decl_line(0xce)
	.dwattr $C$DW$T$1062, DW_AT_decl_column(0x1f)
$C$DW$T$1063	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_A_clockDisabled")
	.dwattr $C$DW$T$1063, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1063, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1063, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1063, DW_AT_decl_line(0xc9)
	.dwattr $C$DW$T$1063, DW_AT_decl_column(0x1f)
$C$DW$T$1064	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_A_badContext")
	.dwattr $C$DW$T$1064, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1064, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1064, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1064, DW_AT_decl_line(0x12a)
	.dwattr $C$DW$T$1064, DW_AT_decl_column(0x1f)
$C$DW$T$1065	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_A_eventInUse")
	.dwattr $C$DW$T$1065, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1065, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1065, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1065, DW_AT_decl_line(0x125)
	.dwattr $C$DW$T$1065, DW_AT_decl_column(0x1f)
$C$DW$T$1066	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_A_nullEventId")
	.dwattr $C$DW$T$1066, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1066, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1066, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1066, DW_AT_decl_line(0x120)
	.dwattr $C$DW$T$1066, DW_AT_decl_column(0x1f)
$C$DW$T$1067	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_A_nullEventMasks")
	.dwattr $C$DW$T$1067, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1067, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1067, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1067, DW_AT_decl_line(0x11b)
	.dwattr $C$DW$T$1067, DW_AT_decl_column(0x1f)
$C$DW$T$1068	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_A_pendTaskDisabled")
	.dwattr $C$DW$T$1068, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1068, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1068, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1068, DW_AT_decl_line(0x12f)
	.dwattr $C$DW$T$1068, DW_AT_decl_column(0x1f)
$C$DW$T$1069	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_A_badContext")
	.dwattr $C$DW$T$1069, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1069, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1069, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1069, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$1069, DW_AT_decl_column(0x1f)
$C$DW$T$1070	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_A_invTimeout")
	.dwattr $C$DW$T$1070, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1070, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1070, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1070, DW_AT_decl_line(0xce)
	.dwattr $C$DW$T$1070, DW_AT_decl_column(0x1f)
$C$DW$T$1071	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_A_noEvents")
	.dwattr $C$DW$T$1071, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1071, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1071, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1071, DW_AT_decl_line(0xc9)
	.dwattr $C$DW$T$1071, DW_AT_decl_column(0x1f)
$C$DW$T$1072	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_A_overflow")
	.dwattr $C$DW$T$1072, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1072, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1072, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1072, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$T$1072, DW_AT_decl_column(0x1f)
$C$DW$T$1073	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_A_pendTaskDisabled")
	.dwattr $C$DW$T$1073, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1073, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1073, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1073, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$T$1073, DW_AT_decl_column(0x1f)
$C$DW$T$1074	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_A_badPriority")
	.dwattr $C$DW$T$1074, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1074, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1074, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1074, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$1074, DW_AT_decl_column(0x1f)
$C$DW$T$1075	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_A_swiDisabled")
	.dwattr $C$DW$T$1075, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1075, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1075, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1075, DW_AT_decl_line(0xce)
	.dwattr $C$DW$T$1075, DW_AT_decl_column(0x1f)
$C$DW$T$1076	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_badAffinity")
	.dwattr $C$DW$T$1076, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1076, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1076, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1076, DW_AT_decl_line(0x158)
	.dwattr $C$DW$T$1076, DW_AT_decl_column(0x1f)
$C$DW$T$1077	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_badPriority")
	.dwattr $C$DW$T$1077, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1077, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1077, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1077, DW_AT_decl_line(0x14e)
	.dwattr $C$DW$T$1077, DW_AT_decl_column(0x1f)
$C$DW$T$1078	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_badTaskState")
	.dwattr $C$DW$T$1078, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1078, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1078, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1078, DW_AT_decl_line(0x13f)
	.dwattr $C$DW$T$1078, DW_AT_decl_column(0x1f)
$C$DW$T$1079	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_badThreadType")
	.dwattr $C$DW$T$1079, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1079, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1079, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1079, DW_AT_decl_line(0x13a)
	.dwattr $C$DW$T$1079, DW_AT_decl_column(0x1f)
$C$DW$T$1080	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_badTimeout")
	.dwattr $C$DW$T$1080, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1080, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1080, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1080, DW_AT_decl_line(0x153)
	.dwattr $C$DW$T$1080, DW_AT_decl_column(0x1f)
$C$DW$T$1081	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_invalidCoreId")
	.dwattr $C$DW$T$1081, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1081, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1081, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1081, DW_AT_decl_line(0x162)
	.dwattr $C$DW$T$1081, DW_AT_decl_column(0x1f)
$C$DW$T$1082	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_noPendElem")
	.dwattr $C$DW$T$1082, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1082, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1082, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1082, DW_AT_decl_line(0x144)
	.dwattr $C$DW$T$1082, DW_AT_decl_column(0x1f)
$C$DW$T$1083	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_sleepTaskDisabled")
	.dwattr $C$DW$T$1083, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1083, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1083, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1083, DW_AT_decl_line(0x15d)
	.dwattr $C$DW$T$1083, DW_AT_decl_column(0x1f)
$C$DW$T$1084	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_A_taskDisabled")
	.dwattr $C$DW$T$1084, DW_AT_type(*$C$DW$T$1061)
	.dwattr $C$DW$T$1084, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1084, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1084, DW_AT_decl_line(0x149)
	.dwattr $C$DW$T$1084, DW_AT_decl_column(0x1f)
$C$DW$T$365	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_Id")
	.dwattr $C$DW$T$365, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$365, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$365, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error__prologue.h")
	.dwattr $C$DW$T$365, DW_AT_decl_line(0x12)
	.dwattr $C$DW$T$365, DW_AT_decl_column(0x14)
$C$DW$T$1085	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_E_deleteNotAllowed")
	.dwattr $C$DW$T$1085, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1085, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1085, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1085, DW_AT_decl_line(0x135)
	.dwattr $C$DW$T$1085, DW_AT_decl_column(0x1e)
$C$DW$T$1086	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_E_spOutOfBounds")
	.dwattr $C$DW$T$1086, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1086, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1086, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1086, DW_AT_decl_line(0x130)
	.dwattr $C$DW$T$1086, DW_AT_decl_column(0x1e)
$C$DW$T$1087	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_E_stackOverflow")
	.dwattr $C$DW$T$1087, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1087, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1087, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1087, DW_AT_decl_line(0x12b)
	.dwattr $C$DW$T$1087, DW_AT_decl_column(0x1e)
$C$DW$T$1088	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_E_assertFailed")
	.dwattr $C$DW$T$1088, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1088, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1088, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$1088, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$1088, DW_AT_decl_column(0x1e)
$C$DW$T$1089	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_E_generic")
	.dwattr $C$DW$T$1089, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1089, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1089, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1089, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$1089, DW_AT_decl_column(0x1e)
$C$DW$T$1090	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_E_memory")
	.dwattr $C$DW$T$1090, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1090, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1090, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1090, DW_AT_decl_line(0xc6)
	.dwattr $C$DW$T$1090, DW_AT_decl_column(0x1e)
$C$DW$T$1091	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_E_msgCode")
	.dwattr $C$DW$T$1091, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$T$1091, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1091, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1091, DW_AT_decl_line(0xcb)
	.dwattr $C$DW$T$1091, DW_AT_decl_column(0x1e)
$C$DW$T$1092	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Log_Event")
	.dwattr $C$DW$T$1092, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$1092, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1092, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log__prologue.h")
	.dwattr $C$DW$T$1092, DW_AT_decl_line(0x21)
	.dwattr $C$DW$T$1092, DW_AT_decl_column(0x14)
$C$DW$T$1093	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_LM_begin")
	.dwattr $C$DW$T$1093, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1093, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1093, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1093, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$1093, DW_AT_decl_column(0x1f)
$C$DW$T$1094	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_LM_tick")
	.dwattr $C$DW$T$1094, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1094, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1094, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1094, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$T$1094, DW_AT_decl_column(0x1f)
$C$DW$T$1095	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_LW_delayed")
	.dwattr $C$DW$T$1095, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1095, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1095, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1095, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$1095, DW_AT_decl_column(0x1f)
$C$DW$T$1096	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_LM_pend")
	.dwattr $C$DW$T$1096, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1096, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1096, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1096, DW_AT_decl_line(0x116)
	.dwattr $C$DW$T$1096, DW_AT_decl_column(0x1f)
$C$DW$T$1097	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_LM_post")
	.dwattr $C$DW$T$1097, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1097, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1097, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1097, DW_AT_decl_line(0x111)
	.dwattr $C$DW$T$1097, DW_AT_decl_column(0x1f)
$C$DW$T$1098	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_LM_pend")
	.dwattr $C$DW$T$1098, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1098, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1098, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1098, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$1098, DW_AT_decl_column(0x1f)
$C$DW$T$1099	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_LM_post")
	.dwattr $C$DW$T$1099, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1099, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1099, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1099, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$T$1099, DW_AT_decl_column(0x1f)
$C$DW$T$1100	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_LD_end")
	.dwattr $C$DW$T$1100, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1100, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1100, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1100, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$1100, DW_AT_decl_column(0x1f)
$C$DW$T$1101	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_LM_begin")
	.dwattr $C$DW$T$1101, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1101, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1101, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1101, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$T$1101, DW_AT_decl_column(0x1f)
$C$DW$T$1102	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_LM_post")
	.dwattr $C$DW$T$1102, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1102, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1102, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1102, DW_AT_decl_line(0xc9)
	.dwattr $C$DW$T$1102, DW_AT_decl_column(0x1f)
$C$DW$T$1103	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LD_block")
	.dwattr $C$DW$T$1103, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1103, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1103, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1103, DW_AT_decl_line(0x108)
	.dwattr $C$DW$T$1103, DW_AT_decl_column(0x1f)
$C$DW$T$1104	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LD_exit")
	.dwattr $C$DW$T$1104, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1104, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1104, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1104, DW_AT_decl_line(0x117)
	.dwattr $C$DW$T$1104, DW_AT_decl_column(0x1f)
$C$DW$T$1105	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LD_ready")
	.dwattr $C$DW$T$1105, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1105, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1105, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1105, DW_AT_decl_line(0x103)
	.dwattr $C$DW$T$1105, DW_AT_decl_column(0x1f)
$C$DW$T$1106	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_noWork")
	.dwattr $C$DW$T$1106, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1106, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1106, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1106, DW_AT_decl_line(0x126)
	.dwattr $C$DW$T$1106, DW_AT_decl_column(0x1f)
$C$DW$T$1107	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_schedule")
	.dwattr $C$DW$T$1107, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1107, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1107, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1107, DW_AT_decl_line(0x121)
	.dwattr $C$DW$T$1107, DW_AT_decl_column(0x1f)
$C$DW$T$1108	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_setAffinity")
	.dwattr $C$DW$T$1108, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1108, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1108, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1108, DW_AT_decl_line(0x11c)
	.dwattr $C$DW$T$1108, DW_AT_decl_column(0x1f)
$C$DW$T$1109	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_setPri")
	.dwattr $C$DW$T$1109, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1109, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1109, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1109, DW_AT_decl_line(0x112)
	.dwattr $C$DW$T$1109, DW_AT_decl_column(0x1f)
$C$DW$T$1110	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_sleep")
	.dwattr $C$DW$T$1110, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1110, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1110, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1110, DW_AT_decl_line(0xfe)
	.dwattr $C$DW$T$1110, DW_AT_decl_column(0x1f)
$C$DW$T$1111	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_switch")
	.dwattr $C$DW$T$1111, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1111, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1111, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1111, DW_AT_decl_line(0xf9)
	.dwattr $C$DW$T$1111, DW_AT_decl_column(0x1f)
$C$DW$T$1112	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_LM_yield")
	.dwattr $C$DW$T$1112, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1112, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1112, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1112, DW_AT_decl_line(0x10d)
	.dwattr $C$DW$T$1112, DW_AT_decl_column(0x1f)
$C$DW$T$1113	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_construct")
	.dwattr $C$DW$T$1113, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1113, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1113, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1113, DW_AT_decl_line(0xad)
	.dwattr $C$DW$T$1113, DW_AT_decl_column(0x1f)
$C$DW$T$1114	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_create")
	.dwattr $C$DW$T$1114, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1114, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1114, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1114, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$T$1114, DW_AT_decl_column(0x1f)
$C$DW$T$1115	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_delete")
	.dwattr $C$DW$T$1115, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1115, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1115, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1115, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$T$1115, DW_AT_decl_column(0x1f)
$C$DW$T$1116	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_destruct")
	.dwattr $C$DW$T$1116, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1116, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1116, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1116, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$1116, DW_AT_decl_column(0x1f)
$C$DW$T$1117	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_error")
	.dwattr $C$DW$T$1117, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1117, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1117, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1117, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$1117, DW_AT_decl_column(0x1f)
$C$DW$T$1118	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_info")
	.dwattr $C$DW$T$1118, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1118, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1118, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1118, DW_AT_decl_line(0xcb)
	.dwattr $C$DW$T$1118, DW_AT_decl_column(0x1f)
$C$DW$T$1119	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_start")
	.dwattr $C$DW$T$1119, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1119, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1119, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1119, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$T$1119, DW_AT_decl_column(0x1f)
$C$DW$T$1120	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_startInstance")
	.dwattr $C$DW$T$1120, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1120, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1120, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1120, DW_AT_decl_line(0xda)
	.dwattr $C$DW$T$1120, DW_AT_decl_column(0x1f)
$C$DW$T$1121	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_stop")
	.dwattr $C$DW$T$1121, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1121, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1121, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1121, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$1121, DW_AT_decl_column(0x1f)
$C$DW$T$1122	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_stopInstance")
	.dwattr $C$DW$T$1122, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1122, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1122, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1122, DW_AT_decl_line(0xdf)
	.dwattr $C$DW$T$1122, DW_AT_decl_column(0x1f)
$C$DW$T$1123	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_L_warning")
	.dwattr $C$DW$T$1123, DW_AT_type(*$C$DW$T$1092)
	.dwattr $C$DW$T$1123, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1123, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1123, DW_AT_decl_line(0xc6)
	.dwattr $C$DW$T$1123, DW_AT_decl_column(0x1f)
$C$DW$T$414	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Event")
	.dwattr $C$DW$T$414, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$414, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$414, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$414, DW_AT_decl_line(0x44)
	.dwattr $C$DW$T$414, DW_AT_decl_column(0x14)
$C$DW$T$1124	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_EventId")
	.dwattr $C$DW$T$1124, DW_AT_type(*$C$DW$T$414)
	.dwattr $C$DW$T$1124, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1124, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1124, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$1124, DW_AT_decl_column(0x21)
$C$DW$T$640	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_LogEvent")
	.dwattr $C$DW$T$640, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$T$640, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$640, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$640, DW_AT_decl_line(0x91)
	.dwattr $C$DW$T$640, DW_AT_decl_column(0x14)
$C$DW$T$202	.dwtag  DW_TAG_typedef, DW_AT_name("uintptr_t")
	.dwattr $C$DW$T$202, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$T$202, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$202, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$202, DW_AT_decl_line(0x53)
	.dwattr $C$DW$T$202, DW_AT_decl_column(0x1a)
$C$DW$T$203	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UArg")
	.dwattr $C$DW$T$203, DW_AT_type(*$C$DW$T$202)
	.dwattr $C$DW$T$203, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$203, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$203, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$203, DW_AT_decl_column(0x19)
$C$DW$T$1125	.dwtag  DW_TAG_typedef, DW_AT_name("UArg")
	.dwattr $C$DW$T$1125, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$T$1125, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1125, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1125, DW_AT_decl_line(0xe4)
	.dwattr $C$DW$T$1125, DW_AT_decl_column(0x19)
$C$DW$T$226	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$226, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$T$226, DW_AT_address_class(0x20)
$C$DW$T$445	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_Size")
	.dwattr $C$DW$T$445, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$T$445, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$445, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$445, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$445, DW_AT_decl_column(0x12)
$C$DW$T$138	.dwtag  DW_TAG_typedef, DW_AT_name("word32")
	.dwattr $C$DW$T$138, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$T$138, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$138, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$138, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$T$138, DW_AT_decl_column(0x1c)

$C$DW$T$139	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$139, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$T$139, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$139, DW_AT_byte_size(0x40)
$C$DW$446	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$446, DW_AT_upper_bound(0x0f)
	.dwendtag $C$DW$T$139


$C$DW$T$1127	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$1127, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$T$1127, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1127, DW_AT_byte_size(0x0c)
$C$DW$447	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$447, DW_AT_upper_bound(0x02)
	.dwendtag $C$DW$T$1127

$C$DW$T$1128	.dwtag  DW_TAG_typedef, DW_AT_name("word")
	.dwattr $C$DW$T$1128, DW_AT_type(*$C$DW$T$138)
	.dwattr $C$DW$T$1128, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1128, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$1128, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$1128, DW_AT_decl_column(0x14)
$C$DW$T$631	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$631, DW_AT_type(*$C$DW$T$138)
$C$DW$T$632	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$632, DW_AT_type(*$C$DW$T$631)
	.dwattr $C$DW$T$632, DW_AT_address_class(0x20)

$C$DW$T$1129	.dwtag  DW_TAG_array_type
	.dwattr $C$DW$T$1129, DW_AT_type(*$C$DW$T$631)
	.dwattr $C$DW$T$1129, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1129, DW_AT_byte_size(0x10)
$C$DW$448	.dwtag  DW_TAG_subrange_type
	.dwattr $C$DW$448, DW_AT_upper_bound(0x03)
	.dwendtag $C$DW$T$1129

$C$DW$T$196	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UInt")
	.dwattr $C$DW$T$196, DW_AT_type(*$C$DW$T$11)
	.dwattr $C$DW$T$196, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$196, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$196, DW_AT_decl_line(0x22)
	.dwattr $C$DW$T$196, DW_AT_decl_column(0x19)
$C$DW$T$1130	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_timerId")
	.dwattr $C$DW$T$1130, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1130, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1130, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1130, DW_AT_decl_line(0xe0)
	.dwattr $C$DW$T$1130, DW_AT_decl_column(0x12)
$C$DW$T$1131	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_numConstructedSwis")
	.dwattr $C$DW$T$1131, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1131, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1131, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1131, DW_AT_decl_line(0xf6)
	.dwattr $C$DW$T$1131, DW_AT_decl_column(0x12)
$C$DW$T$1132	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_numPriorities")
	.dwattr $C$DW$T$1132, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1132, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1132, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1132, DW_AT_decl_line(0xdb)
	.dwattr $C$DW$T$1132, DW_AT_decl_column(0x12)
$C$DW$T$1133	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_stackAlignment")
	.dwattr $C$DW$T$1133, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1133, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1133, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$1133, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$1133, DW_AT_decl_column(0x12)
$C$DW$T$1134	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_numConstructedTasks")
	.dwattr $C$DW$T$1134, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1134, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1134, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1134, DW_AT_decl_line(0x1a9)
	.dwattr $C$DW$T$1134, DW_AT_decl_column(0x12)
$C$DW$T$1135	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_numPriorities")
	.dwattr $C$DW$T$1135, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1135, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1135, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1135, DW_AT_decl_line(0x16a)
	.dwattr $C$DW$T$1135, DW_AT_decl_column(0x12)
$C$DW$T$1136	.dwtag  DW_TAG_typedef, DW_AT_name("UInt")
	.dwattr $C$DW$T$1136, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1136, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1136, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1136, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$T$1136, DW_AT_decl_column(0x19)
$C$DW$T$1137	.dwtag  DW_TAG_typedef, DW_AT_name("Uns")
	.dwattr $C$DW$T$1137, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$1137, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1137, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1137, DW_AT_decl_line(0xfe)
	.dwattr $C$DW$T$1137, DW_AT_decl_column(0x19)

$C$DW$T$197	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$197, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$T$197, DW_AT_language(DW_LANG_C)
$C$DW$T$198	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$198, DW_AT_type(*$C$DW$T$197)
	.dwattr $C$DW$T$198, DW_AT_address_class(0x20)
$C$DW$T$1138	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_taskDisable")
	.dwattr $C$DW$T$1138, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$T$1138, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1138, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1138, DW_AT_decl_line(0xe9)
	.dwattr $C$DW$T$1138, DW_AT_decl_column(0x14)
$C$DW$T$1139	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_getStackAlignment_FxnT")
	.dwattr $C$DW$T$1139, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$T$1139, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1139, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$1139, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$1139, DW_AT_decl_column(0x14)
$C$DW$T$1140	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getNumTimers_FxnT")
	.dwattr $C$DW$T$1140, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$T$1140, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1140, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1140, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$T$1140, DW_AT_decl_column(0x14)
$C$DW$T$284	.dwtag  DW_TAG_volatile_type
	.dwattr $C$DW$T$284, DW_AT_type(*$C$DW$T$196)
$C$DW$T$1141	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__smpCurMask")
	.dwattr $C$DW$T$1141, DW_AT_type(*$C$DW$T$284)
	.dwattr $C$DW$T$1141, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1141, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1141, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$1141, DW_AT_decl_column(0x1b)
$C$DW$T$1142	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__smpCurSet")
	.dwattr $C$DW$T$1142, DW_AT_type(*$C$DW$T$284)
	.dwattr $C$DW$T$1142, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1142, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1142, DW_AT_decl_line(0x97)
	.dwattr $C$DW$T$1142, DW_AT_decl_column(0x1b)
$C$DW$T$1143	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1143, DW_AT_type(*$C$DW$T$284)
	.dwattr $C$DW$T$1143, DW_AT_address_class(0x20)
$C$DW$T$1144	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__smpCurMask")
	.dwattr $C$DW$T$1144, DW_AT_type(*$C$DW$T$1143)
	.dwattr $C$DW$T$1144, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1144, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1144, DW_AT_decl_line(0x9b)
	.dwattr $C$DW$T$1144, DW_AT_decl_column(0x1c)
$C$DW$T$1145	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__smpCurMask")
	.dwattr $C$DW$T$1145, DW_AT_type(*$C$DW$T$1144)
	.dwattr $C$DW$T$1145, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1145, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1145, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$T$1145, DW_AT_decl_column(0x3f)
$C$DW$T$1146	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__smpCurSet")
	.dwattr $C$DW$T$1146, DW_AT_type(*$C$DW$T$1143)
	.dwattr $C$DW$T$1146, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1146, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1146, DW_AT_decl_line(0x98)
	.dwattr $C$DW$T$1146, DW_AT_decl_column(0x1c)
$C$DW$T$1147	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__smpCurSet")
	.dwattr $C$DW$T$1147, DW_AT_type(*$C$DW$T$1146)
	.dwattr $C$DW$T$1147, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1147, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1147, DW_AT_decl_line(0x99)
	.dwattr $C$DW$T$1147, DW_AT_decl_column(0x3e)
$C$DW$T$12	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$12, DW_AT_encoding(DW_ATE_signed)
	.dwattr $C$DW$T$12, DW_AT_name("long")
	.dwattr $C$DW$T$12, DW_AT_byte_size(0x04)
$C$DW$T$1148	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Long")
	.dwattr $C$DW$T$1148, DW_AT_type(*$C$DW$T$12)
	.dwattr $C$DW$T$1148, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1148, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1148, DW_AT_decl_line(0x23)
	.dwattr $C$DW$T$1148, DW_AT_decl_column(0x19)
$C$DW$T$1149	.dwtag  DW_TAG_typedef, DW_AT_name("Long")
	.dwattr $C$DW$T$1149, DW_AT_type(*$C$DW$T$1148)
	.dwattr $C$DW$T$1149, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1149, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1149, DW_AT_decl_line(0xd9)
	.dwattr $C$DW$T$1149, DW_AT_decl_column(0x19)
$C$DW$T$13	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$13, DW_AT_encoding(DW_ATE_unsigned)
	.dwattr $C$DW$T$13, DW_AT_name("unsigned long")
	.dwattr $C$DW$T$13, DW_AT_byte_size(0x04)
$C$DW$T$1150	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_ULong")
	.dwattr $C$DW$T$1150, DW_AT_type(*$C$DW$T$13)
	.dwattr $C$DW$T$1150, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1150, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1150, DW_AT_decl_line(0x24)
	.dwattr $C$DW$T$1150, DW_AT_decl_column(0x19)
$C$DW$T$1151	.dwtag  DW_TAG_typedef, DW_AT_name("ULong")
	.dwattr $C$DW$T$1151, DW_AT_type(*$C$DW$T$1150)
	.dwattr $C$DW$T$1151, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1151, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1151, DW_AT_decl_line(0xda)
	.dwattr $C$DW$T$1151, DW_AT_decl_column(0x19)
$C$DW$T$14	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$14, DW_AT_encoding(DW_ATE_signed)
	.dwattr $C$DW$T$14, DW_AT_name("long long")
	.dwattr $C$DW$T$14, DW_AT_byte_size(0x08)
$C$DW$T$1152	.dwtag  DW_TAG_typedef, DW_AT_name("int64_t")
	.dwattr $C$DW$T$1152, DW_AT_type(*$C$DW$T$14)
	.dwattr $C$DW$T$1152, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1152, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1152, DW_AT_decl_line(0x32)
	.dwattr $C$DW$T$1152, DW_AT_decl_column(0x21)
$C$DW$T$1153	.dwtag  DW_TAG_typedef, DW_AT_name("int_fast64_t")
	.dwattr $C$DW$T$1153, DW_AT_type(*$C$DW$T$1152)
	.dwattr $C$DW$T$1153, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1153, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1153, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$1153, DW_AT_decl_column(0x17)
$C$DW$T$1154	.dwtag  DW_TAG_typedef, DW_AT_name("int_least64_t")
	.dwattr $C$DW$T$1154, DW_AT_type(*$C$DW$T$1152)
	.dwattr $C$DW$T$1154, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1154, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1154, DW_AT_decl_line(0x40)
	.dwattr $C$DW$T$1154, DW_AT_decl_column(0x17)
$C$DW$T$1155	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Int64")
	.dwattr $C$DW$T$1155, DW_AT_type(*$C$DW$T$1154)
	.dwattr $C$DW$T$1155, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1155, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$1155, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$1155, DW_AT_decl_column(0x1d)
$C$DW$T$1156	.dwtag  DW_TAG_typedef, DW_AT_name("Int64")
	.dwattr $C$DW$T$1156, DW_AT_type(*$C$DW$T$1155)
	.dwattr $C$DW$T$1156, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1156, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1156, DW_AT_decl_line(0x106)
	.dwattr $C$DW$T$1156, DW_AT_decl_column(0x19)
$C$DW$T$1157	.dwtag  DW_TAG_typedef, DW_AT_name("intmax_t")
	.dwattr $C$DW$T$1157, DW_AT_type(*$C$DW$T$14)
	.dwattr $C$DW$T$1157, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1157, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1157, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$1157, DW_AT_decl_column(0x20)
$C$DW$T$1158	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_LLong")
	.dwattr $C$DW$T$1158, DW_AT_type(*$C$DW$T$14)
	.dwattr $C$DW$T$1158, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1158, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1158, DW_AT_decl_line(0x83)
	.dwattr $C$DW$T$1158, DW_AT_decl_column(0x21)
$C$DW$T$1159	.dwtag  DW_TAG_typedef, DW_AT_name("LLong")
	.dwattr $C$DW$T$1159, DW_AT_type(*$C$DW$T$1158)
	.dwattr $C$DW$T$1159, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1159, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1159, DW_AT_decl_line(0xdb)
	.dwattr $C$DW$T$1159, DW_AT_decl_column(0x19)
$C$DW$T$15	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$15, DW_AT_encoding(DW_ATE_unsigned)
	.dwattr $C$DW$T$15, DW_AT_name("unsigned long long")
	.dwattr $C$DW$T$15, DW_AT_byte_size(0x08)
$C$DW$T$1160	.dwtag  DW_TAG_typedef, DW_AT_name("uint64_t")
	.dwattr $C$DW$T$1160, DW_AT_type(*$C$DW$T$15)
	.dwattr $C$DW$T$1160, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1160, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1160, DW_AT_decl_line(0x33)
	.dwattr $C$DW$T$1160, DW_AT_decl_column(0x20)
$C$DW$T$1161	.dwtag  DW_TAG_typedef, DW_AT_name("uint_fast64_t")
	.dwattr $C$DW$T$1161, DW_AT_type(*$C$DW$T$1160)
	.dwattr $C$DW$T$1161, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1161, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1161, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$1161, DW_AT_decl_column(0x16)
$C$DW$T$1162	.dwtag  DW_TAG_typedef, DW_AT_name("uint_least64_t")
	.dwattr $C$DW$T$1162, DW_AT_type(*$C$DW$T$1160)
	.dwattr $C$DW$T$1162, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1162, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1162, DW_AT_decl_line(0x41)
	.dwattr $C$DW$T$1162, DW_AT_decl_column(0x16)
$C$DW$T$1163	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_UInt64")
	.dwattr $C$DW$T$1163, DW_AT_type(*$C$DW$T$1162)
	.dwattr $C$DW$T$1163, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1163, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$1163, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$1163, DW_AT_decl_column(0x1e)
$C$DW$T$1164	.dwtag  DW_TAG_typedef, DW_AT_name("UInt64")
	.dwattr $C$DW$T$1164, DW_AT_type(*$C$DW$T$1163)
	.dwattr $C$DW$T$1164, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1164, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1164, DW_AT_decl_line(0x107)
	.dwattr $C$DW$T$1164, DW_AT_decl_column(0x19)
$C$DW$T$1165	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Bits64")
	.dwattr $C$DW$T$1165, DW_AT_type(*$C$DW$T$1160)
	.dwattr $C$DW$T$1165, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1165, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/targets/std.h")
	.dwattr $C$DW$T$1165, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$1165, DW_AT_decl_column(0x19)
$C$DW$T$1166	.dwtag  DW_TAG_typedef, DW_AT_name("Bits64")
	.dwattr $C$DW$T$1166, DW_AT_type(*$C$DW$T$1165)
	.dwattr $C$DW$T$1166, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1166, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1166, DW_AT_decl_line(0x11b)
	.dwattr $C$DW$T$1166, DW_AT_decl_column(0x19)
$C$DW$T$1167	.dwtag  DW_TAG_typedef, DW_AT_name("uintmax_t")
	.dwattr $C$DW$T$1167, DW_AT_type(*$C$DW$T$15)
	.dwattr $C$DW$T$1167, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1167, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdint.h")
	.dwattr $C$DW$T$1167, DW_AT_decl_line(0x57)
	.dwattr $C$DW$T$1167, DW_AT_decl_column(0x20)
$C$DW$T$1168	.dwtag  DW_TAG_typedef, DW_AT_name("word64")
	.dwattr $C$DW$T$1168, DW_AT_type(*$C$DW$T$15)
	.dwattr $C$DW$T$1168, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1168, DW_AT_decl_file("C:\cyassl\cyassl\ctaocrypt\types.h")
	.dwattr $C$DW$T$1168, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$1168, DW_AT_decl_column(0x20)
$C$DW$T$1169	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_ULLong")
	.dwattr $C$DW$T$1169, DW_AT_type(*$C$DW$T$15)
	.dwattr $C$DW$T$1169, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1169, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1169, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1169, DW_AT_decl_column(0x21)
$C$DW$T$1170	.dwtag  DW_TAG_typedef, DW_AT_name("ULLong")
	.dwattr $C$DW$T$1170, DW_AT_type(*$C$DW$T$1169)
	.dwattr $C$DW$T$1170, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1170, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1170, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$1170, DW_AT_decl_column(0x19)
$C$DW$T$16	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$16, DW_AT_encoding(DW_ATE_float)
	.dwattr $C$DW$T$16, DW_AT_name("float")
	.dwattr $C$DW$T$16, DW_AT_byte_size(0x04)
$C$DW$T$131	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Float")
	.dwattr $C$DW$T$131, DW_AT_type(*$C$DW$T$16)
	.dwattr $C$DW$T$131, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$131, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$131, DW_AT_decl_line(0x25)
	.dwattr $C$DW$T$131, DW_AT_decl_column(0x19)
$C$DW$T$1171	.dwtag  DW_TAG_typedef, DW_AT_name("Float")
	.dwattr $C$DW$T$1171, DW_AT_type(*$C$DW$T$131)
	.dwattr $C$DW$T$1171, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1171, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1171, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$T$1171, DW_AT_decl_column(0x19)
$C$DW$T$17	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$17, DW_AT_encoding(DW_ATE_float)
	.dwattr $C$DW$T$17, DW_AT_name("double")
	.dwattr $C$DW$T$17, DW_AT_byte_size(0x08)
$C$DW$T$1172	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Double")
	.dwattr $C$DW$T$1172, DW_AT_type(*$C$DW$T$17)
	.dwattr $C$DW$T$1172, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1172, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1172, DW_AT_decl_line(0x26)
	.dwattr $C$DW$T$1172, DW_AT_decl_column(0x19)
$C$DW$T$1173	.dwtag  DW_TAG_typedef, DW_AT_name("Double")
	.dwattr $C$DW$T$1173, DW_AT_type(*$C$DW$T$1172)
	.dwattr $C$DW$T$1173, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1173, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1173, DW_AT_decl_line(0xde)
	.dwattr $C$DW$T$1173, DW_AT_decl_column(0x19)
$C$DW$T$18	.dwtag  DW_TAG_base_type
	.dwattr $C$DW$T$18, DW_AT_encoding(DW_ATE_float)
	.dwattr $C$DW$T$18, DW_AT_name("long double")
	.dwattr $C$DW$T$18, DW_AT_byte_size(0x08)
$C$DW$T$1174	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_LDouble")
	.dwattr $C$DW$T$1174, DW_AT_type(*$C$DW$T$18)
	.dwattr $C$DW$T$1174, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1174, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1174, DW_AT_decl_line(0x27)
	.dwattr $C$DW$T$1174, DW_AT_decl_column(0x19)
$C$DW$T$1175	.dwtag  DW_TAG_typedef, DW_AT_name("LDouble")
	.dwattr $C$DW$T$1175, DW_AT_type(*$C$DW$T$1174)
	.dwattr $C$DW$T$1175, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1175, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1175, DW_AT_decl_line(0xdf)
	.dwattr $C$DW$T$1175, DW_AT_decl_column(0x19)
$C$DW$T$366	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$366, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$366, DW_AT_address_class(0x20)
$C$DW$T$1176	.dwtag  DW_TAG_typedef, DW_AT_name("__builtin_va_list")
	.dwattr $C$DW$T$1176, DW_AT_type(*$C$DW$T$366)
	.dwattr $C$DW$T$1176, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1176, DW_AT_decl_file("C:/cyassl/ctaocrypt/src/chacha.c")
	.dwattr $C$DW$T$1176, DW_AT_decl_line(0xf7)
	.dwattr $C$DW$T$1176, DW_AT_decl_column(0x01)
$C$DW$T$367	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_String")
	.dwattr $C$DW$T$367, DW_AT_type(*$C$DW$T$366)
	.dwattr $C$DW$T$367, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$367, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$367, DW_AT_decl_line(0x30)
	.dwattr $C$DW$T$367, DW_AT_decl_column(0x1a)
$C$DW$T$1177	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_heapSection")
	.dwattr $C$DW$T$1177, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$1177, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1177, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1177, DW_AT_decl_line(0x108)
	.dwattr $C$DW$T$1177, DW_AT_decl_column(0x14)
$C$DW$T$1178	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_nameEmpty")
	.dwattr $C$DW$T$1178, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$1178, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1178, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1178, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$T$1178, DW_AT_decl_column(0x14)
$C$DW$T$1179	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_nameStatic")
	.dwattr $C$DW$T$1179, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$1179, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1179, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1179, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$T$1179, DW_AT_decl_column(0x14)
$C$DW$T$1180	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_nameUnknown")
	.dwattr $C$DW$T$1180, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$1180, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1180, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1180, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$1180, DW_AT_decl_column(0x14)
$C$DW$T$1181	.dwtag  DW_TAG_typedef, DW_AT_name("String")
	.dwattr $C$DW$T$1181, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$1181, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1181, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1181, DW_AT_decl_line(0xeb)
	.dwattr $C$DW$T$1181, DW_AT_decl_column(0x19)
$C$DW$T$773	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$773, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$T$773, DW_AT_address_class(0x20)
$C$DW$T$447	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$447, DW_AT_type(*$C$DW$T$6)
$C$DW$T$448	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$448, DW_AT_type(*$C$DW$T$447)
	.dwattr $C$DW$T$448, DW_AT_address_class(0x20)
$C$DW$T$788	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$788, DW_AT_type(*$C$DW$T$448)
$C$DW$T$449	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_CString")
	.dwattr $C$DW$T$449, DW_AT_type(*$C$DW$T$448)
	.dwattr $C$DW$T$449, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$449, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$449, DW_AT_decl_line(0x31)
	.dwattr $C$DW$T$449, DW_AT_decl_column(0x1a)
$C$DW$T$1182	.dwtag  DW_TAG_typedef, DW_AT_name("CString")
	.dwattr $C$DW$T$1182, DW_AT_type(*$C$DW$T$449)
	.dwattr $C$DW$T$1182, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1182, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1182, DW_AT_decl_line(0xec)
	.dwattr $C$DW$T$1182, DW_AT_decl_column(0x19)
$C$DW$T$189	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_Char")
	.dwattr $C$DW$T$189, DW_AT_type(*$C$DW$T$6)
	.dwattr $C$DW$T$189, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$189, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$189, DW_AT_decl_line(0x1d)
	.dwattr $C$DW$T$189, DW_AT_decl_column(0x19)
$C$DW$T$1183	.dwtag  DW_TAG_typedef, DW_AT_name("Char")
	.dwattr $C$DW$T$1183, DW_AT_type(*$C$DW$T$189)
	.dwattr $C$DW$T$1183, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1183, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1183, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$1183, DW_AT_decl_column(0x19)
$C$DW$T$1184	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Instance_State__stack")
	.dwattr $C$DW$T$1184, DW_AT_type(*$C$DW$T$189)
	.dwattr $C$DW$T$1184, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1184, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1184, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$1184, DW_AT_decl_column(0x12)
$C$DW$T$1185	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_xdc_runtime_Text_charTab")
	.dwattr $C$DW$T$1185, DW_AT_type(*$C$DW$T$189)
	.dwattr $C$DW$T$1185, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1185, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1185, DW_AT_decl_line(0xd2)
	.dwattr $C$DW$T$1185, DW_AT_decl_column(0x12)
$C$DW$T$190	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$190, DW_AT_type(*$C$DW$T$189)
	.dwattr $C$DW$T$190, DW_AT_address_class(0x20)
$C$DW$T$352	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Instance_State__stack")
	.dwattr $C$DW$T$352, DW_AT_type(*$C$DW$T$190)
	.dwattr $C$DW$T$352, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$352, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$352, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$T$352, DW_AT_decl_column(0x13)
$C$DW$T$353	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Instance_State__stack")
	.dwattr $C$DW$T$353, DW_AT_type(*$C$DW$T$352)
	.dwattr $C$DW$T$353, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$353, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$353, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$T$353, DW_AT_decl_column(0x3c)
$C$DW$T$1186	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_xdc_runtime_Text_charTab")
	.dwattr $C$DW$T$1186, DW_AT_type(*$C$DW$T$190)
	.dwattr $C$DW$T$1186, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1186, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1186, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$1186, DW_AT_decl_column(0x13)
$C$DW$T$1187	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_xdc_runtime_Text_charTab")
	.dwattr $C$DW$T$1187, DW_AT_type(*$C$DW$T$1186)
	.dwattr $C$DW$T$1187, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1187, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1187, DW_AT_decl_line(0xd4)
	.dwattr $C$DW$T$1187, DW_AT_decl_column(0x2b)
$C$DW$T$1188	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_charTab")
	.dwattr $C$DW$T$1188, DW_AT_type(*$C$DW$T$1187)
	.dwattr $C$DW$T$1188, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1188, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1188, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$1188, DW_AT_decl_column(0x27)
$C$DW$T$454	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$454, DW_AT_type(*$C$DW$T$190)
	.dwattr $C$DW$T$454, DW_AT_address_class(0x20)

$C$DW$T$141	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$141, DW_AT_name("__va_list")
	.dwattr $C$DW$T$141, DW_AT_byte_size(0x04)
$C$DW$449	.dwtag  DW_TAG_member
	.dwattr $C$DW$449, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$449, DW_AT_name("__ap")
	.dwattr $C$DW$449, DW_AT_TI_symbol_name("__ap")
	.dwattr $C$DW$449, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$449, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$449, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdarg.h")
	.dwattr $C$DW$449, DW_AT_decl_line(0x32)
	.dwattr $C$DW$449, DW_AT_decl_column(0x0c)
	.dwendtag $C$DW$T$141

	.dwattr $C$DW$T$141, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdarg.h")
	.dwattr $C$DW$T$141, DW_AT_decl_line(0x31)
	.dwattr $C$DW$T$141, DW_AT_decl_column(0x10)
$C$DW$T$1189	.dwtag  DW_TAG_typedef, DW_AT_name("va_list")
	.dwattr $C$DW$T$1189, DW_AT_type(*$C$DW$T$141)
	.dwattr $C$DW$T$1189, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1189, DW_AT_decl_file("c:/ti/ccsv6/tools/compiler/arm_5.1.6/include/stdarg.h")
	.dwattr $C$DW$T$1189, DW_AT_decl_line(0x33)
	.dwattr $C$DW$T$1189, DW_AT_decl_column(0x03)
$C$DW$T$1190	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_VaList")
	.dwattr $C$DW$T$1190, DW_AT_type(*$C$DW$T$1189)
	.dwattr $C$DW$T$1190, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1190, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1190, DW_AT_decl_line(0x29)
	.dwattr $C$DW$T$1190, DW_AT_decl_column(0x19)
$C$DW$T$1191	.dwtag  DW_TAG_typedef, DW_AT_name("VaList")
	.dwattr $C$DW$T$1191, DW_AT_type(*$C$DW$T$1190)
	.dwattr $C$DW$T$1191, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1191, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/std.h")
	.dwattr $C$DW$T$1191, DW_AT_decl_line(0xe1)
	.dwattr $C$DW$T$1191, DW_AT_decl_column(0x19)

$C$DW$T$1192	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1192, DW_AT_name("ti_sysbios_BIOS_LibType")
	.dwattr $C$DW$T$1192, DW_AT_byte_size(0x01)
$C$DW$450	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_LibType_Instrumented"), DW_AT_const_value(0x00)
	.dwattr $C$DW$450, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$450, DW_AT_decl_line(0x59)
	.dwattr $C$DW$450, DW_AT_decl_column(0x05)
$C$DW$451	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_LibType_NonInstrumented"), DW_AT_const_value(0x01)
	.dwattr $C$DW$451, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$451, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$451, DW_AT_decl_column(0x05)
$C$DW$452	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_LibType_Custom"), DW_AT_const_value(0x02)
	.dwattr $C$DW$452, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$452, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$452, DW_AT_decl_column(0x05)
$C$DW$453	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_LibType_Debug"), DW_AT_const_value(0x03)
	.dwattr $C$DW$453, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$453, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$453, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1192

	.dwattr $C$DW$T$1192, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1192, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$1192, DW_AT_decl_column(0x06)
$C$DW$T$1193	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_LibType")
	.dwattr $C$DW$T$1193, DW_AT_type(*$C$DW$T$1192)
	.dwattr $C$DW$T$1193, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1193, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1193, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$1193, DW_AT_decl_column(0x26)

$C$DW$T$19	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$19, DW_AT_name("ti_sysbios_BIOS_Module_State")
	.dwattr $C$DW$T$19, DW_AT_declaration
	.dwendtag $C$DW$T$19

	.dwattr $C$DW$T$19, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$19, DW_AT_decl_line(0x11)
	.dwattr $C$DW$T$19, DW_AT_decl_column(0x10)
$C$DW$T$1194	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_Module_State")
	.dwattr $C$DW$T$1194, DW_AT_type(*$C$DW$T$19)
	.dwattr $C$DW$T$1194, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1194, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$1194, DW_AT_decl_line(0x11)
	.dwattr $C$DW$T$1194, DW_AT_decl_column(0x2d)

$C$DW$T$157	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$157, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Fxns__")
	.dwattr $C$DW$T$157, DW_AT_byte_size(0x24)
$C$DW$454	.dwtag  DW_TAG_member
	.dwattr $C$DW$454, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$454, DW_AT_name("__base")
	.dwattr $C$DW$454, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$454, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$454, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$454, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$454, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$454, DW_AT_decl_column(0x1d)
$C$DW$455	.dwtag  DW_TAG_member
	.dwattr $C$DW$455, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$455, DW_AT_name("__sysp")
	.dwattr $C$DW$455, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$455, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$455, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$455, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$455, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$455, DW_AT_decl_column(0x27)
$C$DW$456	.dwtag  DW_TAG_member
	.dwattr $C$DW$456, DW_AT_type(*$C$DW$T$150)
	.dwattr $C$DW$456, DW_AT_name("query")
	.dwattr $C$DW$456, DW_AT_TI_symbol_name("query")
	.dwattr $C$DW$456, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$456, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$456, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$456, DW_AT_decl_line(0xb1)
	.dwattr $C$DW$456, DW_AT_decl_column(0x10)
$C$DW$457	.dwtag  DW_TAG_member
	.dwattr $C$DW$457, DW_AT_type(*$C$DW$T$154)
	.dwattr $C$DW$457, DW_AT_name("enter")
	.dwattr $C$DW$457, DW_AT_TI_symbol_name("enter")
	.dwattr $C$DW$457, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$457, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$457, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$457, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$457, DW_AT_decl_column(0x10)
$C$DW$458	.dwtag  DW_TAG_member
	.dwattr $C$DW$458, DW_AT_type(*$C$DW$T$156)
	.dwattr $C$DW$458, DW_AT_name("leave")
	.dwattr $C$DW$458, DW_AT_TI_symbol_name("leave")
	.dwattr $C$DW$458, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$458, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$458, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$458, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$458, DW_AT_decl_column(0x10)
$C$DW$459	.dwtag  DW_TAG_member
	.dwattr $C$DW$459, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$459, DW_AT_name("__sfxns")
	.dwattr $C$DW$459, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$459, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$459, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$459, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$459, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$459, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$157

	.dwattr $C$DW$T$157, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$157, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$157, DW_AT_decl_column(0x08)
$C$DW$T$164	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Fxns__")
	.dwattr $C$DW$T$164, DW_AT_type(*$C$DW$T$157)
	.dwattr $C$DW$T$164, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$164, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$164, DW_AT_decl_line(0x17)
	.dwattr $C$DW$T$164, DW_AT_decl_column(0x34)
$C$DW$T$165	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$165, DW_AT_type(*$C$DW$T$164)
$C$DW$T$166	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$166, DW_AT_type(*$C$DW$T$165)
	.dwattr $C$DW$T$166, DW_AT_address_class(0x20)
$C$DW$T$1195	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Module")
	.dwattr $C$DW$T$1195, DW_AT_type(*$C$DW$T$166)
	.dwattr $C$DW$T$1195, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1195, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$1195, DW_AT_decl_line(0x18)
	.dwattr $C$DW$T$1195, DW_AT_decl_column(0x34)

$C$DW$T$163	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$163, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Params")
	.dwattr $C$DW$T$163, DW_AT_byte_size(0x18)
$C$DW$460	.dwtag  DW_TAG_member
	.dwattr $C$DW$460, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$460, DW_AT_name("__size")
	.dwattr $C$DW$460, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$460, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$460, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$460, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$460, DW_AT_decl_line(0x9b)
	.dwattr $C$DW$460, DW_AT_decl_column(0x0c)
$C$DW$461	.dwtag  DW_TAG_member
	.dwattr $C$DW$461, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$461, DW_AT_name("__self")
	.dwattr $C$DW$461, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$461, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$461, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$461, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$461, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$461, DW_AT_decl_column(0x11)
$C$DW$462	.dwtag  DW_TAG_member
	.dwattr $C$DW$462, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$462, DW_AT_name("__fxns")
	.dwattr $C$DW$462, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$462, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$462, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$462, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$462, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$462, DW_AT_decl_column(0x0b)
$C$DW$463	.dwtag  DW_TAG_member
	.dwattr $C$DW$463, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$463, DW_AT_name("instance")
	.dwattr $C$DW$463, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$463, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$463, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$463, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$463, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$463, DW_AT_decl_column(0x23)
$C$DW$464	.dwtag  DW_TAG_member
	.dwattr $C$DW$464, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$464, DW_AT_name("__iprms")
	.dwattr $C$DW$464, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$464, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$464, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$464, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$464, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$464, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$163

	.dwattr $C$DW$T$163, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$163, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$163, DW_AT_decl_column(0x08)
$C$DW$T$1196	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Params")
	.dwattr $C$DW$T$1196, DW_AT_type(*$C$DW$T$163)
	.dwattr $C$DW$T$1196, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1196, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$1196, DW_AT_decl_line(0x19)
	.dwattr $C$DW$T$1196, DW_AT_decl_column(0x34)

$C$DW$T$170	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$170, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Struct")
	.dwattr $C$DW$T$170, DW_AT_byte_size(0x08)
$C$DW$465	.dwtag  DW_TAG_member
	.dwattr $C$DW$465, DW_AT_type(*$C$DW$T$166)
	.dwattr $C$DW$465, DW_AT_name("__fxns")
	.dwattr $C$DW$465, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$465, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$465, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$465, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$465, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$465, DW_AT_decl_column(0x30)
$C$DW$466	.dwtag  DW_TAG_member
	.dwattr $C$DW$466, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$466, DW_AT_name("__name")
	.dwattr $C$DW$466, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$466, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$466, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$466, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$466, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$466, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$170

	.dwattr $C$DW$T$170, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$170, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$170, DW_AT_decl_column(0x08)

$C$DW$T$1197	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1197, DW_AT_name("ti_sysbios_BIOS_RtsLockType")
	.dwattr $C$DW$T$1197, DW_AT_byte_size(0x01)
$C$DW$467	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_NoLocking"), DW_AT_const_value(0x00)
	.dwattr $C$DW$467, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$467, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$467, DW_AT_decl_column(0x05)
$C$DW$468	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_GateHwi"), DW_AT_const_value(0x01)
	.dwattr $C$DW$468, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$468, DW_AT_decl_line(0x50)
	.dwattr $C$DW$468, DW_AT_decl_column(0x05)
$C$DW$469	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_GateSwi"), DW_AT_const_value(0x02)
	.dwattr $C$DW$469, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$469, DW_AT_decl_line(0x51)
	.dwattr $C$DW$469, DW_AT_decl_column(0x05)
$C$DW$470	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_GateMutex"), DW_AT_const_value(0x03)
	.dwattr $C$DW$470, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$470, DW_AT_decl_line(0x52)
	.dwattr $C$DW$470, DW_AT_decl_column(0x05)
$C$DW$471	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_GateMutexPri"), DW_AT_const_value(0x04)
	.dwattr $C$DW$471, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$471, DW_AT_decl_line(0x53)
	.dwattr $C$DW$471, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1197

	.dwattr $C$DW$T$1197, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1197, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$1197, DW_AT_decl_column(0x06)
$C$DW$T$1198	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_RtsLockType")
	.dwattr $C$DW$T$1198, DW_AT_type(*$C$DW$T$1197)
	.dwattr $C$DW$T$1198, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1198, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1198, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$1198, DW_AT_decl_column(0x2a)

$C$DW$T$1199	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1199, DW_AT_name("ti_sysbios_BIOS_ThreadType")
	.dwattr $C$DW$T$1199, DW_AT_byte_size(0x01)
$C$DW$472	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_ThreadType_Hwi"), DW_AT_const_value(0x00)
	.dwattr $C$DW$472, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$472, DW_AT_decl_line(0x46)
	.dwattr $C$DW$472, DW_AT_decl_column(0x05)
$C$DW$473	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_ThreadType_Swi"), DW_AT_const_value(0x01)
	.dwattr $C$DW$473, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$473, DW_AT_decl_line(0x47)
	.dwattr $C$DW$473, DW_AT_decl_column(0x05)
$C$DW$474	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_ThreadType_Task"), DW_AT_const_value(0x02)
	.dwattr $C$DW$474, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$474, DW_AT_decl_line(0x48)
	.dwattr $C$DW$474, DW_AT_decl_column(0x05)
$C$DW$475	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_BIOS_ThreadType_Main"), DW_AT_const_value(0x03)
	.dwattr $C$DW$475, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$475, DW_AT_decl_line(0x49)
	.dwattr $C$DW$475, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1199

	.dwattr $C$DW$T$1199, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1199, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$1199, DW_AT_decl_column(0x06)
$C$DW$T$1200	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_ThreadType")
	.dwattr $C$DW$T$1200, DW_AT_type(*$C$DW$T$1199)
	.dwattr $C$DW$T$1200, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1200, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1200, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$1200, DW_AT_decl_column(0x29)
$C$DW$T$1201	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_BIOS_Module_State__smpThreadType")
	.dwattr $C$DW$T$1201, DW_AT_type(*$C$DW$T$1200)
	.dwattr $C$DW$T$1201, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1201, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1201, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$1201, DW_AT_decl_column(0x24)
$C$DW$T$1202	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1202, DW_AT_type(*$C$DW$T$1200)
	.dwattr $C$DW$T$1202, DW_AT_address_class(0x20)
$C$DW$T$1203	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_BIOS_Module_State__smpThreadType")
	.dwattr $C$DW$T$1203, DW_AT_type(*$C$DW$T$1202)
	.dwattr $C$DW$T$1203, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1203, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1203, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$1203, DW_AT_decl_column(0x25)
$C$DW$T$1204	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_BIOS_Module_State__smpThreadType")
	.dwattr $C$DW$T$1204, DW_AT_type(*$C$DW$T$1203)
	.dwattr $C$DW$T$1204, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1204, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1204, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$1204, DW_AT_decl_column(0x3e)

$C$DW$T$171	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$171, DW_AT_name("ti_sysbios_BIOS_intSize")
	.dwattr $C$DW$T$171, DW_AT_byte_size(0x04)
$C$DW$476	.dwtag  DW_TAG_member
	.dwattr $C$DW$476, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$476, DW_AT_name("intSize")
	.dwattr $C$DW$476, DW_AT_TI_symbol_name("intSize")
	.dwattr $C$DW$476, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$476, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$476, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$476, DW_AT_decl_line(0x70)
	.dwattr $C$DW$476, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$171

	.dwattr $C$DW$T$171, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$171, DW_AT_decl_line(0x6f)
	.dwattr $C$DW$T$171, DW_AT_decl_column(0x08)
$C$DW$T$1205	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_intSize")
	.dwattr $C$DW$T$1205, DW_AT_type(*$C$DW$T$171)
	.dwattr $C$DW$T$1205, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1205, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$1205, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$1205, DW_AT_decl_column(0x28)

$C$DW$T$20	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$20, DW_AT_name("ti_sysbios_interfaces_ICache_Fxns__")
	.dwattr $C$DW$T$20, DW_AT_declaration
	.dwendtag $C$DW$T$20

	.dwattr $C$DW$T$20, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$20, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$20, DW_AT_decl_column(0x10)
$C$DW$T$1206	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ICache_Fxns__")
	.dwattr $C$DW$T$1206, DW_AT_type(*$C$DW$T$20)
	.dwattr $C$DW$T$1206, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1206, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1206, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$1206, DW_AT_decl_column(0x34)
$C$DW$T$1207	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1207, DW_AT_type(*$C$DW$T$1206)
$C$DW$T$1208	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1208, DW_AT_type(*$C$DW$T$1207)
	.dwattr $C$DW$T$1208, DW_AT_address_class(0x20)
$C$DW$T$1209	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ICache_Module")
	.dwattr $C$DW$T$1209, DW_AT_type(*$C$DW$T$1208)
	.dwattr $C$DW$T$1209, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1209, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1209, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$1209, DW_AT_decl_column(0x34)

$C$DW$T$21	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$21, DW_AT_name("ti_sysbios_interfaces_ICore_Fxns__")
	.dwattr $C$DW$T$21, DW_AT_declaration
	.dwendtag $C$DW$T$21

	.dwattr $C$DW$T$21, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$21, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$21, DW_AT_decl_column(0x10)
$C$DW$T$1210	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ICore_Fxns__")
	.dwattr $C$DW$T$1210, DW_AT_type(*$C$DW$T$21)
	.dwattr $C$DW$T$1210, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1210, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1210, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$1210, DW_AT_decl_column(0x33)
$C$DW$T$1211	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1211, DW_AT_type(*$C$DW$T$1210)
$C$DW$T$1212	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1212, DW_AT_type(*$C$DW$T$1211)
	.dwattr $C$DW$T$1212, DW_AT_address_class(0x20)
$C$DW$T$1213	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ICore_Module")
	.dwattr $C$DW$T$1213, DW_AT_type(*$C$DW$T$1212)
	.dwattr $C$DW$T$1213, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1213, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1213, DW_AT_decl_line(0x11)
	.dwattr $C$DW$T$1213, DW_AT_decl_column(0x33)

$C$DW$T$22	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$22, DW_AT_name("ti_sysbios_interfaces_IHwi_Fxns__")
	.dwattr $C$DW$T$22, DW_AT_declaration
	.dwendtag $C$DW$T$22

	.dwattr $C$DW$T$22, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$22, DW_AT_decl_line(0x19)
	.dwattr $C$DW$T$22, DW_AT_decl_column(0x10)
$C$DW$T$172	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_Fxns__")
	.dwattr $C$DW$T$172, DW_AT_type(*$C$DW$T$22)
	.dwattr $C$DW$T$172, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$172, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$172, DW_AT_decl_line(0x19)
	.dwattr $C$DW$T$172, DW_AT_decl_column(0x32)
$C$DW$T$173	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$173, DW_AT_type(*$C$DW$T$172)
	.dwattr $C$DW$T$173, DW_AT_address_class(0x20)
$C$DW$T$1214	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1214, DW_AT_type(*$C$DW$T$172)
$C$DW$T$1215	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1215, DW_AT_type(*$C$DW$T$1214)
	.dwattr $C$DW$T$1215, DW_AT_address_class(0x20)
$C$DW$T$1216	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_Module")
	.dwattr $C$DW$T$1216, DW_AT_type(*$C$DW$T$1215)
	.dwattr $C$DW$T$1216, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1216, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1216, DW_AT_decl_line(0x1a)
	.dwattr $C$DW$T$1216, DW_AT_decl_column(0x32)

$C$DW$T$23	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$23, DW_AT_name("ti_sysbios_interfaces_IHwi_HookSet")
	.dwattr $C$DW$T$23, DW_AT_declaration
	.dwendtag $C$DW$T$23

	.dwattr $C$DW$T$23, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$23, DW_AT_decl_line(0x17)
	.dwattr $C$DW$T$23, DW_AT_decl_column(0x10)
$C$DW$T$1217	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_HookSet")
	.dwattr $C$DW$T$1217, DW_AT_type(*$C$DW$T$23)
	.dwattr $C$DW$T$1217, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1217, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1217, DW_AT_decl_line(0x17)
	.dwattr $C$DW$T$1217, DW_AT_decl_column(0x33)

$C$DW$T$24	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$24, DW_AT_name("ti_sysbios_interfaces_IHwi_Params")
	.dwattr $C$DW$T$24, DW_AT_declaration
	.dwendtag $C$DW$T$24

	.dwattr $C$DW$T$24, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$24, DW_AT_decl_line(0x1b)
	.dwattr $C$DW$T$24, DW_AT_decl_column(0x10)
$C$DW$T$1218	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_Params")
	.dwattr $C$DW$T$1218, DW_AT_type(*$C$DW$T$24)
	.dwattr $C$DW$T$1218, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1218, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1218, DW_AT_decl_line(0x1b)
	.dwattr $C$DW$T$1218, DW_AT_decl_column(0x32)

$C$DW$T$25	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$25, DW_AT_name("ti_sysbios_interfaces_IHwi_StackInfo")
	.dwattr $C$DW$T$25, DW_AT_declaration
	.dwendtag $C$DW$T$25

	.dwattr $C$DW$T$25, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$25, DW_AT_decl_line(0x18)
	.dwattr $C$DW$T$25, DW_AT_decl_column(0x10)
$C$DW$T$1219	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_StackInfo")
	.dwattr $C$DW$T$1219, DW_AT_type(*$C$DW$T$25)
	.dwattr $C$DW$T$1219, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1219, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1219, DW_AT_decl_line(0x18)
	.dwattr $C$DW$T$1219, DW_AT_decl_column(0x35)

$C$DW$T$176	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$176, DW_AT_name("ti_sysbios_interfaces_IHwi___Object")
	.dwattr $C$DW$T$176, DW_AT_byte_size(0x08)
$C$DW$477	.dwtag  DW_TAG_member
	.dwattr $C$DW$477, DW_AT_type(*$C$DW$T$173)
	.dwattr $C$DW$477, DW_AT_name("__fxns")
	.dwattr $C$DW$477, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$477, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$477, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$477, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$477, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$477, DW_AT_decl_column(0x59)
$C$DW$478	.dwtag  DW_TAG_member
	.dwattr $C$DW$478, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$478, DW_AT_name("__label")
	.dwattr $C$DW$478, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$478, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$478, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$478, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$478, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$478, DW_AT_decl_column(0x6c)
	.dwendtag $C$DW$T$176

	.dwattr $C$DW$T$176, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$176, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$T$176, DW_AT_decl_column(0x10)
$C$DW$T$1220	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1220, DW_AT_type(*$C$DW$T$176)
	.dwattr $C$DW$T$1220, DW_AT_address_class(0x20)
$C$DW$T$1221	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IHwi_Handle")
	.dwattr $C$DW$T$1221, DW_AT_type(*$C$DW$T$1220)
	.dwattr $C$DW$T$1221, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1221, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1221, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$T$1221, DW_AT_decl_column(0x78)

$C$DW$T$26	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$26, DW_AT_name("ti_sysbios_interfaces_IIntrinsicsSupport_Fxns__")
	.dwattr $C$DW$T$26, DW_AT_declaration
	.dwendtag $C$DW$T$26

	.dwattr $C$DW$T$26, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$26, DW_AT_decl_line(0x40)
	.dwattr $C$DW$T$26, DW_AT_decl_column(0x10)
$C$DW$T$1222	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IIntrinsicsSupport_Fxns__")
	.dwattr $C$DW$T$1222, DW_AT_type(*$C$DW$T$26)
	.dwattr $C$DW$T$1222, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1222, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1222, DW_AT_decl_line(0x40)
	.dwattr $C$DW$T$1222, DW_AT_decl_column(0x40)
$C$DW$T$1223	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1223, DW_AT_type(*$C$DW$T$1222)
$C$DW$T$1224	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1224, DW_AT_type(*$C$DW$T$1223)
	.dwattr $C$DW$T$1224, DW_AT_address_class(0x20)
$C$DW$T$1225	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IIntrinsicsSupport_Module")
	.dwattr $C$DW$T$1225, DW_AT_type(*$C$DW$T$1224)
	.dwattr $C$DW$T$1225, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1225, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1225, DW_AT_decl_line(0x41)
	.dwattr $C$DW$T$1225, DW_AT_decl_column(0x40)

$C$DW$T$27	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$27, DW_AT_name("ti_sysbios_interfaces_IPower_Fxns__")
	.dwattr $C$DW$T$27, DW_AT_declaration
	.dwendtag $C$DW$T$27

	.dwattr $C$DW$T$27, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$27, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$27, DW_AT_decl_column(0x10)
$C$DW$T$1226	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IPower_Fxns__")
	.dwattr $C$DW$T$1226, DW_AT_type(*$C$DW$T$27)
	.dwattr $C$DW$T$1226, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1226, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1226, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$1226, DW_AT_decl_column(0x34)
$C$DW$T$1227	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1227, DW_AT_type(*$C$DW$T$1226)
$C$DW$T$1228	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1228, DW_AT_type(*$C$DW$T$1227)
	.dwattr $C$DW$T$1228, DW_AT_address_class(0x20)
$C$DW$T$1229	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IPower_Module")
	.dwattr $C$DW$T$1229, DW_AT_type(*$C$DW$T$1228)
	.dwattr $C$DW$T$1229, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1229, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1229, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$1229, DW_AT_decl_column(0x34)

$C$DW$T$28	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$28, DW_AT_name("ti_sysbios_interfaces_IRomDevice_Fxns__")
	.dwattr $C$DW$T$28, DW_AT_declaration
	.dwendtag $C$DW$T$28

	.dwattr $C$DW$T$28, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$28, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$28, DW_AT_decl_column(0x10)
$C$DW$T$1230	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IRomDevice_Fxns__")
	.dwattr $C$DW$T$1230, DW_AT_type(*$C$DW$T$28)
	.dwattr $C$DW$T$1230, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1230, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1230, DW_AT_decl_line(0x55)
	.dwattr $C$DW$T$1230, DW_AT_decl_column(0x38)
$C$DW$T$1231	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1231, DW_AT_type(*$C$DW$T$1230)
$C$DW$T$1232	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1232, DW_AT_type(*$C$DW$T$1231)
	.dwattr $C$DW$T$1232, DW_AT_address_class(0x20)
$C$DW$T$1233	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_IRomDevice_Module")
	.dwattr $C$DW$T$1233, DW_AT_type(*$C$DW$T$1232)
	.dwattr $C$DW$T$1233, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1233, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1233, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$1233, DW_AT_decl_column(0x38)

$C$DW$T$29	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$29, DW_AT_name("ti_sysbios_interfaces_ISeconds_Fxns__")
	.dwattr $C$DW$T$29, DW_AT_declaration
	.dwendtag $C$DW$T$29

	.dwattr $C$DW$T$29, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$29, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$29, DW_AT_decl_column(0x10)
$C$DW$T$1234	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ISeconds_Fxns__")
	.dwattr $C$DW$T$1234, DW_AT_type(*$C$DW$T$29)
	.dwattr $C$DW$T$1234, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1234, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1234, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$1234, DW_AT_decl_column(0x36)
$C$DW$T$1235	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1235, DW_AT_type(*$C$DW$T$1234)
$C$DW$T$1236	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1236, DW_AT_type(*$C$DW$T$1235)
	.dwattr $C$DW$T$1236, DW_AT_address_class(0x20)
$C$DW$T$1237	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ISeconds_Module")
	.dwattr $C$DW$T$1237, DW_AT_type(*$C$DW$T$1236)
	.dwattr $C$DW$T$1237, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1237, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1237, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$1237, DW_AT_decl_column(0x36)

$C$DW$T$201	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$201, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_Fxns__")
	.dwattr $C$DW$T$201, DW_AT_byte_size(0x30)
$C$DW$479	.dwtag  DW_TAG_member
	.dwattr $C$DW$479, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$479, DW_AT_name("__base")
	.dwattr $C$DW$479, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$479, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$479, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$479, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$479, DW_AT_decl_line(0x48)
	.dwattr $C$DW$479, DW_AT_decl_column(0x1d)
$C$DW$480	.dwtag  DW_TAG_member
	.dwattr $C$DW$480, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$480, DW_AT_name("__sysp")
	.dwattr $C$DW$480, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$480, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$480, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$480, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$480, DW_AT_decl_line(0x49)
	.dwattr $C$DW$480, DW_AT_decl_column(0x27)
$C$DW$481	.dwtag  DW_TAG_member
	.dwattr $C$DW$481, DW_AT_type(*$C$DW$T$184)
	.dwattr $C$DW$481, DW_AT_name("start")
	.dwattr $C$DW$481, DW_AT_TI_symbol_name("start")
	.dwattr $C$DW$481, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$481, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$481, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$481, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$481, DW_AT_decl_column(0x0f)
$C$DW$482	.dwtag  DW_TAG_member
	.dwattr $C$DW$482, DW_AT_type(*$C$DW$T$187)
	.dwattr $C$DW$482, DW_AT_name("swap")
	.dwattr $C$DW$482, DW_AT_TI_symbol_name("swap")
	.dwattr $C$DW$482, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$482, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$482, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$482, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$482, DW_AT_decl_column(0x10)
$C$DW$483	.dwtag  DW_TAG_member
	.dwattr $C$DW$483, DW_AT_type(*$C$DW$T$193)
	.dwattr $C$DW$483, DW_AT_name("checkStack")
	.dwattr $C$DW$483, DW_AT_TI_symbol_name("checkStack")
	.dwattr $C$DW$483, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$483, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$483, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$483, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$483, DW_AT_decl_column(0x10)
$C$DW$484	.dwtag  DW_TAG_member
	.dwattr $C$DW$484, DW_AT_type(*$C$DW$T$195)
	.dwattr $C$DW$484, DW_AT_name("stackUsed")
	.dwattr $C$DW$484, DW_AT_TI_symbol_name("stackUsed")
	.dwattr $C$DW$484, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$484, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$484, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$484, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$484, DW_AT_decl_column(0x11)
$C$DW$485	.dwtag  DW_TAG_member
	.dwattr $C$DW$485, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$485, DW_AT_name("getStackAlignment")
	.dwattr $C$DW$485, DW_AT_TI_symbol_name("getStackAlignment")
	.dwattr $C$DW$485, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$485, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$485, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$485, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$485, DW_AT_decl_column(0x10)
$C$DW$486	.dwtag  DW_TAG_member
	.dwattr $C$DW$486, DW_AT_type(*$C$DW$T$200)
	.dwattr $C$DW$486, DW_AT_name("getDefaultStackSize")
	.dwattr $C$DW$486, DW_AT_TI_symbol_name("getDefaultStackSize")
	.dwattr $C$DW$486, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$486, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$486, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$486, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$486, DW_AT_decl_column(0x11)
$C$DW$487	.dwtag  DW_TAG_member
	.dwattr $C$DW$487, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$487, DW_AT_name("__sfxns")
	.dwattr $C$DW$487, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$487, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$487, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$487, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$487, DW_AT_decl_line(0x50)
	.dwattr $C$DW$487, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$201

	.dwattr $C$DW$T$201, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITaskSupport.h")
	.dwattr $C$DW$T$201, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$201, DW_AT_decl_column(0x08)
$C$DW$T$1238	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_Fxns__")
	.dwattr $C$DW$T$1238, DW_AT_type(*$C$DW$T$201)
	.dwattr $C$DW$T$1238, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1238, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1238, DW_AT_decl_line(0x22)
	.dwattr $C$DW$T$1238, DW_AT_decl_column(0x3a)
$C$DW$T$1239	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1239, DW_AT_type(*$C$DW$T$1238)
$C$DW$T$1240	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1240, DW_AT_type(*$C$DW$T$1239)
	.dwattr $C$DW$T$1240, DW_AT_address_class(0x20)
$C$DW$T$1241	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITaskSupport_Module")
	.dwattr $C$DW$T$1241, DW_AT_type(*$C$DW$T$1240)
	.dwattr $C$DW$T$1241, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1241, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1241, DW_AT_decl_line(0x23)
	.dwattr $C$DW$T$1241, DW_AT_decl_column(0x3a)

$C$DW$T$30	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$30, DW_AT_name("ti_sysbios_interfaces_ITimerSupport_Fxns__")
	.dwattr $C$DW$T$30, DW_AT_declaration
	.dwendtag $C$DW$T$30

	.dwattr $C$DW$T$30, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$30, DW_AT_decl_line(0x32)
	.dwattr $C$DW$T$30, DW_AT_decl_column(0x10)
$C$DW$T$1242	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimerSupport_Fxns__")
	.dwattr $C$DW$T$1242, DW_AT_type(*$C$DW$T$30)
	.dwattr $C$DW$T$1242, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1242, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1242, DW_AT_decl_line(0x32)
	.dwattr $C$DW$T$1242, DW_AT_decl_column(0x3b)
$C$DW$T$1243	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1243, DW_AT_type(*$C$DW$T$1242)
$C$DW$T$1244	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1244, DW_AT_type(*$C$DW$T$1243)
	.dwattr $C$DW$T$1244, DW_AT_address_class(0x20)
$C$DW$T$1245	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimerSupport_Module")
	.dwattr $C$DW$T$1245, DW_AT_type(*$C$DW$T$1244)
	.dwattr $C$DW$T$1245, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1245, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1245, DW_AT_decl_line(0x33)
	.dwattr $C$DW$T$1245, DW_AT_decl_column(0x3b)

$C$DW$T$207	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$207, DW_AT_name("ti_sysbios_interfaces_ITimer_Args__create")
	.dwattr $C$DW$T$207, DW_AT_byte_size(0x08)
$C$DW$488	.dwtag  DW_TAG_member
	.dwattr $C$DW$488, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$488, DW_AT_name("id")
	.dwattr $C$DW$488, DW_AT_TI_symbol_name("id")
	.dwattr $C$DW$488, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$488, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$488, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$488, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$488, DW_AT_decl_column(0x0d)
$C$DW$489	.dwtag  DW_TAG_member
	.dwattr $C$DW$489, DW_AT_type(*$C$DW$T$206)
	.dwattr $C$DW$489, DW_AT_name("tickFxn")
	.dwattr $C$DW$489, DW_AT_TI_symbol_name("tickFxn")
	.dwattr $C$DW$489, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$489, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$489, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$489, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$489, DW_AT_decl_column(0x2a)
	.dwendtag $C$DW$T$207

	.dwattr $C$DW$T$207, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$207, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$207, DW_AT_decl_column(0x10)
$C$DW$T$1246	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Args__create")
	.dwattr $C$DW$T$1246, DW_AT_type(*$C$DW$T$207)
	.dwattr $C$DW$T$1246, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1246, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1246, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$1246, DW_AT_decl_column(0x03)

$C$DW$T$235	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$235, DW_AT_name("ti_sysbios_interfaces_ITimer_Fxns__")
	.dwattr $C$DW$T$235, DW_AT_byte_size(0x60)
$C$DW$490	.dwtag  DW_TAG_member
	.dwattr $C$DW$490, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$490, DW_AT_name("__base")
	.dwattr $C$DW$490, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$490, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$490, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$490, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$490, DW_AT_decl_line(0x89)
	.dwattr $C$DW$490, DW_AT_decl_column(0x1d)
$C$DW$491	.dwtag  DW_TAG_member
	.dwattr $C$DW$491, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$491, DW_AT_name("__sysp")
	.dwattr $C$DW$491, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$491, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$491, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$491, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$491, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$491, DW_AT_decl_column(0x27)
$C$DW$492	.dwtag  DW_TAG_member
	.dwattr $C$DW$492, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$492, DW_AT_name("getNumTimers")
	.dwattr $C$DW$492, DW_AT_TI_symbol_name("getNumTimers")
	.dwattr $C$DW$492, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$492, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$492, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$492, DW_AT_decl_line(0x8b)
	.dwattr $C$DW$492, DW_AT_decl_column(0x10)
$C$DW$493	.dwtag  DW_TAG_member
	.dwattr $C$DW$493, DW_AT_type(*$C$DW$T$211)
	.dwattr $C$DW$493, DW_AT_name("getStatus")
	.dwattr $C$DW$493, DW_AT_TI_symbol_name("getStatus")
	.dwattr $C$DW$493, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$493, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$493, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$493, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$493, DW_AT_decl_column(0x2b)
$C$DW$494	.dwtag  DW_TAG_member
	.dwattr $C$DW$494, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$494, DW_AT_name("startup")
	.dwattr $C$DW$494, DW_AT_TI_symbol_name("startup")
	.dwattr $C$DW$494, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$494, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$494, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$494, DW_AT_decl_line(0x8d)
	.dwattr $C$DW$494, DW_AT_decl_column(0x10)
$C$DW$495	.dwtag  DW_TAG_member
	.dwattr $C$DW$495, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$495, DW_AT_name("getMaxTicks")
	.dwattr $C$DW$495, DW_AT_TI_symbol_name("getMaxTicks")
	.dwattr $C$DW$495, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$495, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$495, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$495, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$495, DW_AT_decl_column(0x12)
$C$DW$496	.dwtag  DW_TAG_member
	.dwattr $C$DW$496, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$496, DW_AT_name("setNextTick")
	.dwattr $C$DW$496, DW_AT_TI_symbol_name("setNextTick")
	.dwattr $C$DW$496, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$496, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$496, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$496, DW_AT_decl_line(0x8f)
	.dwattr $C$DW$496, DW_AT_decl_column(0x10)
$C$DW$497	.dwtag  DW_TAG_member
	.dwattr $C$DW$497, DW_AT_type(*$C$DW$T$219)
	.dwattr $C$DW$497, DW_AT_name("start")
	.dwattr $C$DW$497, DW_AT_TI_symbol_name("start")
	.dwattr $C$DW$497, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$497, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$497, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$497, DW_AT_decl_line(0x90)
	.dwattr $C$DW$497, DW_AT_decl_column(0x10)
$C$DW$498	.dwtag  DW_TAG_member
	.dwattr $C$DW$498, DW_AT_type(*$C$DW$T$219)
	.dwattr $C$DW$498, DW_AT_name("stop")
	.dwattr $C$DW$498, DW_AT_TI_symbol_name("stop")
	.dwattr $C$DW$498, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$498, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$498, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$498, DW_AT_decl_line(0x91)
	.dwattr $C$DW$498, DW_AT_decl_column(0x10)
$C$DW$499	.dwtag  DW_TAG_member
	.dwattr $C$DW$499, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$499, DW_AT_name("setPeriod")
	.dwattr $C$DW$499, DW_AT_TI_symbol_name("setPeriod")
	.dwattr $C$DW$499, DW_AT_data_member_location[DW_OP_plus_uconst 0x24]
	.dwattr $C$DW$499, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$499, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$499, DW_AT_decl_line(0x92)
	.dwattr $C$DW$499, DW_AT_decl_column(0x10)
$C$DW$500	.dwtag  DW_TAG_member
	.dwattr $C$DW$500, DW_AT_type(*$C$DW$T$221)
	.dwattr $C$DW$500, DW_AT_name("setPeriodMicroSecs")
	.dwattr $C$DW$500, DW_AT_TI_symbol_name("setPeriodMicroSecs")
	.dwattr $C$DW$500, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$500, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$500, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$500, DW_AT_decl_line(0x93)
	.dwattr $C$DW$500, DW_AT_decl_column(0x10)
$C$DW$501	.dwtag  DW_TAG_member
	.dwattr $C$DW$501, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$501, DW_AT_name("getPeriod")
	.dwattr $C$DW$501, DW_AT_TI_symbol_name("getPeriod")
	.dwattr $C$DW$501, DW_AT_data_member_location[DW_OP_plus_uconst 0x2c]
	.dwattr $C$DW$501, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$501, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$501, DW_AT_decl_line(0x94)
	.dwattr $C$DW$501, DW_AT_decl_column(0x12)
$C$DW$502	.dwtag  DW_TAG_member
	.dwattr $C$DW$502, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$502, DW_AT_name("getCount")
	.dwattr $C$DW$502, DW_AT_TI_symbol_name("getCount")
	.dwattr $C$DW$502, DW_AT_data_member_location[DW_OP_plus_uconst 0x30]
	.dwattr $C$DW$502, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$502, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$502, DW_AT_decl_line(0x95)
	.dwattr $C$DW$502, DW_AT_decl_column(0x12)
$C$DW$503	.dwtag  DW_TAG_member
	.dwattr $C$DW$503, DW_AT_type(*$C$DW$T$225)
	.dwattr $C$DW$503, DW_AT_name("getFreq")
	.dwattr $C$DW$503, DW_AT_TI_symbol_name("getFreq")
	.dwattr $C$DW$503, DW_AT_data_member_location[DW_OP_plus_uconst 0x34]
	.dwattr $C$DW$503, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$503, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$503, DW_AT_decl_line(0x96)
	.dwattr $C$DW$503, DW_AT_decl_column(0x10)
$C$DW$504	.dwtag  DW_TAG_member
	.dwattr $C$DW$504, DW_AT_type(*$C$DW$T$228)
	.dwattr $C$DW$504, DW_AT_name("getFunc")
	.dwattr $C$DW$504, DW_AT_TI_symbol_name("getFunc")
	.dwattr $C$DW$504, DW_AT_data_member_location[DW_OP_plus_uconst 0x38]
	.dwattr $C$DW$504, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$504, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$504, DW_AT_decl_line(0x97)
	.dwattr $C$DW$504, DW_AT_decl_column(0x2c)
$C$DW$505	.dwtag  DW_TAG_member
	.dwattr $C$DW$505, DW_AT_type(*$C$DW$T$230)
	.dwattr $C$DW$505, DW_AT_name("setFunc")
	.dwattr $C$DW$505, DW_AT_TI_symbol_name("setFunc")
	.dwattr $C$DW$505, DW_AT_data_member_location[DW_OP_plus_uconst 0x3c]
	.dwattr $C$DW$505, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$505, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$505, DW_AT_decl_line(0x98)
	.dwattr $C$DW$505, DW_AT_decl_column(0x10)
$C$DW$506	.dwtag  DW_TAG_member
	.dwattr $C$DW$506, DW_AT_type(*$C$DW$T$217)
	.dwattr $C$DW$506, DW_AT_name("trigger")
	.dwattr $C$DW$506, DW_AT_TI_symbol_name("trigger")
	.dwattr $C$DW$506, DW_AT_data_member_location[DW_OP_plus_uconst 0x40]
	.dwattr $C$DW$506, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$506, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$506, DW_AT_decl_line(0x99)
	.dwattr $C$DW$506, DW_AT_decl_column(0x10)
$C$DW$507	.dwtag  DW_TAG_member
	.dwattr $C$DW$507, DW_AT_type(*$C$DW$T$215)
	.dwattr $C$DW$507, DW_AT_name("getExpiredCounts")
	.dwattr $C$DW$507, DW_AT_TI_symbol_name("getExpiredCounts")
	.dwattr $C$DW$507, DW_AT_data_member_location[DW_OP_plus_uconst 0x44]
	.dwattr $C$DW$507, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$507, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$507, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$507, DW_AT_decl_column(0x12)
$C$DW$508	.dwtag  DW_TAG_member
	.dwattr $C$DW$508, DW_AT_type(*$C$DW$T$232)
	.dwattr $C$DW$508, DW_AT_name("getExpiredTicks")
	.dwattr $C$DW$508, DW_AT_TI_symbol_name("getExpiredTicks")
	.dwattr $C$DW$508, DW_AT_data_member_location[DW_OP_plus_uconst 0x48]
	.dwattr $C$DW$508, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$508, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$508, DW_AT_decl_line(0x9b)
	.dwattr $C$DW$508, DW_AT_decl_column(0x12)
$C$DW$509	.dwtag  DW_TAG_member
	.dwattr $C$DW$509, DW_AT_type(*$C$DW$T$234)
	.dwattr $C$DW$509, DW_AT_name("getCurrentTick")
	.dwattr $C$DW$509, DW_AT_TI_symbol_name("getCurrentTick")
	.dwattr $C$DW$509, DW_AT_data_member_location[DW_OP_plus_uconst 0x4c]
	.dwattr $C$DW$509, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$509, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$509, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$509, DW_AT_decl_column(0x12)
$C$DW$510	.dwtag  DW_TAG_member
	.dwattr $C$DW$510, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$510, DW_AT_name("__sfxns")
	.dwattr $C$DW$510, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$510, DW_AT_data_member_location[DW_OP_plus_uconst 0x50]
	.dwattr $C$DW$510, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$510, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$510, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$510, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$235

	.dwattr $C$DW$T$235, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$235, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$235, DW_AT_decl_column(0x08)
$C$DW$T$243	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Fxns__")
	.dwattr $C$DW$T$243, DW_AT_type(*$C$DW$T$235)
	.dwattr $C$DW$T$243, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$243, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$243, DW_AT_decl_line(0x29)
	.dwattr $C$DW$T$243, DW_AT_decl_column(0x34)
$C$DW$T$244	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$244, DW_AT_type(*$C$DW$T$243)
	.dwattr $C$DW$T$244, DW_AT_address_class(0x20)
$C$DW$T$1247	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1247, DW_AT_type(*$C$DW$T$243)
$C$DW$T$1248	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1248, DW_AT_type(*$C$DW$T$1247)
	.dwattr $C$DW$T$1248, DW_AT_address_class(0x20)
$C$DW$T$1249	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Module")
	.dwattr $C$DW$T$1249, DW_AT_type(*$C$DW$T$1248)
	.dwattr $C$DW$T$1249, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1249, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1249, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$T$1249, DW_AT_decl_column(0x34)

$C$DW$T$242	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$242, DW_AT_name("ti_sysbios_interfaces_ITimer_Params")
	.dwattr $C$DW$T$242, DW_AT_byte_size(0x28)
$C$DW$511	.dwtag  DW_TAG_member
	.dwattr $C$DW$511, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$511, DW_AT_name("__size")
	.dwattr $C$DW$511, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$511, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$511, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$511, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$511, DW_AT_decl_line(0x76)
	.dwattr $C$DW$511, DW_AT_decl_column(0x0c)
$C$DW$512	.dwtag  DW_TAG_member
	.dwattr $C$DW$512, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$512, DW_AT_name("__self")
	.dwattr $C$DW$512, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$512, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$512, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$512, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$512, DW_AT_decl_line(0x77)
	.dwattr $C$DW$512, DW_AT_decl_column(0x11)
$C$DW$513	.dwtag  DW_TAG_member
	.dwattr $C$DW$513, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$513, DW_AT_name("__fxns")
	.dwattr $C$DW$513, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$513, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$513, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$513, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$513, DW_AT_decl_line(0x78)
	.dwattr $C$DW$513, DW_AT_decl_column(0x0b)
$C$DW$514	.dwtag  DW_TAG_member
	.dwattr $C$DW$514, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$514, DW_AT_name("instance")
	.dwattr $C$DW$514, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$514, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$514, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$514, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$514, DW_AT_decl_line(0x79)
	.dwattr $C$DW$514, DW_AT_decl_column(0x23)
$C$DW$515	.dwtag  DW_TAG_member
	.dwattr $C$DW$515, DW_AT_type(*$C$DW$T$237)
	.dwattr $C$DW$515, DW_AT_name("runMode")
	.dwattr $C$DW$515, DW_AT_TI_symbol_name("runMode")
	.dwattr $C$DW$515, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$515, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$515, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$515, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$515, DW_AT_decl_column(0x2a)
$C$DW$516	.dwtag  DW_TAG_member
	.dwattr $C$DW$516, DW_AT_type(*$C$DW$T$239)
	.dwattr $C$DW$516, DW_AT_name("startMode")
	.dwattr $C$DW$516, DW_AT_TI_symbol_name("startMode")
	.dwattr $C$DW$516, DW_AT_data_member_location[DW_OP_plus_uconst 0x11]
	.dwattr $C$DW$516, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$516, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$516, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$516, DW_AT_decl_column(0x2c)
$C$DW$517	.dwtag  DW_TAG_member
	.dwattr $C$DW$517, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$517, DW_AT_name("arg")
	.dwattr $C$DW$517, DW_AT_TI_symbol_name("arg")
	.dwattr $C$DW$517, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$517, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$517, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$517, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$517, DW_AT_decl_column(0x0e)
$C$DW$518	.dwtag  DW_TAG_member
	.dwattr $C$DW$518, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$518, DW_AT_name("period")
	.dwattr $C$DW$518, DW_AT_TI_symbol_name("period")
	.dwattr $C$DW$518, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$518, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$518, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$518, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$518, DW_AT_decl_column(0x10)
$C$DW$519	.dwtag  DW_TAG_member
	.dwattr $C$DW$519, DW_AT_type(*$C$DW$T$241)
	.dwattr $C$DW$519, DW_AT_name("periodType")
	.dwattr $C$DW$519, DW_AT_TI_symbol_name("periodType")
	.dwattr $C$DW$519, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$519, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$519, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$519, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$519, DW_AT_decl_column(0x2d)
$C$DW$520	.dwtag  DW_TAG_member
	.dwattr $C$DW$520, DW_AT_type(*$C$DW$T$222)
	.dwattr $C$DW$520, DW_AT_name("extFreq")
	.dwattr $C$DW$520, DW_AT_TI_symbol_name("extFreq")
	.dwattr $C$DW$520, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$520, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$520, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$520, DW_AT_decl_line(0x7f)
	.dwattr $C$DW$520, DW_AT_decl_column(0x1e)
	.dwendtag $C$DW$T$242

	.dwattr $C$DW$T$242, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$242, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$242, DW_AT_decl_column(0x08)
$C$DW$T$1250	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Params")
	.dwattr $C$DW$T$1250, DW_AT_type(*$C$DW$T$242)
	.dwattr $C$DW$T$1250, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1250, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1250, DW_AT_decl_line(0x2b)
	.dwattr $C$DW$T$1250, DW_AT_decl_column(0x34)

$C$DW$T$240	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$240, DW_AT_name("ti_sysbios_interfaces_ITimer_PeriodType")
	.dwattr $C$DW$T$240, DW_AT_byte_size(0x01)
$C$DW$521	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_PeriodType_MICROSECS"), DW_AT_const_value(0x00)
	.dwattr $C$DW$521, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$521, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$521, DW_AT_decl_column(0x05)
$C$DW$522	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_PeriodType_COUNTS"), DW_AT_const_value(0x01)
	.dwattr $C$DW$522, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$522, DW_AT_decl_line(0x60)
	.dwattr $C$DW$522, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$240

	.dwattr $C$DW$T$240, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$240, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$240, DW_AT_decl_column(0x06)
$C$DW$T$241	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_PeriodType")
	.dwattr $C$DW$T$241, DW_AT_type(*$C$DW$T$240)
	.dwattr $C$DW$T$241, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$241, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$241, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$241, DW_AT_decl_column(0x36)
$C$DW$T$1251	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_PeriodType")
	.dwattr $C$DW$T$1251, DW_AT_type(*$C$DW$T$241)
	.dwattr $C$DW$T$1251, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1251, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1251, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$1251, DW_AT_decl_column(0x31)

$C$DW$T$236	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$236, DW_AT_name("ti_sysbios_interfaces_ITimer_RunMode")
	.dwattr $C$DW$T$236, DW_AT_byte_size(0x01)
$C$DW$523	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_RunMode_CONTINUOUS"), DW_AT_const_value(0x00)
	.dwattr $C$DW$523, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$523, DW_AT_decl_line(0x50)
	.dwattr $C$DW$523, DW_AT_decl_column(0x05)
$C$DW$524	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_RunMode_ONESHOT"), DW_AT_const_value(0x01)
	.dwattr $C$DW$524, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$524, DW_AT_decl_line(0x51)
	.dwattr $C$DW$524, DW_AT_decl_column(0x05)
$C$DW$525	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_RunMode_DYNAMIC"), DW_AT_const_value(0x02)
	.dwattr $C$DW$525, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$525, DW_AT_decl_line(0x52)
	.dwattr $C$DW$525, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$236

	.dwattr $C$DW$T$236, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$236, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$236, DW_AT_decl_column(0x06)
$C$DW$T$237	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_RunMode")
	.dwattr $C$DW$T$237, DW_AT_type(*$C$DW$T$236)
	.dwattr $C$DW$T$237, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$237, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$237, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$237, DW_AT_decl_column(0x33)
$C$DW$T$1252	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_RunMode")
	.dwattr $C$DW$T$1252, DW_AT_type(*$C$DW$T$237)
	.dwattr $C$DW$T$1252, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1252, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1252, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$1252, DW_AT_decl_column(0x2e)

$C$DW$T$238	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$238, DW_AT_name("ti_sysbios_interfaces_ITimer_StartMode")
	.dwattr $C$DW$T$238, DW_AT_byte_size(0x01)
$C$DW$526	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_StartMode_AUTO"), DW_AT_const_value(0x00)
	.dwattr $C$DW$526, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$526, DW_AT_decl_line(0x49)
	.dwattr $C$DW$526, DW_AT_decl_column(0x05)
$C$DW$527	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_StartMode_USER"), DW_AT_const_value(0x01)
	.dwattr $C$DW$527, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$527, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$527, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$238

	.dwattr $C$DW$T$238, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$238, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$238, DW_AT_decl_column(0x06)
$C$DW$T$239	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_StartMode")
	.dwattr $C$DW$T$239, DW_AT_type(*$C$DW$T$238)
	.dwattr $C$DW$T$239, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$239, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$239, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$239, DW_AT_decl_column(0x35)
$C$DW$T$1253	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_StartMode")
	.dwattr $C$DW$T$1253, DW_AT_type(*$C$DW$T$239)
	.dwattr $C$DW$T$1253, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1253, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1253, DW_AT_decl_line(0x49)
	.dwattr $C$DW$T$1253, DW_AT_decl_column(0x30)

$C$DW$T$208	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$208, DW_AT_name("ti_sysbios_interfaces_ITimer_Status")
	.dwattr $C$DW$T$208, DW_AT_byte_size(0x01)
$C$DW$528	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_Status_INUSE"), DW_AT_const_value(0x00)
	.dwattr $C$DW$528, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$528, DW_AT_decl_line(0x58)
	.dwattr $C$DW$528, DW_AT_decl_column(0x05)
$C$DW$529	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_interfaces_ITimer_Status_FREE"), DW_AT_const_value(0x01)
	.dwattr $C$DW$529, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$529, DW_AT_decl_line(0x59)
	.dwattr $C$DW$529, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$208

	.dwattr $C$DW$T$208, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$208, DW_AT_decl_line(0x57)
	.dwattr $C$DW$T$208, DW_AT_decl_column(0x06)
$C$DW$T$209	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Status")
	.dwattr $C$DW$T$209, DW_AT_type(*$C$DW$T$208)
	.dwattr $C$DW$T$209, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$209, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$209, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$T$209, DW_AT_decl_column(0x32)

$C$DW$T$210	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$210, DW_AT_type(*$C$DW$T$209)
	.dwattr $C$DW$T$210, DW_AT_language(DW_LANG_C)
$C$DW$530	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$530, DW_AT_type(*$C$DW$T$196)
	.dwendtag $C$DW$T$210

$C$DW$T$211	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$211, DW_AT_type(*$C$DW$T$210)
	.dwattr $C$DW$T$211, DW_AT_address_class(0x20)
$C$DW$T$1254	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_getStatus_FxnT")
	.dwattr $C$DW$T$1254, DW_AT_type(*$C$DW$T$211)
	.dwattr $C$DW$T$1254, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1254, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/ITimer.h")
	.dwattr $C$DW$T$1254, DW_AT_decl_line(0x142)
	.dwattr $C$DW$T$1254, DW_AT_decl_column(0x2f)
$C$DW$T$1255	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Status")
	.dwattr $C$DW$T$1255, DW_AT_type(*$C$DW$T$209)
	.dwattr $C$DW$T$1255, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1255, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1255, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$1255, DW_AT_decl_column(0x2d)

$C$DW$T$245	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$245, DW_AT_name("ti_sysbios_interfaces_ITimer___Object")
	.dwattr $C$DW$T$245, DW_AT_byte_size(0x08)
$C$DW$531	.dwtag  DW_TAG_member
	.dwattr $C$DW$531, DW_AT_type(*$C$DW$T$244)
	.dwattr $C$DW$531, DW_AT_name("__fxns")
	.dwattr $C$DW$531, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$531, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$531, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$531, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$531, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$531, DW_AT_decl_column(0x5d)
$C$DW$532	.dwtag  DW_TAG_member
	.dwattr $C$DW$532, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$532, DW_AT_name("__label")
	.dwattr $C$DW$532, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$532, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$532, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$532, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$532, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$532, DW_AT_decl_column(0x70)
	.dwendtag $C$DW$T$245

	.dwattr $C$DW$T$245, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$245, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$T$245, DW_AT_decl_column(0x10)
$C$DW$T$253	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$253, DW_AT_type(*$C$DW$T$245)
	.dwattr $C$DW$T$253, DW_AT_address_class(0x20)
$C$DW$T$1256	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimer_Handle")
	.dwattr $C$DW$T$1256, DW_AT_type(*$C$DW$T$253)
	.dwattr $C$DW$T$1256, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1256, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1256, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$T$1256, DW_AT_decl_column(0x7c)
$C$DW$T$254	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Handle")
	.dwattr $C$DW$T$254, DW_AT_type(*$C$DW$T$253)
	.dwattr $C$DW$T$254, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$254, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$254, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$254, DW_AT_decl_column(0x37)

$C$DW$T$31	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$31, DW_AT_name("ti_sysbios_interfaces_ITimestamp_Fxns__")
	.dwattr $C$DW$T$31, DW_AT_declaration
	.dwendtag $C$DW$T$31

	.dwattr $C$DW$T$31, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$31, DW_AT_decl_line(0x39)
	.dwattr $C$DW$T$31, DW_AT_decl_column(0x10)
$C$DW$T$1257	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimestamp_Fxns__")
	.dwattr $C$DW$T$1257, DW_AT_type(*$C$DW$T$31)
	.dwattr $C$DW$T$1257, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1257, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1257, DW_AT_decl_line(0x39)
	.dwattr $C$DW$T$1257, DW_AT_decl_column(0x38)
$C$DW$T$1258	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1258, DW_AT_type(*$C$DW$T$1257)
$C$DW$T$1259	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1259, DW_AT_type(*$C$DW$T$1258)
	.dwattr $C$DW$T$1259, DW_AT_address_class(0x20)
$C$DW$T$1260	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_interfaces_ITimestamp_Module")
	.dwattr $C$DW$T$1260, DW_AT_type(*$C$DW$T$1259)
	.dwattr $C$DW$T$1260, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1260, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/interfaces/package/package.defs.h")
	.dwattr $C$DW$T$1260, DW_AT_decl_line(0x3a)
	.dwattr $C$DW$T$1260, DW_AT_decl_column(0x38)

$C$DW$T$247	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$247, DW_AT_name("ti_sysbios_knl_Clock_Args__create")
	.dwattr $C$DW$T$247, DW_AT_byte_size(0x08)
$C$DW$533	.dwtag  DW_TAG_member
	.dwattr $C$DW$533, DW_AT_type(*$C$DW$T$246)
	.dwattr $C$DW$533, DW_AT_name("clockFxn")
	.dwattr $C$DW$533, DW_AT_TI_symbol_name("clockFxn")
	.dwattr $C$DW$533, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$533, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$533, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$533, DW_AT_decl_line(0x62)
	.dwattr $C$DW$533, DW_AT_decl_column(0x22)
$C$DW$534	.dwtag  DW_TAG_member
	.dwattr $C$DW$534, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$534, DW_AT_name("timeout")
	.dwattr $C$DW$534, DW_AT_TI_symbol_name("timeout")
	.dwattr $C$DW$534, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$534, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$534, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$534, DW_AT_decl_line(0x63)
	.dwattr $C$DW$534, DW_AT_decl_column(0x0e)
	.dwendtag $C$DW$T$247

	.dwattr $C$DW$T$247, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$247, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$247, DW_AT_decl_column(0x10)
$C$DW$T$1261	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Args__create")
	.dwattr $C$DW$T$1261, DW_AT_type(*$C$DW$T$247)
	.dwattr $C$DW$T$1261, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1261, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1261, DW_AT_decl_line(0x64)
	.dwattr $C$DW$T$1261, DW_AT_decl_column(0x03)

$C$DW$T$32	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$32, DW_AT_name("ti_sysbios_knl_Clock_Module_State")
	.dwattr $C$DW$T$32, DW_AT_declaration
	.dwendtag $C$DW$T$32

	.dwattr $C$DW$T$32, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$32, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$32, DW_AT_decl_column(0x10)
$C$DW$T$1262	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Module_State")
	.dwattr $C$DW$T$1262, DW_AT_type(*$C$DW$T$32)
	.dwattr $C$DW$T$1262, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1262, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1262, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$1262, DW_AT_decl_column(0x32)

$C$DW$T$33	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$33, DW_AT_name("ti_sysbios_knl_Clock_Object")
	.dwattr $C$DW$T$33, DW_AT_declaration
	.dwendtag $C$DW$T$33

	.dwattr $C$DW$T$33, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$33, DW_AT_decl_line(0x12)
	.dwattr $C$DW$T$33, DW_AT_decl_column(0x10)
$C$DW$T$343	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Object")
	.dwattr $C$DW$T$343, DW_AT_type(*$C$DW$T$33)
	.dwattr $C$DW$T$343, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$343, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$343, DW_AT_decl_line(0x12)
	.dwattr $C$DW$T$343, DW_AT_decl_column(0x2c)
$C$DW$T$344	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$344, DW_AT_type(*$C$DW$T$343)
	.dwattr $C$DW$T$344, DW_AT_address_class(0x20)
$C$DW$T$345	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Handle")
	.dwattr $C$DW$T$345, DW_AT_type(*$C$DW$T$344)
	.dwattr $C$DW$T$345, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$345, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$345, DW_AT_decl_line(0x14)
	.dwattr $C$DW$T$345, DW_AT_decl_column(0x26)
$C$DW$T$1263	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Instance")
	.dwattr $C$DW$T$1263, DW_AT_type(*$C$DW$T$344)
	.dwattr $C$DW$T$1263, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1263, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1263, DW_AT_decl_line(0x16)
	.dwattr $C$DW$T$1263, DW_AT_decl_column(0x26)

$C$DW$T$34	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$34, DW_AT_name("ti_sysbios_knl_Clock_Object__")
	.dwattr $C$DW$T$34, DW_AT_declaration
	.dwendtag $C$DW$T$34

	.dwattr $C$DW$T$34, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$34, DW_AT_decl_line(0x15)
	.dwattr $C$DW$T$34, DW_AT_decl_column(0x10)
$C$DW$T$1264	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Instance_State")
	.dwattr $C$DW$T$1264, DW_AT_type(*$C$DW$T$34)
	.dwattr $C$DW$T$1264, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1264, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1264, DW_AT_decl_line(0x15)
	.dwattr $C$DW$T$1264, DW_AT_decl_column(0x2e)

$C$DW$T$248	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$248, DW_AT_name("ti_sysbios_knl_Clock_Params")
	.dwattr $C$DW$T$248, DW_AT_byte_size(0x24)
$C$DW$535	.dwtag  DW_TAG_member
	.dwattr $C$DW$535, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$535, DW_AT_name("__size")
	.dwattr $C$DW$535, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$535, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$535, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$535, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$535, DW_AT_decl_line(0x102)
	.dwattr $C$DW$535, DW_AT_decl_column(0x0c)
$C$DW$536	.dwtag  DW_TAG_member
	.dwattr $C$DW$536, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$536, DW_AT_name("__self")
	.dwattr $C$DW$536, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$536, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$536, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$536, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$536, DW_AT_decl_line(0x103)
	.dwattr $C$DW$536, DW_AT_decl_column(0x11)
$C$DW$537	.dwtag  DW_TAG_member
	.dwattr $C$DW$537, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$537, DW_AT_name("__fxns")
	.dwattr $C$DW$537, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$537, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$537, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$537, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$537, DW_AT_decl_line(0x104)
	.dwattr $C$DW$537, DW_AT_decl_column(0x0b)
$C$DW$538	.dwtag  DW_TAG_member
	.dwattr $C$DW$538, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$538, DW_AT_name("instance")
	.dwattr $C$DW$538, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$538, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$538, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$538, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$538, DW_AT_decl_line(0x105)
	.dwattr $C$DW$538, DW_AT_decl_column(0x23)
$C$DW$539	.dwtag  DW_TAG_member
	.dwattr $C$DW$539, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$539, DW_AT_name("startFlag")
	.dwattr $C$DW$539, DW_AT_TI_symbol_name("startFlag")
	.dwattr $C$DW$539, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$539, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$539, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$539, DW_AT_decl_line(0x106)
	.dwattr $C$DW$539, DW_AT_decl_column(0x0e)
$C$DW$540	.dwtag  DW_TAG_member
	.dwattr $C$DW$540, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$540, DW_AT_name("period")
	.dwattr $C$DW$540, DW_AT_TI_symbol_name("period")
	.dwattr $C$DW$540, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$540, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$540, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$540, DW_AT_decl_line(0x107)
	.dwattr $C$DW$540, DW_AT_decl_column(0x10)
$C$DW$541	.dwtag  DW_TAG_member
	.dwattr $C$DW$541, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$541, DW_AT_name("arg")
	.dwattr $C$DW$541, DW_AT_TI_symbol_name("arg")
	.dwattr $C$DW$541, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$541, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$541, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$541, DW_AT_decl_line(0x108)
	.dwattr $C$DW$541, DW_AT_decl_column(0x0e)
$C$DW$542	.dwtag  DW_TAG_member
	.dwattr $C$DW$542, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$542, DW_AT_name("__iprms")
	.dwattr $C$DW$542, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$542, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$542, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$542, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$542, DW_AT_decl_line(0x109)
	.dwattr $C$DW$542, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$248

	.dwattr $C$DW$T$248, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$248, DW_AT_decl_line(0x101)
	.dwattr $C$DW$T$248, DW_AT_decl_column(0x08)
$C$DW$T$1265	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Params")
	.dwattr $C$DW$T$1265, DW_AT_type(*$C$DW$T$248)
	.dwattr $C$DW$T$1265, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1265, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1265, DW_AT_decl_line(0x11)
	.dwattr $C$DW$T$1265, DW_AT_decl_column(0x2c)

$C$DW$T$251	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$251, DW_AT_name("ti_sysbios_knl_Clock_Struct")
	.dwattr $C$DW$T$251, DW_AT_byte_size(0x24)
$C$DW$543	.dwtag  DW_TAG_member
	.dwattr $C$DW$543, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$543, DW_AT_name("__f0")
	.dwattr $C$DW$543, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$543, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$543, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$543, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$543, DW_AT_decl_line(0x10e)
	.dwattr $C$DW$543, DW_AT_decl_column(0x1f)
$C$DW$544	.dwtag  DW_TAG_member
	.dwattr $C$DW$544, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$544, DW_AT_name("__f1")
	.dwattr $C$DW$544, DW_AT_TI_symbol_name("__f1")
	.dwattr $C$DW$544, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$544, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$544, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$544, DW_AT_decl_line(0x10f)
	.dwattr $C$DW$544, DW_AT_decl_column(0x10)
$C$DW$545	.dwtag  DW_TAG_member
	.dwattr $C$DW$545, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$545, DW_AT_name("__f2")
	.dwattr $C$DW$545, DW_AT_TI_symbol_name("__f2")
	.dwattr $C$DW$545, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$545, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$545, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$545, DW_AT_decl_line(0x110)
	.dwattr $C$DW$545, DW_AT_decl_column(0x10)
$C$DW$546	.dwtag  DW_TAG_member
	.dwattr $C$DW$546, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$546, DW_AT_name("__f3")
	.dwattr $C$DW$546, DW_AT_TI_symbol_name("__f3")
	.dwattr $C$DW$546, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$546, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$546, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$546, DW_AT_decl_line(0x111)
	.dwattr $C$DW$546, DW_AT_decl_column(0x10)
$C$DW$547	.dwtag  DW_TAG_member
	.dwattr $C$DW$547, DW_AT_type(*$C$DW$T$250)
	.dwattr $C$DW$547, DW_AT_name("__f4")
	.dwattr $C$DW$547, DW_AT_TI_symbol_name("__f4")
	.dwattr $C$DW$547, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$547, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$547, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$547, DW_AT_decl_line(0x112)
	.dwattr $C$DW$547, DW_AT_decl_column(0x17)
$C$DW$548	.dwtag  DW_TAG_member
	.dwattr $C$DW$548, DW_AT_type(*$C$DW$T$246)
	.dwattr $C$DW$548, DW_AT_name("__f5")
	.dwattr $C$DW$548, DW_AT_TI_symbol_name("__f5")
	.dwattr $C$DW$548, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$548, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$548, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$548, DW_AT_decl_line(0x113)
	.dwattr $C$DW$548, DW_AT_decl_column(0x22)
$C$DW$549	.dwtag  DW_TAG_member
	.dwattr $C$DW$549, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$549, DW_AT_name("__f6")
	.dwattr $C$DW$549, DW_AT_TI_symbol_name("__f6")
	.dwattr $C$DW$549, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$549, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$549, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$549, DW_AT_decl_line(0x114)
	.dwattr $C$DW$549, DW_AT_decl_column(0x0e)
$C$DW$550	.dwtag  DW_TAG_member
	.dwattr $C$DW$550, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$550, DW_AT_name("__name")
	.dwattr $C$DW$550, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$550, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$550, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$550, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$550, DW_AT_decl_line(0x115)
	.dwattr $C$DW$550, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$251

	.dwattr $C$DW$T$251, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$251, DW_AT_decl_line(0x10d)
	.dwattr $C$DW$T$251, DW_AT_decl_column(0x08)
$C$DW$T$1266	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_Struct")
	.dwattr $C$DW$T$1266, DW_AT_type(*$C$DW$T$251)
	.dwattr $C$DW$T$1266, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1266, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1266, DW_AT_decl_line(0x13)
	.dwattr $C$DW$T$1266, DW_AT_decl_column(0x2c)

$C$DW$T$1267	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1267, DW_AT_name("ti_sysbios_knl_Clock_TickMode")
	.dwattr $C$DW$T$1267, DW_AT_byte_size(0x01)
$C$DW$551	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Clock_TickMode_PERIODIC"), DW_AT_const_value(0x00)
	.dwattr $C$DW$551, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$551, DW_AT_decl_line(0x53)
	.dwattr $C$DW$551, DW_AT_decl_column(0x05)
$C$DW$552	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Clock_TickMode_DYNAMIC"), DW_AT_const_value(0x01)
	.dwattr $C$DW$552, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$552, DW_AT_decl_line(0x54)
	.dwattr $C$DW$552, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1267

	.dwattr $C$DW$T$1267, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1267, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$1267, DW_AT_decl_column(0x06)
$C$DW$T$1268	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TickMode")
	.dwattr $C$DW$T$1268, DW_AT_type(*$C$DW$T$1267)
	.dwattr $C$DW$T$1268, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1268, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1268, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$1268, DW_AT_decl_column(0x2c)
$C$DW$T$1269	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_tickMode")
	.dwattr $C$DW$T$1269, DW_AT_type(*$C$DW$T$1268)
	.dwattr $C$DW$T$1269, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1269, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1269, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$T$1269, DW_AT_decl_column(0x27)

$C$DW$T$1270	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1270, DW_AT_name("ti_sysbios_knl_Clock_TickSource")
	.dwattr $C$DW$T$1270, DW_AT_byte_size(0x01)
$C$DW$553	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Clock_TickSource_TIMER"), DW_AT_const_value(0x00)
	.dwattr $C$DW$553, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$553, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$553, DW_AT_decl_column(0x05)
$C$DW$554	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Clock_TickSource_USER"), DW_AT_const_value(0x01)
	.dwattr $C$DW$554, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$554, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$554, DW_AT_decl_column(0x05)
$C$DW$555	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Clock_TickSource_NULL"), DW_AT_const_value(0x02)
	.dwattr $C$DW$555, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$555, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$555, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1270

	.dwattr $C$DW$T$1270, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1270, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$T$1270, DW_AT_decl_column(0x06)
$C$DW$T$1271	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TickSource")
	.dwattr $C$DW$T$1271, DW_AT_type(*$C$DW$T$1270)
	.dwattr $C$DW$T$1271, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1271, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1271, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$1271, DW_AT_decl_column(0x2e)
$C$DW$T$1272	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_tickSource")
	.dwattr $C$DW$T$1272, DW_AT_type(*$C$DW$T$1271)
	.dwattr $C$DW$T$1272, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1272, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1272, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$T$1272, DW_AT_decl_column(0x29)

$C$DW$T$252	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$252, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Args__create")
	.dwattr $C$DW$T$252, DW_AT_byte_size(0x08)
$C$DW$556	.dwtag  DW_TAG_member
	.dwattr $C$DW$556, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$556, DW_AT_name("id")
	.dwattr $C$DW$556, DW_AT_TI_symbol_name("id")
	.dwattr $C$DW$556, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$556, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$556, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$556, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$556, DW_AT_decl_column(0x0d)
$C$DW$557	.dwtag  DW_TAG_member
	.dwattr $C$DW$557, DW_AT_type(*$C$DW$T$206)
	.dwattr $C$DW$557, DW_AT_name("tickFxn")
	.dwattr $C$DW$557, DW_AT_TI_symbol_name("tickFxn")
	.dwattr $C$DW$557, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$557, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$557, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$557, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$557, DW_AT_decl_column(0x2a)
	.dwendtag $C$DW$T$252

	.dwattr $C$DW$T$252, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$252, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$252, DW_AT_decl_column(0x10)
$C$DW$T$1273	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Args__create")
	.dwattr $C$DW$T$1273, DW_AT_type(*$C$DW$T$252)
	.dwattr $C$DW$T$1273, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1273, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1273, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$1273, DW_AT_decl_column(0x03)

$C$DW$T$273	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$273, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Fxns__")
	.dwattr $C$DW$T$273, DW_AT_byte_size(0x60)
$C$DW$558	.dwtag  DW_TAG_member
	.dwattr $C$DW$558, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$558, DW_AT_name("__base")
	.dwattr $C$DW$558, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$558, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$558, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$558, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$558, DW_AT_decl_line(0xcd)
	.dwattr $C$DW$558, DW_AT_decl_column(0x1d)
$C$DW$559	.dwtag  DW_TAG_member
	.dwattr $C$DW$559, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$559, DW_AT_name("__sysp")
	.dwattr $C$DW$559, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$559, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$559, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$559, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$559, DW_AT_decl_line(0xce)
	.dwattr $C$DW$559, DW_AT_decl_column(0x27)
$C$DW$560	.dwtag  DW_TAG_member
	.dwattr $C$DW$560, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$560, DW_AT_name("getNumTimers")
	.dwattr $C$DW$560, DW_AT_TI_symbol_name("getNumTimers")
	.dwattr $C$DW$560, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$560, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$560, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$560, DW_AT_decl_line(0xcf)
	.dwattr $C$DW$560, DW_AT_decl_column(0x10)
$C$DW$561	.dwtag  DW_TAG_member
	.dwattr $C$DW$561, DW_AT_type(*$C$DW$T$211)
	.dwattr $C$DW$561, DW_AT_name("getStatus")
	.dwattr $C$DW$561, DW_AT_TI_symbol_name("getStatus")
	.dwattr $C$DW$561, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$561, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$561, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$561, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$561, DW_AT_decl_column(0x2b)
$C$DW$562	.dwtag  DW_TAG_member
	.dwattr $C$DW$562, DW_AT_type(*$C$DW$T$179)
	.dwattr $C$DW$562, DW_AT_name("startup")
	.dwattr $C$DW$562, DW_AT_TI_symbol_name("startup")
	.dwattr $C$DW$562, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$562, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$562, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$562, DW_AT_decl_line(0xd1)
	.dwattr $C$DW$562, DW_AT_decl_column(0x10)
$C$DW$563	.dwtag  DW_TAG_member
	.dwattr $C$DW$563, DW_AT_type(*$C$DW$T$256)
	.dwattr $C$DW$563, DW_AT_name("getMaxTicks")
	.dwattr $C$DW$563, DW_AT_TI_symbol_name("getMaxTicks")
	.dwattr $C$DW$563, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$563, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$563, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$563, DW_AT_decl_line(0xd2)
	.dwattr $C$DW$563, DW_AT_decl_column(0x12)
$C$DW$564	.dwtag  DW_TAG_member
	.dwattr $C$DW$564, DW_AT_type(*$C$DW$T$258)
	.dwattr $C$DW$564, DW_AT_name("setNextTick")
	.dwattr $C$DW$564, DW_AT_TI_symbol_name("setNextTick")
	.dwattr $C$DW$564, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$564, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$564, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$564, DW_AT_decl_line(0xd3)
	.dwattr $C$DW$564, DW_AT_decl_column(0x10)
$C$DW$565	.dwtag  DW_TAG_member
	.dwattr $C$DW$565, DW_AT_type(*$C$DW$T$260)
	.dwattr $C$DW$565, DW_AT_name("start")
	.dwattr $C$DW$565, DW_AT_TI_symbol_name("start")
	.dwattr $C$DW$565, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$565, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$565, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$565, DW_AT_decl_line(0xd4)
	.dwattr $C$DW$565, DW_AT_decl_column(0x10)
$C$DW$566	.dwtag  DW_TAG_member
	.dwattr $C$DW$566, DW_AT_type(*$C$DW$T$260)
	.dwattr $C$DW$566, DW_AT_name("stop")
	.dwattr $C$DW$566, DW_AT_TI_symbol_name("stop")
	.dwattr $C$DW$566, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$566, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$566, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$566, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$566, DW_AT_decl_column(0x10)
$C$DW$567	.dwtag  DW_TAG_member
	.dwattr $C$DW$567, DW_AT_type(*$C$DW$T$258)
	.dwattr $C$DW$567, DW_AT_name("setPeriod")
	.dwattr $C$DW$567, DW_AT_TI_symbol_name("setPeriod")
	.dwattr $C$DW$567, DW_AT_data_member_location[DW_OP_plus_uconst 0x24]
	.dwattr $C$DW$567, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$567, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$567, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$567, DW_AT_decl_column(0x10)
$C$DW$568	.dwtag  DW_TAG_member
	.dwattr $C$DW$568, DW_AT_type(*$C$DW$T$262)
	.dwattr $C$DW$568, DW_AT_name("setPeriodMicroSecs")
	.dwattr $C$DW$568, DW_AT_TI_symbol_name("setPeriodMicroSecs")
	.dwattr $C$DW$568, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$568, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$568, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$568, DW_AT_decl_line(0xd7)
	.dwattr $C$DW$568, DW_AT_decl_column(0x10)
$C$DW$569	.dwtag  DW_TAG_member
	.dwattr $C$DW$569, DW_AT_type(*$C$DW$T$256)
	.dwattr $C$DW$569, DW_AT_name("getPeriod")
	.dwattr $C$DW$569, DW_AT_TI_symbol_name("getPeriod")
	.dwattr $C$DW$569, DW_AT_data_member_location[DW_OP_plus_uconst 0x2c]
	.dwattr $C$DW$569, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$569, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$569, DW_AT_decl_line(0xd8)
	.dwattr $C$DW$569, DW_AT_decl_column(0x12)
$C$DW$570	.dwtag  DW_TAG_member
	.dwattr $C$DW$570, DW_AT_type(*$C$DW$T$256)
	.dwattr $C$DW$570, DW_AT_name("getCount")
	.dwattr $C$DW$570, DW_AT_TI_symbol_name("getCount")
	.dwattr $C$DW$570, DW_AT_data_member_location[DW_OP_plus_uconst 0x30]
	.dwattr $C$DW$570, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$570, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$570, DW_AT_decl_line(0xd9)
	.dwattr $C$DW$570, DW_AT_decl_column(0x12)
$C$DW$571	.dwtag  DW_TAG_member
	.dwattr $C$DW$571, DW_AT_type(*$C$DW$T$264)
	.dwattr $C$DW$571, DW_AT_name("getFreq")
	.dwattr $C$DW$571, DW_AT_TI_symbol_name("getFreq")
	.dwattr $C$DW$571, DW_AT_data_member_location[DW_OP_plus_uconst 0x34]
	.dwattr $C$DW$571, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$571, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$571, DW_AT_decl_line(0xda)
	.dwattr $C$DW$571, DW_AT_decl_column(0x10)
$C$DW$572	.dwtag  DW_TAG_member
	.dwattr $C$DW$572, DW_AT_type(*$C$DW$T$266)
	.dwattr $C$DW$572, DW_AT_name("getFunc")
	.dwattr $C$DW$572, DW_AT_TI_symbol_name("getFunc")
	.dwattr $C$DW$572, DW_AT_data_member_location[DW_OP_plus_uconst 0x38]
	.dwattr $C$DW$572, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$572, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$572, DW_AT_decl_line(0xdb)
	.dwattr $C$DW$572, DW_AT_decl_column(0x2c)
$C$DW$573	.dwtag  DW_TAG_member
	.dwattr $C$DW$573, DW_AT_type(*$C$DW$T$268)
	.dwattr $C$DW$573, DW_AT_name("setFunc")
	.dwattr $C$DW$573, DW_AT_TI_symbol_name("setFunc")
	.dwattr $C$DW$573, DW_AT_data_member_location[DW_OP_plus_uconst 0x3c]
	.dwattr $C$DW$573, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$573, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$573, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$573, DW_AT_decl_column(0x10)
$C$DW$574	.dwtag  DW_TAG_member
	.dwattr $C$DW$574, DW_AT_type(*$C$DW$T$258)
	.dwattr $C$DW$574, DW_AT_name("trigger")
	.dwattr $C$DW$574, DW_AT_TI_symbol_name("trigger")
	.dwattr $C$DW$574, DW_AT_data_member_location[DW_OP_plus_uconst 0x40]
	.dwattr $C$DW$574, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$574, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$574, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$574, DW_AT_decl_column(0x10)
$C$DW$575	.dwtag  DW_TAG_member
	.dwattr $C$DW$575, DW_AT_type(*$C$DW$T$256)
	.dwattr $C$DW$575, DW_AT_name("getExpiredCounts")
	.dwattr $C$DW$575, DW_AT_TI_symbol_name("getExpiredCounts")
	.dwattr $C$DW$575, DW_AT_data_member_location[DW_OP_plus_uconst 0x44]
	.dwattr $C$DW$575, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$575, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$575, DW_AT_decl_line(0xde)
	.dwattr $C$DW$575, DW_AT_decl_column(0x12)
$C$DW$576	.dwtag  DW_TAG_member
	.dwattr $C$DW$576, DW_AT_type(*$C$DW$T$270)
	.dwattr $C$DW$576, DW_AT_name("getExpiredTicks")
	.dwattr $C$DW$576, DW_AT_TI_symbol_name("getExpiredTicks")
	.dwattr $C$DW$576, DW_AT_data_member_location[DW_OP_plus_uconst 0x48]
	.dwattr $C$DW$576, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$576, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$576, DW_AT_decl_line(0xdf)
	.dwattr $C$DW$576, DW_AT_decl_column(0x12)
$C$DW$577	.dwtag  DW_TAG_member
	.dwattr $C$DW$577, DW_AT_type(*$C$DW$T$272)
	.dwattr $C$DW$577, DW_AT_name("getCurrentTick")
	.dwattr $C$DW$577, DW_AT_TI_symbol_name("getCurrentTick")
	.dwattr $C$DW$577, DW_AT_data_member_location[DW_OP_plus_uconst 0x4c]
	.dwattr $C$DW$577, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$577, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$577, DW_AT_decl_line(0xe0)
	.dwattr $C$DW$577, DW_AT_decl_column(0x12)
$C$DW$578	.dwtag  DW_TAG_member
	.dwattr $C$DW$578, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$578, DW_AT_name("__sfxns")
	.dwattr $C$DW$578, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$578, DW_AT_data_member_location[DW_OP_plus_uconst 0x50]
	.dwattr $C$DW$578, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$578, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$578, DW_AT_decl_line(0xe1)
	.dwattr $C$DW$578, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$273

	.dwattr $C$DW$T$273, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$273, DW_AT_decl_line(0xcc)
	.dwattr $C$DW$T$273, DW_AT_decl_column(0x08)
$C$DW$T$275	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Fxns__")
	.dwattr $C$DW$T$275, DW_AT_type(*$C$DW$T$273)
	.dwattr $C$DW$T$275, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$275, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$275, DW_AT_decl_line(0x74)
	.dwattr $C$DW$T$275, DW_AT_decl_column(0x37)
$C$DW$T$276	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$276, DW_AT_type(*$C$DW$T$275)
$C$DW$T$277	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$277, DW_AT_type(*$C$DW$T$276)
	.dwattr $C$DW$T$277, DW_AT_address_class(0x20)
$C$DW$T$1274	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Module")
	.dwattr $C$DW$T$1274, DW_AT_type(*$C$DW$T$277)
	.dwattr $C$DW$T$1274, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1274, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1274, DW_AT_decl_line(0x75)
	.dwattr $C$DW$T$1274, DW_AT_decl_column(0x37)

$C$DW$T$274	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$274, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Params")
	.dwattr $C$DW$T$274, DW_AT_byte_size(0x30)
$C$DW$579	.dwtag  DW_TAG_member
	.dwattr $C$DW$579, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$579, DW_AT_name("__size")
	.dwattr $C$DW$579, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$579, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$579, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$579, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$579, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$579, DW_AT_decl_column(0x0c)
$C$DW$580	.dwtag  DW_TAG_member
	.dwattr $C$DW$580, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$580, DW_AT_name("__self")
	.dwattr $C$DW$580, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$580, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$580, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$580, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$580, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$580, DW_AT_decl_column(0x11)
$C$DW$581	.dwtag  DW_TAG_member
	.dwattr $C$DW$581, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$581, DW_AT_name("__fxns")
	.dwattr $C$DW$581, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$581, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$581, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$581, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$581, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$581, DW_AT_decl_column(0x0b)
$C$DW$582	.dwtag  DW_TAG_member
	.dwattr $C$DW$582, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$582, DW_AT_name("instance")
	.dwattr $C$DW$582, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$582, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$582, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$582, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$582, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$582, DW_AT_decl_column(0x23)
$C$DW$583	.dwtag  DW_TAG_member
	.dwattr $C$DW$583, DW_AT_type(*$C$DW$T$237)
	.dwattr $C$DW$583, DW_AT_name("runMode")
	.dwattr $C$DW$583, DW_AT_TI_symbol_name("runMode")
	.dwattr $C$DW$583, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$583, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$583, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$583, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$583, DW_AT_decl_column(0x2a)
$C$DW$584	.dwtag  DW_TAG_member
	.dwattr $C$DW$584, DW_AT_type(*$C$DW$T$239)
	.dwattr $C$DW$584, DW_AT_name("startMode")
	.dwattr $C$DW$584, DW_AT_TI_symbol_name("startMode")
	.dwattr $C$DW$584, DW_AT_data_member_location[DW_OP_plus_uconst 0x11]
	.dwattr $C$DW$584, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$584, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$584, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$584, DW_AT_decl_column(0x2c)
$C$DW$585	.dwtag  DW_TAG_member
	.dwattr $C$DW$585, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$585, DW_AT_name("arg")
	.dwattr $C$DW$585, DW_AT_TI_symbol_name("arg")
	.dwattr $C$DW$585, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$585, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$585, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$585, DW_AT_decl_line(0xb9)
	.dwattr $C$DW$585, DW_AT_decl_column(0x0e)
$C$DW$586	.dwtag  DW_TAG_member
	.dwattr $C$DW$586, DW_AT_type(*$C$DW$T$213)
	.dwattr $C$DW$586, DW_AT_name("period")
	.dwattr $C$DW$586, DW_AT_TI_symbol_name("period")
	.dwattr $C$DW$586, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$586, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$586, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$586, DW_AT_decl_line(0xba)
	.dwattr $C$DW$586, DW_AT_decl_column(0x10)
$C$DW$587	.dwtag  DW_TAG_member
	.dwattr $C$DW$587, DW_AT_type(*$C$DW$T$241)
	.dwattr $C$DW$587, DW_AT_name("periodType")
	.dwattr $C$DW$587, DW_AT_TI_symbol_name("periodType")
	.dwattr $C$DW$587, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$587, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$587, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$587, DW_AT_decl_line(0xbb)
	.dwattr $C$DW$587, DW_AT_decl_column(0x2d)
$C$DW$588	.dwtag  DW_TAG_member
	.dwattr $C$DW$588, DW_AT_type(*$C$DW$T$222)
	.dwattr $C$DW$588, DW_AT_name("extFreq")
	.dwattr $C$DW$588, DW_AT_TI_symbol_name("extFreq")
	.dwattr $C$DW$588, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$588, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$588, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$588, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$588, DW_AT_decl_column(0x1e)
$C$DW$589	.dwtag  DW_TAG_member
	.dwattr $C$DW$589, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$589, DW_AT_name("__iprms")
	.dwattr $C$DW$589, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$589, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$589, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$589, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$589, DW_AT_decl_line(0xbd)
	.dwattr $C$DW$589, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$274

	.dwattr $C$DW$T$274, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$274, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$T$274, DW_AT_decl_column(0x08)
$C$DW$T$1275	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Params")
	.dwattr $C$DW$T$1275, DW_AT_type(*$C$DW$T$274)
	.dwattr $C$DW$T$1275, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1275, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1275, DW_AT_decl_line(0x76)
	.dwattr $C$DW$T$1275, DW_AT_decl_column(0x37)

$C$DW$T$278	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$278, DW_AT_name("ti_sysbios_knl_Clock_TimerProxy_Struct")
	.dwattr $C$DW$T$278, DW_AT_byte_size(0x08)
$C$DW$590	.dwtag  DW_TAG_member
	.dwattr $C$DW$590, DW_AT_type(*$C$DW$T$277)
	.dwattr $C$DW$590, DW_AT_name("__fxns")
	.dwattr $C$DW$590, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$590, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$590, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$590, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$590, DW_AT_decl_line(0xc2)
	.dwattr $C$DW$590, DW_AT_decl_column(0x33)
$C$DW$591	.dwtag  DW_TAG_member
	.dwattr $C$DW$591, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$591, DW_AT_name("__name")
	.dwattr $C$DW$591, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$591, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$591, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$591, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$591, DW_AT_decl_line(0xc3)
	.dwattr $C$DW$591, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$278

	.dwattr $C$DW$T$278, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$278, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$278, DW_AT_decl_column(0x08)

$C$DW$T$35	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$35, DW_AT_name("ti_sysbios_knl_Event_Object")
	.dwattr $C$DW$T$35, DW_AT_declaration
	.dwendtag $C$DW$T$35

	.dwattr $C$DW$T$35, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$35, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$T$35, DW_AT_decl_column(0x10)
$C$DW$T$293	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Object")
	.dwattr $C$DW$T$293, DW_AT_type(*$C$DW$T$35)
	.dwattr $C$DW$T$293, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$293, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$293, DW_AT_decl_line(0x2a)
	.dwattr $C$DW$T$293, DW_AT_decl_column(0x2c)
$C$DW$T$294	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$294, DW_AT_type(*$C$DW$T$293)
	.dwattr $C$DW$T$294, DW_AT_address_class(0x20)
$C$DW$T$295	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Handle")
	.dwattr $C$DW$T$295, DW_AT_type(*$C$DW$T$294)
	.dwattr $C$DW$T$295, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$295, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$295, DW_AT_decl_line(0x2c)
	.dwattr $C$DW$T$295, DW_AT_decl_column(0x26)
$C$DW$T$1276	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Instance")
	.dwattr $C$DW$T$1276, DW_AT_type(*$C$DW$T$294)
	.dwattr $C$DW$T$1276, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1276, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1276, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$T$1276, DW_AT_decl_column(0x26)

$C$DW$T$36	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$36, DW_AT_name("ti_sysbios_knl_Event_Object__")
	.dwattr $C$DW$T$36, DW_AT_declaration
	.dwendtag $C$DW$T$36

	.dwattr $C$DW$T$36, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$36, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$T$36, DW_AT_decl_column(0x10)
$C$DW$T$1277	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Instance_State")
	.dwattr $C$DW$T$1277, DW_AT_type(*$C$DW$T$36)
	.dwattr $C$DW$T$1277, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1277, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1277, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$T$1277, DW_AT_decl_column(0x2e)

$C$DW$T$279	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$279, DW_AT_name("ti_sysbios_knl_Event_Params")
	.dwattr $C$DW$T$279, DW_AT_byte_size(0x18)
$C$DW$592	.dwtag  DW_TAG_member
	.dwattr $C$DW$592, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$592, DW_AT_name("__size")
	.dwattr $C$DW$592, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$592, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$592, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$592, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$592, DW_AT_decl_line(0x139)
	.dwattr $C$DW$592, DW_AT_decl_column(0x0c)
$C$DW$593	.dwtag  DW_TAG_member
	.dwattr $C$DW$593, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$593, DW_AT_name("__self")
	.dwattr $C$DW$593, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$593, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$593, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$593, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$593, DW_AT_decl_line(0x13a)
	.dwattr $C$DW$593, DW_AT_decl_column(0x11)
$C$DW$594	.dwtag  DW_TAG_member
	.dwattr $C$DW$594, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$594, DW_AT_name("__fxns")
	.dwattr $C$DW$594, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$594, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$594, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$594, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$594, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$594, DW_AT_decl_column(0x0b)
$C$DW$595	.dwtag  DW_TAG_member
	.dwattr $C$DW$595, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$595, DW_AT_name("instance")
	.dwattr $C$DW$595, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$595, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$595, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$595, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$595, DW_AT_decl_line(0x13c)
	.dwattr $C$DW$595, DW_AT_decl_column(0x23)
$C$DW$596	.dwtag  DW_TAG_member
	.dwattr $C$DW$596, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$596, DW_AT_name("__iprms")
	.dwattr $C$DW$596, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$596, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$596, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$596, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$596, DW_AT_decl_line(0x13d)
	.dwattr $C$DW$596, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$279

	.dwattr $C$DW$T$279, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$279, DW_AT_decl_line(0x138)
	.dwattr $C$DW$T$279, DW_AT_decl_column(0x08)
$C$DW$T$1278	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Params")
	.dwattr $C$DW$T$1278, DW_AT_type(*$C$DW$T$279)
	.dwattr $C$DW$T$1278, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1278, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1278, DW_AT_decl_line(0x29)
	.dwattr $C$DW$T$1278, DW_AT_decl_column(0x2c)

$C$DW$T$283	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$283, DW_AT_name("ti_sysbios_knl_Event_PendElem")
	.dwattr $C$DW$T$283, DW_AT_byte_size(0x20)
$C$DW$597	.dwtag  DW_TAG_member
	.dwattr $C$DW$597, DW_AT_type(*$C$DW$T$280)
	.dwattr $C$DW$597, DW_AT_name("tpElem")
	.dwattr $C$DW$597, DW_AT_TI_symbol_name("tpElem")
	.dwattr $C$DW$597, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$597, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$597, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$597, DW_AT_decl_line(0xbb)
	.dwattr $C$DW$597, DW_AT_decl_column(0x22)
$C$DW$598	.dwtag  DW_TAG_member
	.dwattr $C$DW$598, DW_AT_type(*$C$DW$T$282)
	.dwattr $C$DW$598, DW_AT_name("pendState")
	.dwattr $C$DW$598, DW_AT_TI_symbol_name("pendState")
	.dwattr $C$DW$598, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$598, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$598, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$598, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$598, DW_AT_decl_column(0x24)
$C$DW$599	.dwtag  DW_TAG_member
	.dwattr $C$DW$599, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$599, DW_AT_name("matchingEvents")
	.dwattr $C$DW$599, DW_AT_TI_symbol_name("matchingEvents")
	.dwattr $C$DW$599, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$599, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$599, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$599, DW_AT_decl_line(0xbd)
	.dwattr $C$DW$599, DW_AT_decl_column(0x0e)
$C$DW$600	.dwtag  DW_TAG_member
	.dwattr $C$DW$600, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$600, DW_AT_name("andMask")
	.dwattr $C$DW$600, DW_AT_TI_symbol_name("andMask")
	.dwattr $C$DW$600, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$600, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$600, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$600, DW_AT_decl_line(0xbe)
	.dwattr $C$DW$600, DW_AT_decl_column(0x0e)
$C$DW$601	.dwtag  DW_TAG_member
	.dwattr $C$DW$601, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$601, DW_AT_name("orMask")
	.dwattr $C$DW$601, DW_AT_TI_symbol_name("orMask")
	.dwattr $C$DW$601, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$601, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$601, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$601, DW_AT_decl_line(0xbf)
	.dwattr $C$DW$601, DW_AT_decl_column(0x0e)
	.dwendtag $C$DW$T$283

	.dwattr $C$DW$T$283, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$283, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$283, DW_AT_decl_column(0x08)
$C$DW$T$1279	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_PendElem")
	.dwattr $C$DW$T$1279, DW_AT_type(*$C$DW$T$283)
	.dwattr $C$DW$T$1279, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1279, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1279, DW_AT_decl_line(0x28)
	.dwattr $C$DW$T$1279, DW_AT_decl_column(0x2e)

$C$DW$T$281	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$281, DW_AT_name("ti_sysbios_knl_Event_PendState")
	.dwattr $C$DW$T$281, DW_AT_byte_size(0x01)
$C$DW$602	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Event_PendState_TIMEOUT"), DW_AT_const_value(0x00)
	.dwattr $C$DW$602, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$602, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$602, DW_AT_decl_column(0x05)
$C$DW$603	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Event_PendState_POSTED"), DW_AT_const_value(0x01)
	.dwattr $C$DW$603, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$603, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$603, DW_AT_decl_column(0x05)
$C$DW$604	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Event_PendState_CLOCK_WAIT"), DW_AT_const_value(0x02)
	.dwattr $C$DW$604, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$604, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$604, DW_AT_decl_column(0x05)
$C$DW$605	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Event_PendState_WAIT_FOREVER"), DW_AT_const_value(0x03)
	.dwattr $C$DW$605, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$605, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$605, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$281

	.dwattr $C$DW$T$281, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$281, DW_AT_decl_line(0xb1)
	.dwattr $C$DW$T$281, DW_AT_decl_column(0x06)
$C$DW$T$282	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_PendState")
	.dwattr $C$DW$T$282, DW_AT_type(*$C$DW$T$281)
	.dwattr $C$DW$T$282, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$282, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$282, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$282, DW_AT_decl_column(0x2d)

$C$DW$T$286	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$286, DW_AT_name("ti_sysbios_knl_Event_Struct")
	.dwattr $C$DW$T$286, DW_AT_byte_size(0x14)
$C$DW$606	.dwtag  DW_TAG_member
	.dwattr $C$DW$606, DW_AT_type(*$C$DW$T$284)
	.dwattr $C$DW$606, DW_AT_name("__f0")
	.dwattr $C$DW$606, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$606, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$606, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$606, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$606, DW_AT_decl_line(0x142)
	.dwattr $C$DW$606, DW_AT_decl_column(0x17)
$C$DW$607	.dwtag  DW_TAG_member
	.dwattr $C$DW$607, DW_AT_type(*$C$DW$T$285)
	.dwattr $C$DW$607, DW_AT_name("__f1")
	.dwattr $C$DW$607, DW_AT_TI_symbol_name("__f1")
	.dwattr $C$DW$607, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$607, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$607, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$607, DW_AT_decl_line(0x143)
	.dwattr $C$DW$607, DW_AT_decl_column(0x21)
$C$DW$608	.dwtag  DW_TAG_member
	.dwattr $C$DW$608, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$608, DW_AT_name("__name")
	.dwattr $C$DW$608, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$608, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$608, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$608, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$608, DW_AT_decl_line(0x144)
	.dwattr $C$DW$608, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$286

	.dwattr $C$DW$T$286, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$286, DW_AT_decl_line(0x141)
	.dwattr $C$DW$T$286, DW_AT_decl_column(0x08)
$C$DW$T$1280	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Event_Struct")
	.dwattr $C$DW$T$1280, DW_AT_type(*$C$DW$T$286)
	.dwattr $C$DW$T$1280, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1280, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1280, DW_AT_decl_line(0x2b)
	.dwattr $C$DW$T$1280, DW_AT_decl_column(0x2c)

$C$DW$T$37	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$37, DW_AT_name("ti_sysbios_knl_Intrinsics_Fxns__")
	.dwattr $C$DW$T$37, DW_AT_declaration
	.dwendtag $C$DW$T$37

	.dwattr $C$DW$T$37, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$37, DW_AT_decl_line(0x21)
	.dwattr $C$DW$T$37, DW_AT_decl_column(0x10)
$C$DW$T$1281	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Intrinsics_Fxns__")
	.dwattr $C$DW$T$1281, DW_AT_type(*$C$DW$T$37)
	.dwattr $C$DW$T$1281, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1281, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1281, DW_AT_decl_line(0x21)
	.dwattr $C$DW$T$1281, DW_AT_decl_column(0x31)
$C$DW$T$1282	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1282, DW_AT_type(*$C$DW$T$1281)
$C$DW$T$1283	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1283, DW_AT_type(*$C$DW$T$1282)
	.dwattr $C$DW$T$1283, DW_AT_address_class(0x20)
$C$DW$T$1284	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Intrinsics_Module")
	.dwattr $C$DW$T$1284, DW_AT_type(*$C$DW$T$1283)
	.dwattr $C$DW$T$1284, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1284, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1284, DW_AT_decl_line(0x22)
	.dwattr $C$DW$T$1284, DW_AT_decl_column(0x31)

$C$DW$T$38	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$38, DW_AT_name("ti_sysbios_knl_Intrinsics_SupportProxy_Fxns__")
	.dwattr $C$DW$T$38, DW_AT_declaration
	.dwendtag $C$DW$T$38

	.dwattr $C$DW$T$38, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$38, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$38, DW_AT_decl_column(0x10)
$C$DW$T$1285	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Intrinsics_SupportProxy_Fxns__")
	.dwattr $C$DW$T$1285, DW_AT_type(*$C$DW$T$38)
	.dwattr $C$DW$T$1285, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1285, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1285, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$1285, DW_AT_decl_column(0x3e)
$C$DW$T$1286	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1286, DW_AT_type(*$C$DW$T$1285)
$C$DW$T$1287	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1287, DW_AT_type(*$C$DW$T$1286)
	.dwattr $C$DW$T$1287, DW_AT_address_class(0x20)
$C$DW$T$1288	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Intrinsics_SupportProxy_Module")
	.dwattr $C$DW$T$1288, DW_AT_type(*$C$DW$T$1287)
	.dwattr $C$DW$T$1288, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1288, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1288, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$1288, DW_AT_decl_column(0x3e)

$C$DW$T$39	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$39, DW_AT_name("ti_sysbios_knl_Mailbox_MbxElem")
	.dwattr $C$DW$T$39, DW_AT_declaration
	.dwendtag $C$DW$T$39

	.dwattr $C$DW$T$39, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$39, DW_AT_decl_line(0x34)
	.dwattr $C$DW$T$39, DW_AT_decl_column(0x10)
$C$DW$T$1289	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_MbxElem")
	.dwattr $C$DW$T$1289, DW_AT_type(*$C$DW$T$39)
	.dwattr $C$DW$T$1289, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1289, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1289, DW_AT_decl_line(0x34)
	.dwattr $C$DW$T$1289, DW_AT_decl_column(0x2f)

$C$DW$T$40	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$40, DW_AT_name("ti_sysbios_knl_Mailbox_Object")
	.dwattr $C$DW$T$40, DW_AT_declaration
	.dwendtag $C$DW$T$40

	.dwattr $C$DW$T$40, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$40, DW_AT_decl_line(0x36)
	.dwattr $C$DW$T$40, DW_AT_decl_column(0x10)
$C$DW$T$1290	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Object")
	.dwattr $C$DW$T$1290, DW_AT_type(*$C$DW$T$40)
	.dwattr $C$DW$T$1290, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1290, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1290, DW_AT_decl_line(0x36)
	.dwattr $C$DW$T$1290, DW_AT_decl_column(0x2e)
$C$DW$T$1291	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1291, DW_AT_type(*$C$DW$T$1290)
	.dwattr $C$DW$T$1291, DW_AT_address_class(0x20)
$C$DW$T$1292	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Handle")
	.dwattr $C$DW$T$1292, DW_AT_type(*$C$DW$T$1291)
	.dwattr $C$DW$T$1292, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1292, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1292, DW_AT_decl_line(0x38)
	.dwattr $C$DW$T$1292, DW_AT_decl_column(0x28)
$C$DW$T$1293	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Instance")
	.dwattr $C$DW$T$1293, DW_AT_type(*$C$DW$T$1291)
	.dwattr $C$DW$T$1293, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1293, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1293, DW_AT_decl_line(0x3a)
	.dwattr $C$DW$T$1293, DW_AT_decl_column(0x28)

$C$DW$T$41	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$41, DW_AT_name("ti_sysbios_knl_Mailbox_Object__")
	.dwattr $C$DW$T$41, DW_AT_declaration
	.dwendtag $C$DW$T$41

	.dwattr $C$DW$T$41, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$41, DW_AT_decl_line(0x39)
	.dwattr $C$DW$T$41, DW_AT_decl_column(0x10)
$C$DW$T$1294	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Instance_State")
	.dwattr $C$DW$T$1294, DW_AT_type(*$C$DW$T$41)
	.dwattr $C$DW$T$1294, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1294, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1294, DW_AT_decl_line(0x39)
	.dwattr $C$DW$T$1294, DW_AT_decl_column(0x30)

$C$DW$T$42	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$42, DW_AT_name("ti_sysbios_knl_Mailbox_Params")
	.dwattr $C$DW$T$42, DW_AT_declaration
	.dwendtag $C$DW$T$42

	.dwattr $C$DW$T$42, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$42, DW_AT_decl_line(0x35)
	.dwattr $C$DW$T$42, DW_AT_decl_column(0x10)
$C$DW$T$1295	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Params")
	.dwattr $C$DW$T$1295, DW_AT_type(*$C$DW$T$42)
	.dwattr $C$DW$T$1295, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1295, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1295, DW_AT_decl_line(0x35)
	.dwattr $C$DW$T$1295, DW_AT_decl_column(0x2e)

$C$DW$T$43	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$43, DW_AT_name("ti_sysbios_knl_Mailbox_Struct")
	.dwattr $C$DW$T$43, DW_AT_declaration
	.dwendtag $C$DW$T$43

	.dwattr $C$DW$T$43, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$43, DW_AT_decl_line(0x37)
	.dwattr $C$DW$T$43, DW_AT_decl_column(0x10)
$C$DW$T$1296	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Mailbox_Struct")
	.dwattr $C$DW$T$1296, DW_AT_type(*$C$DW$T$43)
	.dwattr $C$DW$T$1296, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1296, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1296, DW_AT_decl_line(0x37)
	.dwattr $C$DW$T$1296, DW_AT_decl_column(0x2e)

$C$DW$T$289	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$289, DW_AT_name("ti_sysbios_knl_Queue_Elem")
	.dwattr $C$DW$T$289, DW_AT_byte_size(0x08)
$C$DW$609	.dwtag  DW_TAG_member
	.dwattr $C$DW$609, DW_AT_type(*$C$DW$T$288)
	.dwattr $C$DW$609, DW_AT_name("next")
	.dwattr $C$DW$609, DW_AT_TI_symbol_name("next")
	.dwattr $C$DW$609, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$609, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$609, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$609, DW_AT_decl_line(0x43)
	.dwattr $C$DW$609, DW_AT_decl_column(0x29)
$C$DW$610	.dwtag  DW_TAG_member
	.dwattr $C$DW$610, DW_AT_type(*$C$DW$T$288)
	.dwattr $C$DW$610, DW_AT_name("prev")
	.dwattr $C$DW$610, DW_AT_TI_symbol_name("prev")
	.dwattr $C$DW$610, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$610, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$610, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$610, DW_AT_decl_line(0x44)
	.dwattr $C$DW$610, DW_AT_decl_column(0x29)
	.dwendtag $C$DW$T$289

	.dwattr $C$DW$T$289, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$289, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$289, DW_AT_decl_column(0x08)
$C$DW$T$249	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Elem")
	.dwattr $C$DW$T$249, DW_AT_type(*$C$DW$T$289)
	.dwattr $C$DW$T$249, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$249, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$249, DW_AT_decl_line(0x40)
	.dwattr $C$DW$T$249, DW_AT_decl_column(0x2a)
$C$DW$T$287	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$287, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$T$287, DW_AT_address_class(0x20)
$C$DW$T$288	.dwtag  DW_TAG_volatile_type
	.dwattr $C$DW$T$288, DW_AT_type(*$C$DW$T$287)

$C$DW$T$44	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$44, DW_AT_name("ti_sysbios_knl_Queue_Object")
	.dwattr $C$DW$T$44, DW_AT_declaration
	.dwendtag $C$DW$T$44

	.dwattr $C$DW$T$44, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$44, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$44, DW_AT_decl_column(0x10)
$C$DW$T$322	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Object")
	.dwattr $C$DW$T$322, DW_AT_type(*$C$DW$T$44)
	.dwattr $C$DW$T$322, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$322, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$322, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$322, DW_AT_decl_column(0x2c)
$C$DW$T$323	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$323, DW_AT_type(*$C$DW$T$322)
	.dwattr $C$DW$T$323, DW_AT_address_class(0x20)
$C$DW$T$324	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Handle")
	.dwattr $C$DW$T$324, DW_AT_type(*$C$DW$T$323)
	.dwattr $C$DW$T$324, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$324, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$324, DW_AT_decl_line(0x44)
	.dwattr $C$DW$T$324, DW_AT_decl_column(0x26)
$C$DW$T$1297	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__smpReadyQ")
	.dwattr $C$DW$T$1297, DW_AT_type(*$C$DW$T$324)
	.dwattr $C$DW$T$1297, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1297, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1297, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$1297, DW_AT_decl_column(0x25)
$C$DW$T$1298	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1298, DW_AT_type(*$C$DW$T$324)
	.dwattr $C$DW$T$1298, DW_AT_address_class(0x20)
$C$DW$T$1299	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__smpReadyQ")
	.dwattr $C$DW$T$1299, DW_AT_type(*$C$DW$T$1298)
	.dwattr $C$DW$T$1299, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1299, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1299, DW_AT_decl_line(0xa1)
	.dwattr $C$DW$T$1299, DW_AT_decl_column(0x26)
$C$DW$T$1300	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__smpReadyQ")
	.dwattr $C$DW$T$1300, DW_AT_type(*$C$DW$T$1299)
	.dwattr $C$DW$T$1300, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1300, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1300, DW_AT_decl_line(0xa2)
	.dwattr $C$DW$T$1300, DW_AT_decl_column(0x3e)
$C$DW$T$1301	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Instance")
	.dwattr $C$DW$T$1301, DW_AT_type(*$C$DW$T$323)
	.dwattr $C$DW$T$1301, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1301, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1301, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$1301, DW_AT_decl_column(0x26)

$C$DW$T$45	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$45, DW_AT_name("ti_sysbios_knl_Queue_Object__")
	.dwattr $C$DW$T$45, DW_AT_declaration
	.dwendtag $C$DW$T$45

	.dwattr $C$DW$T$45, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$45, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$45, DW_AT_decl_column(0x10)
$C$DW$T$1302	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Instance_State")
	.dwattr $C$DW$T$1302, DW_AT_type(*$C$DW$T$45)
	.dwattr $C$DW$T$1302, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1302, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1302, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$1302, DW_AT_decl_column(0x2e)
$C$DW$T$1303	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Swi_Module_State__readyQ")
	.dwattr $C$DW$T$1303, DW_AT_type(*$C$DW$T$1302)
	.dwattr $C$DW$T$1303, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1303, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1303, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$1303, DW_AT_decl_column(0x2d)
$C$DW$T$1304	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__readyQ")
	.dwattr $C$DW$T$1304, DW_AT_type(*$C$DW$T$1302)
	.dwattr $C$DW$T$1304, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1304, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1304, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$1304, DW_AT_decl_column(0x2d)
$C$DW$T$1305	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1305, DW_AT_type(*$C$DW$T$1302)
	.dwattr $C$DW$T$1305, DW_AT_address_class(0x20)
$C$DW$T$1306	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Swi_Module_State__readyQ")
	.dwattr $C$DW$T$1306, DW_AT_type(*$C$DW$T$1305)
	.dwattr $C$DW$T$1306, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1306, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1306, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$1306, DW_AT_decl_column(0x2e)
$C$DW$T$1307	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Swi_Module_State__readyQ")
	.dwattr $C$DW$T$1307, DW_AT_type(*$C$DW$T$1306)
	.dwattr $C$DW$T$1307, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1307, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1307, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$T$1307, DW_AT_decl_column(0x3a)
$C$DW$T$1308	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__readyQ")
	.dwattr $C$DW$T$1308, DW_AT_type(*$C$DW$T$1305)
	.dwattr $C$DW$T$1308, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1308, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1308, DW_AT_decl_line(0x95)
	.dwattr $C$DW$T$1308, DW_AT_decl_column(0x2e)
$C$DW$T$1309	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__readyQ")
	.dwattr $C$DW$T$1309, DW_AT_type(*$C$DW$T$1308)
	.dwattr $C$DW$T$1309, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1309, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1309, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$1309, DW_AT_decl_column(0x3b)

$C$DW$T$290	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$290, DW_AT_name("ti_sysbios_knl_Queue_Params")
	.dwattr $C$DW$T$290, DW_AT_byte_size(0x18)
$C$DW$611	.dwtag  DW_TAG_member
	.dwattr $C$DW$611, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$611, DW_AT_name("__size")
	.dwattr $C$DW$611, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$611, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$611, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$611, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$611, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$611, DW_AT_decl_column(0x0c)
$C$DW$612	.dwtag  DW_TAG_member
	.dwattr $C$DW$612, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$612, DW_AT_name("__self")
	.dwattr $C$DW$612, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$612, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$612, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$612, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$612, DW_AT_decl_line(0xa1)
	.dwattr $C$DW$612, DW_AT_decl_column(0x11)
$C$DW$613	.dwtag  DW_TAG_member
	.dwattr $C$DW$613, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$613, DW_AT_name("__fxns")
	.dwattr $C$DW$613, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$613, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$613, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$613, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$613, DW_AT_decl_line(0xa2)
	.dwattr $C$DW$613, DW_AT_decl_column(0x0b)
$C$DW$614	.dwtag  DW_TAG_member
	.dwattr $C$DW$614, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$614, DW_AT_name("instance")
	.dwattr $C$DW$614, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$614, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$614, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$614, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$614, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$614, DW_AT_decl_column(0x23)
$C$DW$615	.dwtag  DW_TAG_member
	.dwattr $C$DW$615, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$615, DW_AT_name("__iprms")
	.dwattr $C$DW$615, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$615, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$615, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$615, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$615, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$615, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$290

	.dwattr $C$DW$T$290, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$290, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$T$290, DW_AT_decl_column(0x08)
$C$DW$T$1310	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Params")
	.dwattr $C$DW$T$1310, DW_AT_type(*$C$DW$T$290)
	.dwattr $C$DW$T$1310, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1310, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1310, DW_AT_decl_line(0x41)
	.dwattr $C$DW$T$1310, DW_AT_decl_column(0x2c)

$C$DW$T$291	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$291, DW_AT_name("ti_sysbios_knl_Queue_Struct")
	.dwattr $C$DW$T$291, DW_AT_byte_size(0x0c)
$C$DW$616	.dwtag  DW_TAG_member
	.dwattr $C$DW$616, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$616, DW_AT_name("__f0")
	.dwattr $C$DW$616, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$616, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$616, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$616, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$616, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$616, DW_AT_decl_column(0x1f)
$C$DW$617	.dwtag  DW_TAG_member
	.dwattr $C$DW$617, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$617, DW_AT_name("__name")
	.dwattr $C$DW$617, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$617, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$617, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$617, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$617, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$617, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$291

	.dwattr $C$DW$T$291, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$291, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$291, DW_AT_decl_column(0x08)
$C$DW$T$285	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Queue_Struct")
	.dwattr $C$DW$T$285, DW_AT_type(*$C$DW$T$291)
	.dwattr $C$DW$T$285, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$285, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$285, DW_AT_decl_line(0x43)
	.dwattr $C$DW$T$285, DW_AT_decl_column(0x2c)

$C$DW$T$292	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$292, DW_AT_name("ti_sysbios_knl_Semaphore_Args__create")
	.dwattr $C$DW$T$292, DW_AT_byte_size(0x04)
$C$DW$618	.dwtag  DW_TAG_member
	.dwattr $C$DW$618, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$618, DW_AT_name("count")
	.dwattr $C$DW$618, DW_AT_TI_symbol_name("count")
	.dwattr $C$DW$618, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$618, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$618, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$618, DW_AT_decl_line(0x59)
	.dwattr $C$DW$618, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$292

	.dwattr $C$DW$T$292, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$292, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$292, DW_AT_decl_column(0x10)
$C$DW$T$1311	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Args__create")
	.dwattr $C$DW$T$1311, DW_AT_type(*$C$DW$T$292)
	.dwattr $C$DW$T$1311, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1311, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1311, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$1311, DW_AT_decl_column(0x03)

$C$DW$T$296	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$296, DW_AT_name("ti_sysbios_knl_Semaphore_Mode")
	.dwattr $C$DW$T$296, DW_AT_byte_size(0x01)
$C$DW$619	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_Mode_COUNTING"), DW_AT_const_value(0x00)
	.dwattr $C$DW$619, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$619, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$619, DW_AT_decl_column(0x05)
$C$DW$620	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_Mode_BINARY"), DW_AT_const_value(0x01)
	.dwattr $C$DW$620, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$620, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$620, DW_AT_decl_column(0x05)
$C$DW$621	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_Mode_COUNTING_PRIORITY"), DW_AT_const_value(0x02)
	.dwattr $C$DW$621, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$621, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$621, DW_AT_decl_column(0x05)
$C$DW$622	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_Mode_BINARY_PRIORITY"), DW_AT_const_value(0x03)
	.dwattr $C$DW$622, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$622, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$622, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$296

	.dwattr $C$DW$T$296, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$296, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$T$296, DW_AT_decl_column(0x06)
$C$DW$T$297	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Mode")
	.dwattr $C$DW$T$297, DW_AT_type(*$C$DW$T$296)
	.dwattr $C$DW$T$297, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$297, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$297, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$297, DW_AT_decl_column(0x2c)

$C$DW$T$46	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$46, DW_AT_name("ti_sysbios_knl_Semaphore_Object")
	.dwattr $C$DW$T$46, DW_AT_declaration
	.dwendtag $C$DW$T$46

	.dwattr $C$DW$T$46, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$46, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$46, DW_AT_decl_column(0x10)
$C$DW$T$1312	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Object")
	.dwattr $C$DW$T$1312, DW_AT_type(*$C$DW$T$46)
	.dwattr $C$DW$T$1312, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1312, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1312, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$T$1312, DW_AT_decl_column(0x30)
$C$DW$T$1313	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1313, DW_AT_type(*$C$DW$T$1312)
	.dwattr $C$DW$T$1313, DW_AT_address_class(0x20)
$C$DW$T$1314	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Handle")
	.dwattr $C$DW$T$1314, DW_AT_type(*$C$DW$T$1313)
	.dwattr $C$DW$T$1314, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1314, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1314, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$1314, DW_AT_decl_column(0x2a)
$C$DW$T$1315	.dwtag  DW_TAG_typedef, DW_AT_name("CyaSSL_Mutex")
	.dwattr $C$DW$T$1315, DW_AT_type(*$C$DW$T$1314)
	.dwattr $C$DW$T$1315, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1315, DW_AT_decl_file("C:/cyassl/cyassl/ctaocrypt/wc_port.h")
	.dwattr $C$DW$T$1315, DW_AT_decl_line(0x6f)
	.dwattr $C$DW$T$1315, DW_AT_decl_column(0x31)
$C$DW$T$1316	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Instance")
	.dwattr $C$DW$T$1316, DW_AT_type(*$C$DW$T$1313)
	.dwattr $C$DW$T$1316, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1316, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1316, DW_AT_decl_line(0x52)
	.dwattr $C$DW$T$1316, DW_AT_decl_column(0x2a)

$C$DW$T$47	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$47, DW_AT_name("ti_sysbios_knl_Semaphore_Object__")
	.dwattr $C$DW$T$47, DW_AT_declaration
	.dwendtag $C$DW$T$47

	.dwattr $C$DW$T$47, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$47, DW_AT_decl_line(0x51)
	.dwattr $C$DW$T$47, DW_AT_decl_column(0x10)
$C$DW$T$1317	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Instance_State")
	.dwattr $C$DW$T$1317, DW_AT_type(*$C$DW$T$47)
	.dwattr $C$DW$T$1317, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1317, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1317, DW_AT_decl_line(0x51)
	.dwattr $C$DW$T$1317, DW_AT_decl_column(0x32)

$C$DW$T$298	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$298, DW_AT_name("ti_sysbios_knl_Semaphore_Params")
	.dwattr $C$DW$T$298, DW_AT_byte_size(0x24)
$C$DW$623	.dwtag  DW_TAG_member
	.dwattr $C$DW$623, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$623, DW_AT_name("__size")
	.dwattr $C$DW$623, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$623, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$623, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$623, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$623, DW_AT_decl_line(0x103)
	.dwattr $C$DW$623, DW_AT_decl_column(0x0c)
$C$DW$624	.dwtag  DW_TAG_member
	.dwattr $C$DW$624, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$624, DW_AT_name("__self")
	.dwattr $C$DW$624, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$624, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$624, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$624, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$624, DW_AT_decl_line(0x104)
	.dwattr $C$DW$624, DW_AT_decl_column(0x11)
$C$DW$625	.dwtag  DW_TAG_member
	.dwattr $C$DW$625, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$625, DW_AT_name("__fxns")
	.dwattr $C$DW$625, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$625, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$625, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$625, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$625, DW_AT_decl_line(0x105)
	.dwattr $C$DW$625, DW_AT_decl_column(0x0b)
$C$DW$626	.dwtag  DW_TAG_member
	.dwattr $C$DW$626, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$626, DW_AT_name("instance")
	.dwattr $C$DW$626, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$626, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$626, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$626, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$626, DW_AT_decl_line(0x106)
	.dwattr $C$DW$626, DW_AT_decl_column(0x23)
$C$DW$627	.dwtag  DW_TAG_member
	.dwattr $C$DW$627, DW_AT_type(*$C$DW$T$295)
	.dwattr $C$DW$627, DW_AT_name("event")
	.dwattr $C$DW$627, DW_AT_TI_symbol_name("event")
	.dwattr $C$DW$627, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$627, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$627, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$627, DW_AT_decl_line(0x107)
	.dwattr $C$DW$627, DW_AT_decl_column(0x21)
$C$DW$628	.dwtag  DW_TAG_member
	.dwattr $C$DW$628, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$628, DW_AT_name("eventId")
	.dwattr $C$DW$628, DW_AT_TI_symbol_name("eventId")
	.dwattr $C$DW$628, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$628, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$628, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$628, DW_AT_decl_line(0x108)
	.dwattr $C$DW$628, DW_AT_decl_column(0x0e)
$C$DW$629	.dwtag  DW_TAG_member
	.dwattr $C$DW$629, DW_AT_type(*$C$DW$T$297)
	.dwattr $C$DW$629, DW_AT_name("mode")
	.dwattr $C$DW$629, DW_AT_TI_symbol_name("mode")
	.dwattr $C$DW$629, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$629, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$629, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$629, DW_AT_decl_line(0x109)
	.dwattr $C$DW$629, DW_AT_decl_column(0x23)
$C$DW$630	.dwtag  DW_TAG_member
	.dwattr $C$DW$630, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$630, DW_AT_name("__iprms")
	.dwattr $C$DW$630, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$630, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$630, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$630, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$630, DW_AT_decl_line(0x10a)
	.dwattr $C$DW$630, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$298

	.dwattr $C$DW$T$298, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$298, DW_AT_decl_line(0x102)
	.dwattr $C$DW$T$298, DW_AT_decl_column(0x08)
$C$DW$T$1318	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Params")
	.dwattr $C$DW$T$1318, DW_AT_type(*$C$DW$T$298)
	.dwattr $C$DW$T$1318, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1318, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1318, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$1318, DW_AT_decl_column(0x30)

$C$DW$T$301	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$301, DW_AT_name("ti_sysbios_knl_Semaphore_PendElem")
	.dwattr $C$DW$T$301, DW_AT_byte_size(0x14)
$C$DW$631	.dwtag  DW_TAG_member
	.dwattr $C$DW$631, DW_AT_type(*$C$DW$T$280)
	.dwattr $C$DW$631, DW_AT_name("tpElem")
	.dwattr $C$DW$631, DW_AT_TI_symbol_name("tpElem")
	.dwattr $C$DW$631, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$631, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$631, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$631, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$631, DW_AT_decl_column(0x22)
$C$DW$632	.dwtag  DW_TAG_member
	.dwattr $C$DW$632, DW_AT_type(*$C$DW$T$300)
	.dwattr $C$DW$632, DW_AT_name("pendState")
	.dwattr $C$DW$632, DW_AT_TI_symbol_name("pendState")
	.dwattr $C$DW$632, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$632, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$632, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$632, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$632, DW_AT_decl_column(0x28)
	.dwendtag $C$DW$T$301

	.dwattr $C$DW$T$301, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$301, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$T$301, DW_AT_decl_column(0x08)
$C$DW$T$1319	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_PendElem")
	.dwattr $C$DW$T$1319, DW_AT_type(*$C$DW$T$301)
	.dwattr $C$DW$T$1319, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1319, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1319, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$T$1319, DW_AT_decl_column(0x32)

$C$DW$T$299	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$299, DW_AT_name("ti_sysbios_knl_Semaphore_PendState")
	.dwattr $C$DW$T$299, DW_AT_byte_size(0x01)
$C$DW$633	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_PendState_TIMEOUT"), DW_AT_const_value(0x00)
	.dwattr $C$DW$633, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$633, DW_AT_decl_line(0x63)
	.dwattr $C$DW$633, DW_AT_decl_column(0x05)
$C$DW$634	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_PendState_POSTED"), DW_AT_const_value(0x01)
	.dwattr $C$DW$634, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$634, DW_AT_decl_line(0x64)
	.dwattr $C$DW$634, DW_AT_decl_column(0x05)
$C$DW$635	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_PendState_CLOCK_WAIT"), DW_AT_const_value(0x02)
	.dwattr $C$DW$635, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$635, DW_AT_decl_line(0x65)
	.dwattr $C$DW$635, DW_AT_decl_column(0x05)
$C$DW$636	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Semaphore_PendState_WAIT_FOREVER"), DW_AT_const_value(0x03)
	.dwattr $C$DW$636, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$636, DW_AT_decl_line(0x66)
	.dwattr $C$DW$636, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$299

	.dwattr $C$DW$T$299, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$299, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$299, DW_AT_decl_column(0x06)
$C$DW$T$300	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_PendState")
	.dwattr $C$DW$T$300, DW_AT_type(*$C$DW$T$299)
	.dwattr $C$DW$T$300, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$300, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$300, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$300, DW_AT_decl_column(0x31)

$C$DW$T$306	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$306, DW_AT_name("ti_sysbios_knl_Semaphore_Struct")
	.dwattr $C$DW$T$306, DW_AT_byte_size(0x1c)
$C$DW$637	.dwtag  DW_TAG_member
	.dwattr $C$DW$637, DW_AT_type(*$C$DW$T$295)
	.dwattr $C$DW$637, DW_AT_name("__f0")
	.dwattr $C$DW$637, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$637, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$637, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$637, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$637, DW_AT_decl_line(0x10f)
	.dwattr $C$DW$637, DW_AT_decl_column(0x21)
$C$DW$638	.dwtag  DW_TAG_member
	.dwattr $C$DW$638, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$638, DW_AT_name("__f1")
	.dwattr $C$DW$638, DW_AT_TI_symbol_name("__f1")
	.dwattr $C$DW$638, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$638, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$638, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$638, DW_AT_decl_line(0x110)
	.dwattr $C$DW$638, DW_AT_decl_column(0x0e)
$C$DW$639	.dwtag  DW_TAG_member
	.dwattr $C$DW$639, DW_AT_type(*$C$DW$T$297)
	.dwattr $C$DW$639, DW_AT_name("__f2")
	.dwattr $C$DW$639, DW_AT_TI_symbol_name("__f2")
	.dwattr $C$DW$639, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$639, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$639, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$639, DW_AT_decl_line(0x111)
	.dwattr $C$DW$639, DW_AT_decl_column(0x23)
$C$DW$640	.dwtag  DW_TAG_member
	.dwattr $C$DW$640, DW_AT_type(*$C$DW$T$305)
	.dwattr $C$DW$640, DW_AT_name("__f3")
	.dwattr $C$DW$640, DW_AT_TI_symbol_name("__f3")
	.dwattr $C$DW$640, DW_AT_data_member_location[DW_OP_plus_uconst 0xa]
	.dwattr $C$DW$640, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$640, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$640, DW_AT_decl_line(0x112)
	.dwattr $C$DW$640, DW_AT_decl_column(0x19)
$C$DW$641	.dwtag  DW_TAG_member
	.dwattr $C$DW$641, DW_AT_type(*$C$DW$T$285)
	.dwattr $C$DW$641, DW_AT_name("__f4")
	.dwattr $C$DW$641, DW_AT_TI_symbol_name("__f4")
	.dwattr $C$DW$641, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$641, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$641, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$641, DW_AT_decl_line(0x113)
	.dwattr $C$DW$641, DW_AT_decl_column(0x21)
$C$DW$642	.dwtag  DW_TAG_member
	.dwattr $C$DW$642, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$642, DW_AT_name("__name")
	.dwattr $C$DW$642, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$642, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$642, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$642, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$642, DW_AT_decl_line(0x114)
	.dwattr $C$DW$642, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$306

	.dwattr $C$DW$T$306, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$306, DW_AT_decl_line(0x10e)
	.dwattr $C$DW$T$306, DW_AT_decl_column(0x08)
$C$DW$T$1320	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Semaphore_Struct")
	.dwattr $C$DW$T$1320, DW_AT_type(*$C$DW$T$306)
	.dwattr $C$DW$T$1320, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1320, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1320, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$1320, DW_AT_decl_column(0x30)

$C$DW$T$310	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$310, DW_AT_name("ti_sysbios_knl_Swi_Args__create")
	.dwattr $C$DW$T$310, DW_AT_byte_size(0x04)
$C$DW$643	.dwtag  DW_TAG_member
	.dwattr $C$DW$643, DW_AT_type(*$C$DW$T$309)
	.dwattr $C$DW$643, DW_AT_name("swiFxn")
	.dwattr $C$DW$643, DW_AT_TI_symbol_name("swiFxn")
	.dwattr $C$DW$643, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$643, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$643, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$643, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$643, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$310

	.dwattr $C$DW$T$310, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$310, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$310, DW_AT_decl_column(0x10)
$C$DW$T$1321	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Args__create")
	.dwattr $C$DW$T$1321, DW_AT_type(*$C$DW$T$310)
	.dwattr $C$DW$T$1321, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1321, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1321, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$1321, DW_AT_decl_column(0x03)

$C$DW$T$320	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$320, DW_AT_name("ti_sysbios_knl_Swi_HookSet")
	.dwattr $C$DW$T$320, DW_AT_byte_size(0x18)
$C$DW$644	.dwtag  DW_TAG_member
	.dwattr $C$DW$644, DW_AT_type(*$C$DW$T$312)
	.dwattr $C$DW$644, DW_AT_name("registerFxn")
	.dwattr $C$DW$644, DW_AT_TI_symbol_name("registerFxn")
	.dwattr $C$DW$644, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$644, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$644, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$644, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$644, DW_AT_decl_column(0x10)
$C$DW$645	.dwtag  DW_TAG_member
	.dwattr $C$DW$645, DW_AT_type(*$C$DW$T$317)
	.dwattr $C$DW$645, DW_AT_name("createFxn")
	.dwattr $C$DW$645, DW_AT_TI_symbol_name("createFxn")
	.dwattr $C$DW$645, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$645, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$645, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$645, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$645, DW_AT_decl_column(0x10)
$C$DW$646	.dwtag  DW_TAG_member
	.dwattr $C$DW$646, DW_AT_type(*$C$DW$T$319)
	.dwattr $C$DW$646, DW_AT_name("readyFxn")
	.dwattr $C$DW$646, DW_AT_TI_symbol_name("readyFxn")
	.dwattr $C$DW$646, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$646, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$646, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$646, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$646, DW_AT_decl_column(0x10)
$C$DW$647	.dwtag  DW_TAG_member
	.dwattr $C$DW$647, DW_AT_type(*$C$DW$T$319)
	.dwattr $C$DW$647, DW_AT_name("beginFxn")
	.dwattr $C$DW$647, DW_AT_TI_symbol_name("beginFxn")
	.dwattr $C$DW$647, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$647, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$647, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$647, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$647, DW_AT_decl_column(0x10)
$C$DW$648	.dwtag  DW_TAG_member
	.dwattr $C$DW$648, DW_AT_type(*$C$DW$T$319)
	.dwattr $C$DW$648, DW_AT_name("endFxn")
	.dwattr $C$DW$648, DW_AT_TI_symbol_name("endFxn")
	.dwattr $C$DW$648, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$648, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$648, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$648, DW_AT_decl_line(0x50)
	.dwattr $C$DW$648, DW_AT_decl_column(0x10)
$C$DW$649	.dwtag  DW_TAG_member
	.dwattr $C$DW$649, DW_AT_type(*$C$DW$T$319)
	.dwattr $C$DW$649, DW_AT_name("deleteFxn")
	.dwattr $C$DW$649, DW_AT_TI_symbol_name("deleteFxn")
	.dwattr $C$DW$649, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$649, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$649, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$649, DW_AT_decl_line(0x51)
	.dwattr $C$DW$649, DW_AT_decl_column(0x10)
	.dwendtag $C$DW$T$320

	.dwattr $C$DW$T$320, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$320, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$320, DW_AT_decl_column(0x08)
$C$DW$T$122	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_HookSet")
	.dwattr $C$DW$T$122, DW_AT_type(*$C$DW$T$320)
	.dwattr $C$DW$T$122, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$122, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$122, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$122, DW_AT_decl_column(0x2b)
$C$DW$T$1322	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Swi_hooks")
	.dwattr $C$DW$T$1322, DW_AT_type(*$C$DW$T$122)
	.dwattr $C$DW$T$1322, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1322, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1322, DW_AT_decl_line(0xe1)
	.dwattr $C$DW$T$1322, DW_AT_decl_column(0x24)
$C$DW$T$123	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$123, DW_AT_type(*$C$DW$T$122)
	.dwattr $C$DW$T$123, DW_AT_address_class(0x20)

$C$DW$T$48	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$48, DW_AT_name("ti_sysbios_knl_Swi_Module_State")
	.dwattr $C$DW$T$48, DW_AT_declaration
	.dwendtag $C$DW$T$48

	.dwattr $C$DW$T$48, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$48, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$48, DW_AT_decl_column(0x10)
$C$DW$T$1323	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Module_State")
	.dwattr $C$DW$T$1323, DW_AT_type(*$C$DW$T$48)
	.dwattr $C$DW$T$1323, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1323, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1323, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$1323, DW_AT_decl_column(0x30)

$C$DW$T$49	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$49, DW_AT_name("ti_sysbios_knl_Swi_Object")
	.dwattr $C$DW$T$49, DW_AT_declaration
	.dwendtag $C$DW$T$49

	.dwattr $C$DW$T$49, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$49, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$T$49, DW_AT_decl_column(0x10)
$C$DW$T$313	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Object")
	.dwattr $C$DW$T$313, DW_AT_type(*$C$DW$T$49)
	.dwattr $C$DW$T$313, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$313, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$313, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$T$313, DW_AT_decl_column(0x2a)
$C$DW$T$314	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$314, DW_AT_type(*$C$DW$T$313)
	.dwattr $C$DW$T$314, DW_AT_address_class(0x20)
$C$DW$T$315	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Handle")
	.dwattr $C$DW$T$315, DW_AT_type(*$C$DW$T$314)
	.dwattr $C$DW$T$315, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$315, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$315, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$315, DW_AT_decl_column(0x24)
$C$DW$T$1324	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Swi_Module_State__constructedSwis")
	.dwattr $C$DW$T$1324, DW_AT_type(*$C$DW$T$315)
	.dwattr $C$DW$T$1324, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1324, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1324, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$1324, DW_AT_decl_column(0x23)
$C$DW$T$1325	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1325, DW_AT_type(*$C$DW$T$315)
	.dwattr $C$DW$T$1325, DW_AT_address_class(0x20)
$C$DW$T$1326	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Swi_Module_State__constructedSwis")
	.dwattr $C$DW$T$1326, DW_AT_type(*$C$DW$T$1325)
	.dwattr $C$DW$T$1326, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1326, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1326, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$1326, DW_AT_decl_column(0x24)
$C$DW$T$1327	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Swi_Module_State__constructedSwis")
	.dwattr $C$DW$T$1327, DW_AT_type(*$C$DW$T$1326)
	.dwattr $C$DW$T$1327, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1327, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1327, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$1327, DW_AT_decl_column(0x43)
$C$DW$T$1328	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Instance")
	.dwattr $C$DW$T$1328, DW_AT_type(*$C$DW$T$314)
	.dwattr $C$DW$T$1328, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1328, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1328, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$T$1328, DW_AT_decl_column(0x24)

$C$DW$T$50	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$50, DW_AT_name("ti_sysbios_knl_Swi_Object__")
	.dwattr $C$DW$T$50, DW_AT_declaration
	.dwendtag $C$DW$T$50

	.dwattr $C$DW$T$50, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$50, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$50, DW_AT_decl_column(0x10)
$C$DW$T$1329	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Instance_State")
	.dwattr $C$DW$T$1329, DW_AT_type(*$C$DW$T$50)
	.dwattr $C$DW$T$1329, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1329, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1329, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$1329, DW_AT_decl_column(0x2c)

$C$DW$T$321	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$321, DW_AT_name("ti_sysbios_knl_Swi_Params")
	.dwattr $C$DW$T$321, DW_AT_byte_size(0x28)
$C$DW$650	.dwtag  DW_TAG_member
	.dwattr $C$DW$650, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$650, DW_AT_name("__size")
	.dwattr $C$DW$650, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$650, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$650, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$650, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$650, DW_AT_decl_line(0x101)
	.dwattr $C$DW$650, DW_AT_decl_column(0x0c)
$C$DW$651	.dwtag  DW_TAG_member
	.dwattr $C$DW$651, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$651, DW_AT_name("__self")
	.dwattr $C$DW$651, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$651, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$651, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$651, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$651, DW_AT_decl_line(0x102)
	.dwattr $C$DW$651, DW_AT_decl_column(0x11)
$C$DW$652	.dwtag  DW_TAG_member
	.dwattr $C$DW$652, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$652, DW_AT_name("__fxns")
	.dwattr $C$DW$652, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$652, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$652, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$652, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$652, DW_AT_decl_line(0x103)
	.dwattr $C$DW$652, DW_AT_decl_column(0x0b)
$C$DW$653	.dwtag  DW_TAG_member
	.dwattr $C$DW$653, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$653, DW_AT_name("instance")
	.dwattr $C$DW$653, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$653, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$653, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$653, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$653, DW_AT_decl_line(0x104)
	.dwattr $C$DW$653, DW_AT_decl_column(0x23)
$C$DW$654	.dwtag  DW_TAG_member
	.dwattr $C$DW$654, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$654, DW_AT_name("arg0")
	.dwattr $C$DW$654, DW_AT_TI_symbol_name("arg0")
	.dwattr $C$DW$654, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$654, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$654, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$654, DW_AT_decl_line(0x105)
	.dwattr $C$DW$654, DW_AT_decl_column(0x0e)
$C$DW$655	.dwtag  DW_TAG_member
	.dwattr $C$DW$655, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$655, DW_AT_name("arg1")
	.dwattr $C$DW$655, DW_AT_TI_symbol_name("arg1")
	.dwattr $C$DW$655, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$655, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$655, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$655, DW_AT_decl_line(0x106)
	.dwattr $C$DW$655, DW_AT_decl_column(0x0e)
$C$DW$656	.dwtag  DW_TAG_member
	.dwattr $C$DW$656, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$656, DW_AT_name("priority")
	.dwattr $C$DW$656, DW_AT_TI_symbol_name("priority")
	.dwattr $C$DW$656, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$656, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$656, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$656, DW_AT_decl_line(0x107)
	.dwattr $C$DW$656, DW_AT_decl_column(0x0e)
$C$DW$657	.dwtag  DW_TAG_member
	.dwattr $C$DW$657, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$657, DW_AT_name("trigger")
	.dwattr $C$DW$657, DW_AT_TI_symbol_name("trigger")
	.dwattr $C$DW$657, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$657, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$657, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$657, DW_AT_decl_line(0x108)
	.dwattr $C$DW$657, DW_AT_decl_column(0x0e)
$C$DW$658	.dwtag  DW_TAG_member
	.dwattr $C$DW$658, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$658, DW_AT_name("__iprms")
	.dwattr $C$DW$658, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$658, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$658, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$658, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$658, DW_AT_decl_line(0x109)
	.dwattr $C$DW$658, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$321

	.dwattr $C$DW$T$321, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$321, DW_AT_decl_line(0x100)
	.dwattr $C$DW$T$321, DW_AT_decl_column(0x08)
$C$DW$T$1330	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Params")
	.dwattr $C$DW$T$1330, DW_AT_type(*$C$DW$T$321)
	.dwattr $C$DW$T$1330, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1330, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1330, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$1330, DW_AT_decl_column(0x2a)

$C$DW$T$327	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$327, DW_AT_name("ti_sysbios_knl_Swi_Struct")
	.dwattr $C$DW$T$327, DW_AT_byte_size(0x34)
$C$DW$659	.dwtag  DW_TAG_member
	.dwattr $C$DW$659, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$659, DW_AT_name("__f0")
	.dwattr $C$DW$659, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$659, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$659, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$659, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$659, DW_AT_decl_line(0x10e)
	.dwattr $C$DW$659, DW_AT_decl_column(0x1f)
$C$DW$660	.dwtag  DW_TAG_member
	.dwattr $C$DW$660, DW_AT_type(*$C$DW$T$309)
	.dwattr $C$DW$660, DW_AT_name("__f1")
	.dwattr $C$DW$660, DW_AT_TI_symbol_name("__f1")
	.dwattr $C$DW$660, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$660, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$660, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$660, DW_AT_decl_line(0x10f)
	.dwattr $C$DW$660, DW_AT_decl_column(0x20)
$C$DW$661	.dwtag  DW_TAG_member
	.dwattr $C$DW$661, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$661, DW_AT_name("__f2")
	.dwattr $C$DW$661, DW_AT_TI_symbol_name("__f2")
	.dwattr $C$DW$661, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$661, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$661, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$661, DW_AT_decl_line(0x110)
	.dwattr $C$DW$661, DW_AT_decl_column(0x0e)
$C$DW$662	.dwtag  DW_TAG_member
	.dwattr $C$DW$662, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$662, DW_AT_name("__f3")
	.dwattr $C$DW$662, DW_AT_TI_symbol_name("__f3")
	.dwattr $C$DW$662, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$662, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$662, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$662, DW_AT_decl_line(0x111)
	.dwattr $C$DW$662, DW_AT_decl_column(0x0e)
$C$DW$663	.dwtag  DW_TAG_member
	.dwattr $C$DW$663, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$663, DW_AT_name("__f4")
	.dwattr $C$DW$663, DW_AT_TI_symbol_name("__f4")
	.dwattr $C$DW$663, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$663, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$663, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$663, DW_AT_decl_line(0x112)
	.dwattr $C$DW$663, DW_AT_decl_column(0x0e)
$C$DW$664	.dwtag  DW_TAG_member
	.dwattr $C$DW$664, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$664, DW_AT_name("__f5")
	.dwattr $C$DW$664, DW_AT_TI_symbol_name("__f5")
	.dwattr $C$DW$664, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$664, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$664, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$664, DW_AT_decl_line(0x113)
	.dwattr $C$DW$664, DW_AT_decl_column(0x0e)
$C$DW$665	.dwtag  DW_TAG_member
	.dwattr $C$DW$665, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$665, DW_AT_name("__f6")
	.dwattr $C$DW$665, DW_AT_TI_symbol_name("__f6")
	.dwattr $C$DW$665, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$665, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$665, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$665, DW_AT_decl_line(0x114)
	.dwattr $C$DW$665, DW_AT_decl_column(0x0e)
$C$DW$666	.dwtag  DW_TAG_member
	.dwattr $C$DW$666, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$666, DW_AT_name("__f7")
	.dwattr $C$DW$666, DW_AT_TI_symbol_name("__f7")
	.dwattr $C$DW$666, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$666, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$666, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$666, DW_AT_decl_line(0x115)
	.dwattr $C$DW$666, DW_AT_decl_column(0x0e)
$C$DW$667	.dwtag  DW_TAG_member
	.dwattr $C$DW$667, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$667, DW_AT_name("__f8")
	.dwattr $C$DW$667, DW_AT_TI_symbol_name("__f8")
	.dwattr $C$DW$667, DW_AT_data_member_location[DW_OP_plus_uconst 0x24]
	.dwattr $C$DW$667, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$667, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$667, DW_AT_decl_line(0x116)
	.dwattr $C$DW$667, DW_AT_decl_column(0x0e)
$C$DW$668	.dwtag  DW_TAG_member
	.dwattr $C$DW$668, DW_AT_type(*$C$DW$T$324)
	.dwattr $C$DW$668, DW_AT_name("__f9")
	.dwattr $C$DW$668, DW_AT_TI_symbol_name("__f9")
	.dwattr $C$DW$668, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$668, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$668, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$668, DW_AT_decl_line(0x117)
	.dwattr $C$DW$668, DW_AT_decl_column(0x21)
$C$DW$669	.dwtag  DW_TAG_member
	.dwattr $C$DW$669, DW_AT_type(*$C$DW$T$326)
	.dwattr $C$DW$669, DW_AT_name("__f10")
	.dwattr $C$DW$669, DW_AT_TI_symbol_name("__f10")
	.dwattr $C$DW$669, DW_AT_data_member_location[DW_OP_plus_uconst 0x2c]
	.dwattr $C$DW$669, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$669, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$669, DW_AT_decl_line(0x118)
	.dwattr $C$DW$669, DW_AT_decl_column(0x35)
$C$DW$670	.dwtag  DW_TAG_member
	.dwattr $C$DW$670, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$670, DW_AT_name("__name")
	.dwattr $C$DW$670, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$670, DW_AT_data_member_location[DW_OP_plus_uconst 0x30]
	.dwattr $C$DW$670, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$670, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$670, DW_AT_decl_line(0x119)
	.dwattr $C$DW$670, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$327

	.dwattr $C$DW$T$327, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$327, DW_AT_decl_line(0x10d)
	.dwattr $C$DW$T$327, DW_AT_decl_column(0x08)
$C$DW$T$1331	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Swi_Struct")
	.dwattr $C$DW$T$1331, DW_AT_type(*$C$DW$T$327)
	.dwattr $C$DW$T$1331, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1331, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1331, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$1331, DW_AT_decl_column(0x2a)

$C$DW$T$329	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$329, DW_AT_name("ti_sysbios_knl_Task_Args__create")
	.dwattr $C$DW$T$329, DW_AT_byte_size(0x04)
$C$DW$671	.dwtag  DW_TAG_member
	.dwattr $C$DW$671, DW_AT_type(*$C$DW$T$328)
	.dwattr $C$DW$671, DW_AT_name("fxn")
	.dwattr $C$DW$671, DW_AT_TI_symbol_name("fxn")
	.dwattr $C$DW$671, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$671, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$671, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$671, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$671, DW_AT_decl_column(0x21)
	.dwendtag $C$DW$T$329

	.dwattr $C$DW$T$329, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$329, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$329, DW_AT_decl_column(0x10)
$C$DW$T$1332	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Args__create")
	.dwattr $C$DW$T$1332, DW_AT_type(*$C$DW$T$329)
	.dwattr $C$DW$T$1332, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1332, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1332, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$1332, DW_AT_decl_column(0x03)

$C$DW$T$339	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$339, DW_AT_name("ti_sysbios_knl_Task_HookSet")
	.dwattr $C$DW$T$339, DW_AT_byte_size(0x18)
$C$DW$672	.dwtag  DW_TAG_member
	.dwattr $C$DW$672, DW_AT_type(*$C$DW$T$312)
	.dwattr $C$DW$672, DW_AT_name("registerFxn")
	.dwattr $C$DW$672, DW_AT_TI_symbol_name("registerFxn")
	.dwattr $C$DW$672, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$672, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$672, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$672, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$672, DW_AT_decl_column(0x10)
$C$DW$673	.dwtag  DW_TAG_member
	.dwattr $C$DW$673, DW_AT_type(*$C$DW$T$334)
	.dwattr $C$DW$673, DW_AT_name("createFxn")
	.dwattr $C$DW$673, DW_AT_TI_symbol_name("createFxn")
	.dwattr $C$DW$673, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$673, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$673, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$673, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$673, DW_AT_decl_column(0x10)
$C$DW$674	.dwtag  DW_TAG_member
	.dwattr $C$DW$674, DW_AT_type(*$C$DW$T$336)
	.dwattr $C$DW$674, DW_AT_name("readyFxn")
	.dwattr $C$DW$674, DW_AT_TI_symbol_name("readyFxn")
	.dwattr $C$DW$674, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$674, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$674, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$674, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$674, DW_AT_decl_column(0x10)
$C$DW$675	.dwtag  DW_TAG_member
	.dwattr $C$DW$675, DW_AT_type(*$C$DW$T$338)
	.dwattr $C$DW$675, DW_AT_name("switchFxn")
	.dwattr $C$DW$675, DW_AT_TI_symbol_name("switchFxn")
	.dwattr $C$DW$675, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$675, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$675, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$675, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$675, DW_AT_decl_column(0x10)
$C$DW$676	.dwtag  DW_TAG_member
	.dwattr $C$DW$676, DW_AT_type(*$C$DW$T$336)
	.dwattr $C$DW$676, DW_AT_name("exitFxn")
	.dwattr $C$DW$676, DW_AT_TI_symbol_name("exitFxn")
	.dwattr $C$DW$676, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$676, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$676, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$676, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$676, DW_AT_decl_column(0x10)
$C$DW$677	.dwtag  DW_TAG_member
	.dwattr $C$DW$677, DW_AT_type(*$C$DW$T$336)
	.dwattr $C$DW$677, DW_AT_name("deleteFxn")
	.dwattr $C$DW$677, DW_AT_TI_symbol_name("deleteFxn")
	.dwattr $C$DW$677, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$677, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$677, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$677, DW_AT_decl_line(0x6f)
	.dwattr $C$DW$677, DW_AT_decl_column(0x10)
	.dwendtag $C$DW$T$339

	.dwattr $C$DW$T$339, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$339, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$339, DW_AT_decl_column(0x08)
$C$DW$T$125	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_HookSet")
	.dwattr $C$DW$T$125, DW_AT_type(*$C$DW$T$339)
	.dwattr $C$DW$T$125, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$125, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$125, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$125, DW_AT_decl_column(0x2c)
$C$DW$T$1333	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_hooks")
	.dwattr $C$DW$T$1333, DW_AT_type(*$C$DW$T$125)
	.dwattr $C$DW$T$1333, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1333, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1333, DW_AT_decl_line(0x19e)
	.dwattr $C$DW$T$1333, DW_AT_decl_column(0x25)
$C$DW$T$126	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$126, DW_AT_type(*$C$DW$T$125)
	.dwattr $C$DW$T$126, DW_AT_address_class(0x20)

$C$DW$T$347	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$347, DW_AT_name("ti_sysbios_knl_Task_Mode")
	.dwattr $C$DW$T$347, DW_AT_byte_size(0x01)
$C$DW$678	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Task_Mode_RUNNING"), DW_AT_const_value(0x00)
	.dwattr $C$DW$678, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$678, DW_AT_decl_line(0x54)
	.dwattr $C$DW$678, DW_AT_decl_column(0x05)
$C$DW$679	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Task_Mode_READY"), DW_AT_const_value(0x01)
	.dwattr $C$DW$679, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$679, DW_AT_decl_line(0x55)
	.dwattr $C$DW$679, DW_AT_decl_column(0x05)
$C$DW$680	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Task_Mode_BLOCKED"), DW_AT_const_value(0x02)
	.dwattr $C$DW$680, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$680, DW_AT_decl_line(0x56)
	.dwattr $C$DW$680, DW_AT_decl_column(0x05)
$C$DW$681	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Task_Mode_TERMINATED"), DW_AT_const_value(0x03)
	.dwattr $C$DW$681, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$681, DW_AT_decl_line(0x57)
	.dwattr $C$DW$681, DW_AT_decl_column(0x05)
$C$DW$682	.dwtag  DW_TAG_enumerator, DW_AT_name("ti_sysbios_knl_Task_Mode_INACTIVE"), DW_AT_const_value(0x04)
	.dwattr $C$DW$682, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$682, DW_AT_decl_line(0x58)
	.dwattr $C$DW$682, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$347

	.dwattr $C$DW$T$347, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$347, DW_AT_decl_line(0x53)
	.dwattr $C$DW$T$347, DW_AT_decl_column(0x06)
$C$DW$T$348	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Mode")
	.dwattr $C$DW$T$348, DW_AT_type(*$C$DW$T$347)
	.dwattr $C$DW$T$348, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$348, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$348, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$T$348, DW_AT_decl_column(0x27)

$C$DW$T$51	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$51, DW_AT_name("ti_sysbios_knl_Task_Module_State")
	.dwattr $C$DW$T$51, DW_AT_declaration
	.dwendtag $C$DW$T$51

	.dwattr $C$DW$T$51, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$51, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$51, DW_AT_decl_column(0x10)
$C$DW$T$1334	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Module_State")
	.dwattr $C$DW$T$1334, DW_AT_type(*$C$DW$T$51)
	.dwattr $C$DW$T$1334, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1334, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1334, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$1334, DW_AT_decl_column(0x31)

$C$DW$T$52	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$52, DW_AT_name("ti_sysbios_knl_Task_Object")
	.dwattr $C$DW$T$52, DW_AT_declaration
	.dwendtag $C$DW$T$52

	.dwattr $C$DW$T$52, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$52, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$52, DW_AT_decl_column(0x10)
$C$DW$T$330	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Object")
	.dwattr $C$DW$T$330, DW_AT_type(*$C$DW$T$52)
	.dwattr $C$DW$T$330, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$330, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$330, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$330, DW_AT_decl_column(0x2b)
$C$DW$T$331	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$331, DW_AT_type(*$C$DW$T$330)
	.dwattr $C$DW$T$331, DW_AT_address_class(0x20)
$C$DW$T$332	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Handle")
	.dwattr $C$DW$T$332, DW_AT_type(*$C$DW$T$331)
	.dwattr $C$DW$T$332, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$332, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$332, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$332, DW_AT_decl_column(0x25)
$C$DW$T$1335	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__constructedTasks")
	.dwattr $C$DW$T$1335, DW_AT_type(*$C$DW$T$332)
	.dwattr $C$DW$T$1335, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1335, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1335, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$1335, DW_AT_decl_column(0x24)
$C$DW$T$1336	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__idleTask")
	.dwattr $C$DW$T$1336, DW_AT_type(*$C$DW$T$332)
	.dwattr $C$DW$T$1336, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1336, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1336, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$1336, DW_AT_decl_column(0x24)
$C$DW$T$1337	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_ti_sysbios_knl_Task_Module_State__smpCurTask")
	.dwattr $C$DW$T$1337, DW_AT_type(*$C$DW$T$332)
	.dwattr $C$DW$T$1337, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1337, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1337, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$1337, DW_AT_decl_column(0x24)
$C$DW$T$1338	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1338, DW_AT_type(*$C$DW$T$332)
	.dwattr $C$DW$T$1338, DW_AT_address_class(0x20)
$C$DW$T$1339	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__constructedTasks")
	.dwattr $C$DW$T$1339, DW_AT_type(*$C$DW$T$1338)
	.dwattr $C$DW$T$1339, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1339, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1339, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$1339, DW_AT_decl_column(0x25)
$C$DW$T$1340	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__constructedTasks")
	.dwattr $C$DW$T$1340, DW_AT_type(*$C$DW$T$1339)
	.dwattr $C$DW$T$1340, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1340, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1340, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$1340, DW_AT_decl_column(0x45)
$C$DW$T$1341	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__idleTask")
	.dwattr $C$DW$T$1341, DW_AT_type(*$C$DW$T$1338)
	.dwattr $C$DW$T$1341, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1341, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1341, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$T$1341, DW_AT_decl_column(0x25)
$C$DW$T$1342	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__idleTask")
	.dwattr $C$DW$T$1342, DW_AT_type(*$C$DW$T$1341)
	.dwattr $C$DW$T$1342, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1342, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1342, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$T$1342, DW_AT_decl_column(0x3d)
$C$DW$T$1343	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_ti_sysbios_knl_Task_Module_State__smpCurTask")
	.dwattr $C$DW$T$1343, DW_AT_type(*$C$DW$T$1338)
	.dwattr $C$DW$T$1343, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1343, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1343, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$T$1343, DW_AT_decl_column(0x25)
$C$DW$T$1344	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_ti_sysbios_knl_Task_Module_State__smpCurTask")
	.dwattr $C$DW$T$1344, DW_AT_type(*$C$DW$T$1343)
	.dwattr $C$DW$T$1344, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1344, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1344, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$T$1344, DW_AT_decl_column(0x3f)
$C$DW$T$1345	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Instance")
	.dwattr $C$DW$T$1345, DW_AT_type(*$C$DW$T$331)
	.dwattr $C$DW$T$1345, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1345, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1345, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$1345, DW_AT_decl_column(0x25)

$C$DW$T$53	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$53, DW_AT_name("ti_sysbios_knl_Task_Object__")
	.dwattr $C$DW$T$53, DW_AT_declaration
	.dwendtag $C$DW$T$53

	.dwattr $C$DW$T$53, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$53, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$53, DW_AT_decl_column(0x10)
$C$DW$T$1346	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Instance_State")
	.dwattr $C$DW$T$1346, DW_AT_type(*$C$DW$T$53)
	.dwattr $C$DW$T$1346, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1346, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1346, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$1346, DW_AT_decl_column(0x2d)

$C$DW$T$342	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$342, DW_AT_name("ti_sysbios_knl_Task_Params")
	.dwattr $C$DW$T$342, DW_AT_byte_size(0x3c)
$C$DW$683	.dwtag  DW_TAG_member
	.dwattr $C$DW$683, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$683, DW_AT_name("__size")
	.dwattr $C$DW$683, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$683, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$683, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$683, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$683, DW_AT_decl_line(0x1b9)
	.dwattr $C$DW$683, DW_AT_decl_column(0x0c)
$C$DW$684	.dwtag  DW_TAG_member
	.dwattr $C$DW$684, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$684, DW_AT_name("__self")
	.dwattr $C$DW$684, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$684, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$684, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$684, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$684, DW_AT_decl_line(0x1ba)
	.dwattr $C$DW$684, DW_AT_decl_column(0x11)
$C$DW$685	.dwtag  DW_TAG_member
	.dwattr $C$DW$685, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$685, DW_AT_name("__fxns")
	.dwattr $C$DW$685, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$685, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$685, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$685, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$685, DW_AT_decl_line(0x1bb)
	.dwattr $C$DW$685, DW_AT_decl_column(0x0b)
$C$DW$686	.dwtag  DW_TAG_member
	.dwattr $C$DW$686, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$686, DW_AT_name("instance")
	.dwattr $C$DW$686, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$686, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$686, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$686, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$686, DW_AT_decl_line(0x1bc)
	.dwattr $C$DW$686, DW_AT_decl_column(0x23)
$C$DW$687	.dwtag  DW_TAG_member
	.dwattr $C$DW$687, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$687, DW_AT_name("arg0")
	.dwattr $C$DW$687, DW_AT_TI_symbol_name("arg0")
	.dwattr $C$DW$687, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$687, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$687, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$687, DW_AT_decl_line(0x1bd)
	.dwattr $C$DW$687, DW_AT_decl_column(0x0e)
$C$DW$688	.dwtag  DW_TAG_member
	.dwattr $C$DW$688, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$688, DW_AT_name("arg1")
	.dwattr $C$DW$688, DW_AT_TI_symbol_name("arg1")
	.dwattr $C$DW$688, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$688, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$688, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$688, DW_AT_decl_line(0x1be)
	.dwattr $C$DW$688, DW_AT_decl_column(0x0e)
$C$DW$689	.dwtag  DW_TAG_member
	.dwattr $C$DW$689, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$689, DW_AT_name("priority")
	.dwattr $C$DW$689, DW_AT_TI_symbol_name("priority")
	.dwattr $C$DW$689, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$689, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$689, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$689, DW_AT_decl_line(0x1bf)
	.dwattr $C$DW$689, DW_AT_decl_column(0x0d)
$C$DW$690	.dwtag  DW_TAG_member
	.dwattr $C$DW$690, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$690, DW_AT_name("stack")
	.dwattr $C$DW$690, DW_AT_TI_symbol_name("stack")
	.dwattr $C$DW$690, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$690, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$690, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$690, DW_AT_decl_line(0x1c0)
	.dwattr $C$DW$690, DW_AT_decl_column(0x0d)
$C$DW$691	.dwtag  DW_TAG_member
	.dwattr $C$DW$691, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$691, DW_AT_name("stackSize")
	.dwattr $C$DW$691, DW_AT_TI_symbol_name("stackSize")
	.dwattr $C$DW$691, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$691, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$691, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$691, DW_AT_decl_line(0x1c1)
	.dwattr $C$DW$691, DW_AT_decl_column(0x0f)
$C$DW$692	.dwtag  DW_TAG_member
	.dwattr $C$DW$692, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$692, DW_AT_name("stackHeap")
	.dwattr $C$DW$692, DW_AT_TI_symbol_name("stackHeap")
	.dwattr $C$DW$692, DW_AT_data_member_location[DW_OP_plus_uconst 0x24]
	.dwattr $C$DW$692, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$692, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$692, DW_AT_decl_line(0x1c2)
	.dwattr $C$DW$692, DW_AT_decl_column(0x1e)
$C$DW$693	.dwtag  DW_TAG_member
	.dwattr $C$DW$693, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$693, DW_AT_name("env")
	.dwattr $C$DW$693, DW_AT_TI_symbol_name("env")
	.dwattr $C$DW$693, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$693, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$693, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$693, DW_AT_decl_line(0x1c3)
	.dwattr $C$DW$693, DW_AT_decl_column(0x0d)
$C$DW$694	.dwtag  DW_TAG_member
	.dwattr $C$DW$694, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$694, DW_AT_name("vitalTaskFlag")
	.dwattr $C$DW$694, DW_AT_TI_symbol_name("vitalTaskFlag")
	.dwattr $C$DW$694, DW_AT_data_member_location[DW_OP_plus_uconst 0x2c]
	.dwattr $C$DW$694, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$694, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$694, DW_AT_decl_line(0x1c4)
	.dwattr $C$DW$694, DW_AT_decl_column(0x0e)
$C$DW$695	.dwtag  DW_TAG_member
	.dwattr $C$DW$695, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$695, DW_AT_name("affinity")
	.dwattr $C$DW$695, DW_AT_TI_symbol_name("affinity")
	.dwattr $C$DW$695, DW_AT_data_member_location[DW_OP_plus_uconst 0x30]
	.dwattr $C$DW$695, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$695, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$695, DW_AT_decl_line(0x1c5)
	.dwattr $C$DW$695, DW_AT_decl_column(0x0e)
$C$DW$696	.dwtag  DW_TAG_member
	.dwattr $C$DW$696, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$696, DW_AT_name("__iprms")
	.dwattr $C$DW$696, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$696, DW_AT_data_member_location[DW_OP_plus_uconst 0x34]
	.dwattr $C$DW$696, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$696, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$696, DW_AT_decl_line(0x1c6)
	.dwattr $C$DW$696, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$342

	.dwattr $C$DW$T$342, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$342, DW_AT_decl_line(0x1b8)
	.dwattr $C$DW$T$342, DW_AT_decl_column(0x08)
$C$DW$T$1347	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Params")
	.dwattr $C$DW$T$1347, DW_AT_type(*$C$DW$T$342)
	.dwattr $C$DW$T$1347, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1347, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1347, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$1347, DW_AT_decl_column(0x2b)

$C$DW$T$346	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$346, DW_AT_name("ti_sysbios_knl_Task_PendElem")
	.dwattr $C$DW$T$346, DW_AT_byte_size(0x10)
$C$DW$697	.dwtag  DW_TAG_member
	.dwattr $C$DW$697, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$697, DW_AT_name("qElem")
	.dwattr $C$DW$697, DW_AT_TI_symbol_name("qElem")
	.dwattr $C$DW$697, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$697, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$697, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$697, DW_AT_decl_line(0x86)
	.dwattr $C$DW$697, DW_AT_decl_column(0x1f)
$C$DW$698	.dwtag  DW_TAG_member
	.dwattr $C$DW$698, DW_AT_type(*$C$DW$T$332)
	.dwattr $C$DW$698, DW_AT_name("task")
	.dwattr $C$DW$698, DW_AT_TI_symbol_name("task")
	.dwattr $C$DW$698, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$698, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$698, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$698, DW_AT_decl_line(0x87)
	.dwattr $C$DW$698, DW_AT_decl_column(0x20)
$C$DW$699	.dwtag  DW_TAG_member
	.dwattr $C$DW$699, DW_AT_type(*$C$DW$T$345)
	.dwattr $C$DW$699, DW_AT_name("clock")
	.dwattr $C$DW$699, DW_AT_TI_symbol_name("clock")
	.dwattr $C$DW$699, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$699, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$699, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$699, DW_AT_decl_line(0x88)
	.dwattr $C$DW$699, DW_AT_decl_column(0x21)
	.dwendtag $C$DW$T$346

	.dwattr $C$DW$T$346, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$346, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$346, DW_AT_decl_column(0x08)
$C$DW$T$280	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_PendElem")
	.dwattr $C$DW$T$280, DW_AT_type(*$C$DW$T$346)
	.dwattr $C$DW$T$280, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$280, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$280, DW_AT_decl_line(0x67)
	.dwattr $C$DW$T$280, DW_AT_decl_column(0x2d)
$C$DW$T$351	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$351, DW_AT_type(*$C$DW$T$280)
	.dwattr $C$DW$T$351, DW_AT_address_class(0x20)

$C$DW$T$349	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$349, DW_AT_name("ti_sysbios_knl_Task_Stat")
	.dwattr $C$DW$T$349, DW_AT_byte_size(0x20)
$C$DW$700	.dwtag  DW_TAG_member
	.dwattr $C$DW$700, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$700, DW_AT_name("priority")
	.dwattr $C$DW$700, DW_AT_TI_symbol_name("priority")
	.dwattr $C$DW$700, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$700, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$700, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$700, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$700, DW_AT_decl_column(0x0d)
$C$DW$701	.dwtag  DW_TAG_member
	.dwattr $C$DW$701, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$701, DW_AT_name("stack")
	.dwattr $C$DW$701, DW_AT_TI_symbol_name("stack")
	.dwattr $C$DW$701, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$701, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$701, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$701, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$701, DW_AT_decl_column(0x0d)
$C$DW$702	.dwtag  DW_TAG_member
	.dwattr $C$DW$702, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$702, DW_AT_name("stackSize")
	.dwattr $C$DW$702, DW_AT_TI_symbol_name("stackSize")
	.dwattr $C$DW$702, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$702, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$702, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$702, DW_AT_decl_line(0x60)
	.dwattr $C$DW$702, DW_AT_decl_column(0x0f)
$C$DW$703	.dwtag  DW_TAG_member
	.dwattr $C$DW$703, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$703, DW_AT_name("stackHeap")
	.dwattr $C$DW$703, DW_AT_TI_symbol_name("stackHeap")
	.dwattr $C$DW$703, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$703, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$703, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$703, DW_AT_decl_line(0x61)
	.dwattr $C$DW$703, DW_AT_decl_column(0x1e)
$C$DW$704	.dwtag  DW_TAG_member
	.dwattr $C$DW$704, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$704, DW_AT_name("env")
	.dwattr $C$DW$704, DW_AT_TI_symbol_name("env")
	.dwattr $C$DW$704, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$704, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$704, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$704, DW_AT_decl_line(0x62)
	.dwattr $C$DW$704, DW_AT_decl_column(0x0d)
$C$DW$705	.dwtag  DW_TAG_member
	.dwattr $C$DW$705, DW_AT_type(*$C$DW$T$348)
	.dwattr $C$DW$705, DW_AT_name("mode")
	.dwattr $C$DW$705, DW_AT_TI_symbol_name("mode")
	.dwattr $C$DW$705, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$705, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$705, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$705, DW_AT_decl_line(0x63)
	.dwattr $C$DW$705, DW_AT_decl_column(0x1e)
$C$DW$706	.dwtag  DW_TAG_member
	.dwattr $C$DW$706, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$706, DW_AT_name("sp")
	.dwattr $C$DW$706, DW_AT_TI_symbol_name("sp")
	.dwattr $C$DW$706, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$706, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$706, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$706, DW_AT_decl_line(0x64)
	.dwattr $C$DW$706, DW_AT_decl_column(0x0d)
$C$DW$707	.dwtag  DW_TAG_member
	.dwattr $C$DW$707, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$707, DW_AT_name("used")
	.dwattr $C$DW$707, DW_AT_TI_symbol_name("used")
	.dwattr $C$DW$707, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$707, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$707, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$707, DW_AT_decl_line(0x65)
	.dwattr $C$DW$707, DW_AT_decl_column(0x0f)
	.dwendtag $C$DW$T$349

	.dwattr $C$DW$T$349, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$349, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$T$349, DW_AT_decl_column(0x08)
$C$DW$T$1348	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Stat")
	.dwattr $C$DW$T$1348, DW_AT_type(*$C$DW$T$349)
	.dwattr $C$DW$T$1348, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1348, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1348, DW_AT_decl_line(0x65)
	.dwattr $C$DW$T$1348, DW_AT_decl_column(0x29)

$C$DW$T$356	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$356, DW_AT_name("ti_sysbios_knl_Task_Struct")
	.dwattr $C$DW$T$356, DW_AT_byte_size(0x50)
$C$DW$708	.dwtag  DW_TAG_member
	.dwattr $C$DW$708, DW_AT_type(*$C$DW$T$249)
	.dwattr $C$DW$708, DW_AT_name("__f0")
	.dwattr $C$DW$708, DW_AT_TI_symbol_name("__f0")
	.dwattr $C$DW$708, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$708, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$708, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$708, DW_AT_decl_line(0x1cb)
	.dwattr $C$DW$708, DW_AT_decl_column(0x1f)
$C$DW$709	.dwtag  DW_TAG_member
	.dwattr $C$DW$709, DW_AT_type(*$C$DW$T$350)
	.dwattr $C$DW$709, DW_AT_name("__f1")
	.dwattr $C$DW$709, DW_AT_TI_symbol_name("__f1")
	.dwattr $C$DW$709, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$709, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$709, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$709, DW_AT_decl_line(0x1cc)
	.dwattr $C$DW$709, DW_AT_decl_column(0x16)
$C$DW$710	.dwtag  DW_TAG_member
	.dwattr $C$DW$710, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$710, DW_AT_name("__f2")
	.dwattr $C$DW$710, DW_AT_TI_symbol_name("__f2")
	.dwattr $C$DW$710, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$710, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$710, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$710, DW_AT_decl_line(0x1cd)
	.dwattr $C$DW$710, DW_AT_decl_column(0x0e)
$C$DW$711	.dwtag  DW_TAG_member
	.dwattr $C$DW$711, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$711, DW_AT_name("__f3")
	.dwattr $C$DW$711, DW_AT_TI_symbol_name("__f3")
	.dwattr $C$DW$711, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$711, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$711, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$711, DW_AT_decl_line(0x1ce)
	.dwattr $C$DW$711, DW_AT_decl_column(0x0d)
$C$DW$712	.dwtag  DW_TAG_member
	.dwattr $C$DW$712, DW_AT_type(*$C$DW$T$348)
	.dwattr $C$DW$712, DW_AT_name("__f4")
	.dwattr $C$DW$712, DW_AT_TI_symbol_name("__f4")
	.dwattr $C$DW$712, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$712, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$712, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$712, DW_AT_decl_line(0x1cf)
	.dwattr $C$DW$712, DW_AT_decl_column(0x1e)
$C$DW$713	.dwtag  DW_TAG_member
	.dwattr $C$DW$713, DW_AT_type(*$C$DW$T$351)
	.dwattr $C$DW$713, DW_AT_name("__f5")
	.dwattr $C$DW$713, DW_AT_TI_symbol_name("__f5")
	.dwattr $C$DW$713, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$713, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$713, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$713, DW_AT_decl_line(0x1d0)
	.dwattr $C$DW$713, DW_AT_decl_column(0x23)
$C$DW$714	.dwtag  DW_TAG_member
	.dwattr $C$DW$714, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$714, DW_AT_name("__f6")
	.dwattr $C$DW$714, DW_AT_TI_symbol_name("__f6")
	.dwattr $C$DW$714, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$714, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$714, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$714, DW_AT_decl_line(0x1d1)
	.dwattr $C$DW$714, DW_AT_decl_column(0x0f)
$C$DW$715	.dwtag  DW_TAG_member
	.dwattr $C$DW$715, DW_AT_type(*$C$DW$T$353)
	.dwattr $C$DW$715, DW_AT_name("__f7")
	.dwattr $C$DW$715, DW_AT_TI_symbol_name("__f7")
	.dwattr $C$DW$715, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$715, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$715, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$715, DW_AT_decl_line(0x1d2)
	.dwattr $C$DW$715, DW_AT_decl_column(0x34)
$C$DW$716	.dwtag  DW_TAG_member
	.dwattr $C$DW$716, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$716, DW_AT_name("__f8")
	.dwattr $C$DW$716, DW_AT_TI_symbol_name("__f8")
	.dwattr $C$DW$716, DW_AT_data_member_location[DW_OP_plus_uconst 0x24]
	.dwattr $C$DW$716, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$716, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$716, DW_AT_decl_line(0x1d3)
	.dwattr $C$DW$716, DW_AT_decl_column(0x1e)
$C$DW$717	.dwtag  DW_TAG_member
	.dwattr $C$DW$717, DW_AT_type(*$C$DW$T$328)
	.dwattr $C$DW$717, DW_AT_name("__f9")
	.dwattr $C$DW$717, DW_AT_TI_symbol_name("__f9")
	.dwattr $C$DW$717, DW_AT_data_member_location[DW_OP_plus_uconst 0x28]
	.dwattr $C$DW$717, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$717, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$717, DW_AT_decl_line(0x1d4)
	.dwattr $C$DW$717, DW_AT_decl_column(0x21)
$C$DW$718	.dwtag  DW_TAG_member
	.dwattr $C$DW$718, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$718, DW_AT_name("__f10")
	.dwattr $C$DW$718, DW_AT_TI_symbol_name("__f10")
	.dwattr $C$DW$718, DW_AT_data_member_location[DW_OP_plus_uconst 0x2c]
	.dwattr $C$DW$718, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$718, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$718, DW_AT_decl_line(0x1d5)
	.dwattr $C$DW$718, DW_AT_decl_column(0x0e)
$C$DW$719	.dwtag  DW_TAG_member
	.dwattr $C$DW$719, DW_AT_type(*$C$DW$T$203)
	.dwattr $C$DW$719, DW_AT_name("__f11")
	.dwattr $C$DW$719, DW_AT_TI_symbol_name("__f11")
	.dwattr $C$DW$719, DW_AT_data_member_location[DW_OP_plus_uconst 0x30]
	.dwattr $C$DW$719, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$719, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$719, DW_AT_decl_line(0x1d6)
	.dwattr $C$DW$719, DW_AT_decl_column(0x0e)
$C$DW$720	.dwtag  DW_TAG_member
	.dwattr $C$DW$720, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$720, DW_AT_name("__f12")
	.dwattr $C$DW$720, DW_AT_TI_symbol_name("__f12")
	.dwattr $C$DW$720, DW_AT_data_member_location[DW_OP_plus_uconst 0x34]
	.dwattr $C$DW$720, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$720, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$720, DW_AT_decl_line(0x1d7)
	.dwattr $C$DW$720, DW_AT_decl_column(0x0d)
$C$DW$721	.dwtag  DW_TAG_member
	.dwattr $C$DW$721, DW_AT_type(*$C$DW$T$355)
	.dwattr $C$DW$721, DW_AT_name("__f13")
	.dwattr $C$DW$721, DW_AT_TI_symbol_name("__f13")
	.dwattr $C$DW$721, DW_AT_data_member_location[DW_OP_plus_uconst 0x38]
	.dwattr $C$DW$721, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$721, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$721, DW_AT_decl_line(0x1d8)
	.dwattr $C$DW$721, DW_AT_decl_column(0x36)
$C$DW$722	.dwtag  DW_TAG_member
	.dwattr $C$DW$722, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$722, DW_AT_name("__f14")
	.dwattr $C$DW$722, DW_AT_TI_symbol_name("__f14")
	.dwattr $C$DW$722, DW_AT_data_member_location[DW_OP_plus_uconst 0x3c]
	.dwattr $C$DW$722, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$722, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$722, DW_AT_decl_line(0x1d9)
	.dwattr $C$DW$722, DW_AT_decl_column(0x0e)
$C$DW$723	.dwtag  DW_TAG_member
	.dwattr $C$DW$723, DW_AT_type(*$C$DW$T$324)
	.dwattr $C$DW$723, DW_AT_name("__f15")
	.dwattr $C$DW$723, DW_AT_TI_symbol_name("__f15")
	.dwattr $C$DW$723, DW_AT_data_member_location[DW_OP_plus_uconst 0x40]
	.dwattr $C$DW$723, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$723, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$723, DW_AT_decl_line(0x1da)
	.dwattr $C$DW$723, DW_AT_decl_column(0x21)
$C$DW$724	.dwtag  DW_TAG_member
	.dwattr $C$DW$724, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$724, DW_AT_name("__f16")
	.dwattr $C$DW$724, DW_AT_TI_symbol_name("__f16")
	.dwattr $C$DW$724, DW_AT_data_member_location[DW_OP_plus_uconst 0x44]
	.dwattr $C$DW$724, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$724, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$724, DW_AT_decl_line(0x1db)
	.dwattr $C$DW$724, DW_AT_decl_column(0x0e)
$C$DW$725	.dwtag  DW_TAG_member
	.dwattr $C$DW$725, DW_AT_type(*$C$DW$T$196)
	.dwattr $C$DW$725, DW_AT_name("__f17")
	.dwattr $C$DW$725, DW_AT_TI_symbol_name("__f17")
	.dwattr $C$DW$725, DW_AT_data_member_location[DW_OP_plus_uconst 0x48]
	.dwattr $C$DW$725, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$725, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$725, DW_AT_decl_line(0x1dc)
	.dwattr $C$DW$725, DW_AT_decl_column(0x0e)
$C$DW$726	.dwtag  DW_TAG_member
	.dwattr $C$DW$726, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$726, DW_AT_name("__name")
	.dwattr $C$DW$726, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$726, DW_AT_data_member_location[DW_OP_plus_uconst 0x4c]
	.dwattr $C$DW$726, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$726, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$726, DW_AT_decl_line(0x1dd)
	.dwattr $C$DW$726, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$356

	.dwattr $C$DW$T$356, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$356, DW_AT_decl_line(0x1ca)
	.dwattr $C$DW$T$356, DW_AT_decl_column(0x08)
$C$DW$T$1349	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_Struct")
	.dwattr $C$DW$T$1349, DW_AT_type(*$C$DW$T$356)
	.dwattr $C$DW$T$1349, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1349, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1349, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$T$1349, DW_AT_decl_column(0x2b)

$C$DW$T$357	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$357, DW_AT_name("ti_sysbios_knl_Task_SupportProxy_Fxns__")
	.dwattr $C$DW$T$357, DW_AT_byte_size(0x30)
$C$DW$727	.dwtag  DW_TAG_member
	.dwattr $C$DW$727, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$727, DW_AT_name("__base")
	.dwattr $C$DW$727, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$727, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$727, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$727, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$727, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$727, DW_AT_decl_column(0x1d)
$C$DW$728	.dwtag  DW_TAG_member
	.dwattr $C$DW$728, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$728, DW_AT_name("__sysp")
	.dwattr $C$DW$728, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$728, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$728, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$728, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$728, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$728, DW_AT_decl_column(0x27)
$C$DW$729	.dwtag  DW_TAG_member
	.dwattr $C$DW$729, DW_AT_type(*$C$DW$T$184)
	.dwattr $C$DW$729, DW_AT_name("start")
	.dwattr $C$DW$729, DW_AT_TI_symbol_name("start")
	.dwattr $C$DW$729, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$729, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$729, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$729, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$729, DW_AT_decl_column(0x0f)
$C$DW$730	.dwtag  DW_TAG_member
	.dwattr $C$DW$730, DW_AT_type(*$C$DW$T$187)
	.dwattr $C$DW$730, DW_AT_name("swap")
	.dwattr $C$DW$730, DW_AT_TI_symbol_name("swap")
	.dwattr $C$DW$730, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$730, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$730, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$730, DW_AT_decl_line(0xab)
	.dwattr $C$DW$730, DW_AT_decl_column(0x10)
$C$DW$731	.dwtag  DW_TAG_member
	.dwattr $C$DW$731, DW_AT_type(*$C$DW$T$193)
	.dwattr $C$DW$731, DW_AT_name("checkStack")
	.dwattr $C$DW$731, DW_AT_TI_symbol_name("checkStack")
	.dwattr $C$DW$731, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$731, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$731, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$731, DW_AT_decl_line(0xac)
	.dwattr $C$DW$731, DW_AT_decl_column(0x10)
$C$DW$732	.dwtag  DW_TAG_member
	.dwattr $C$DW$732, DW_AT_type(*$C$DW$T$195)
	.dwattr $C$DW$732, DW_AT_name("stackUsed")
	.dwattr $C$DW$732, DW_AT_TI_symbol_name("stackUsed")
	.dwattr $C$DW$732, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$732, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$732, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$732, DW_AT_decl_line(0xad)
	.dwattr $C$DW$732, DW_AT_decl_column(0x11)
$C$DW$733	.dwtag  DW_TAG_member
	.dwattr $C$DW$733, DW_AT_type(*$C$DW$T$198)
	.dwattr $C$DW$733, DW_AT_name("getStackAlignment")
	.dwattr $C$DW$733, DW_AT_TI_symbol_name("getStackAlignment")
	.dwattr $C$DW$733, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$733, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$733, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$733, DW_AT_decl_line(0xae)
	.dwattr $C$DW$733, DW_AT_decl_column(0x10)
$C$DW$734	.dwtag  DW_TAG_member
	.dwattr $C$DW$734, DW_AT_type(*$C$DW$T$200)
	.dwattr $C$DW$734, DW_AT_name("getDefaultStackSize")
	.dwattr $C$DW$734, DW_AT_TI_symbol_name("getDefaultStackSize")
	.dwattr $C$DW$734, DW_AT_data_member_location[DW_OP_plus_uconst 0x1c]
	.dwattr $C$DW$734, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$734, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$734, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$734, DW_AT_decl_column(0x11)
$C$DW$735	.dwtag  DW_TAG_member
	.dwattr $C$DW$735, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$735, DW_AT_name("__sfxns")
	.dwattr $C$DW$735, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$735, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$735, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$735, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$735, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$735, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$357

	.dwattr $C$DW$T$357, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$357, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$357, DW_AT_decl_column(0x08)
$C$DW$T$1350	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_SupportProxy_Fxns__")
	.dwattr $C$DW$T$1350, DW_AT_type(*$C$DW$T$357)
	.dwattr $C$DW$T$1350, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1350, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1350, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1350, DW_AT_decl_column(0x38)
$C$DW$T$1351	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1351, DW_AT_type(*$C$DW$T$1350)
$C$DW$T$1352	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1352, DW_AT_type(*$C$DW$T$1351)
	.dwattr $C$DW$T$1352, DW_AT_address_class(0x20)
$C$DW$T$1353	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_knl_Task_SupportProxy_Module")
	.dwattr $C$DW$T$1353, DW_AT_type(*$C$DW$T$1352)
	.dwattr $C$DW$T$1353, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1353, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/package.defs.h")
	.dwattr $C$DW$T$1353, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$1353, DW_AT_decl_column(0x38)

$C$DW$T$54	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$54, DW_AT_name("xdc_runtime_Core_ObjDesc")
	.dwattr $C$DW$T$54, DW_AT_declaration
	.dwendtag $C$DW$T$54

	.dwattr $C$DW$T$54, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$54, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$T$54, DW_AT_decl_column(0x10)
$C$DW$T$1354	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Core_ObjDesc")
	.dwattr $C$DW$T$1354, DW_AT_type(*$C$DW$T$54)
	.dwattr $C$DW$T$1354, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1354, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1354, DW_AT_decl_line(0x1c)
	.dwattr $C$DW$T$1354, DW_AT_decl_column(0x29)

$C$DW$T$363	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$363, DW_AT_name("xdc_runtime_Diags_DictElem")
	.dwattr $C$DW$T$363, DW_AT_byte_size(0x08)
$C$DW$736	.dwtag  DW_TAG_member
	.dwattr $C$DW$736, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$736, DW_AT_name("modId")
	.dwattr $C$DW$736, DW_AT_TI_symbol_name("modId")
	.dwattr $C$DW$736, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$736, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$736, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$736, DW_AT_decl_line(0x99)
	.dwattr $C$DW$736, DW_AT_decl_column(0x20)
$C$DW$737	.dwtag  DW_TAG_member
	.dwattr $C$DW$737, DW_AT_type(*$C$DW$T$362)
	.dwattr $C$DW$737, DW_AT_name("maskAddr")
	.dwattr $C$DW$737, DW_AT_TI_symbol_name("maskAddr")
	.dwattr $C$DW$737, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$737, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$737, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$737, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$737, DW_AT_decl_column(0x1d)
	.dwendtag $C$DW$T$363

	.dwattr $C$DW$T$363, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$363, DW_AT_decl_line(0x98)
	.dwattr $C$DW$T$363, DW_AT_decl_column(0x08)
$C$DW$T$1355	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Diags_DictElem")
	.dwattr $C$DW$T$1355, DW_AT_type(*$C$DW$T$363)
	.dwattr $C$DW$T$1355, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1355, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1355, DW_AT_decl_line(0x27)
	.dwattr $C$DW$T$1355, DW_AT_decl_column(0x2b)
$C$DW$T$1356	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1356, DW_AT_type(*$C$DW$T$1355)
	.dwattr $C$DW$T$1356, DW_AT_address_class(0x20)
$C$DW$T$1357	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_dictBase")
	.dwattr $C$DW$T$1357, DW_AT_type(*$C$DW$T$1356)
	.dwattr $C$DW$T$1357, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1357, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1357, DW_AT_decl_line(0xf5)
	.dwattr $C$DW$T$1357, DW_AT_decl_column(0x25)

$C$DW$T$1358	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1358, DW_AT_name("xdc_runtime_Diags_EventLevel")
	.dwattr $C$DW$T$1358, DW_AT_byte_size(0x01)
$C$DW$738	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Diags_LEVEL1"), DW_AT_const_value(0x00)
	.dwattr $C$DW$738, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$738, DW_AT_decl_line(0x7f)
	.dwattr $C$DW$738, DW_AT_decl_column(0x05)
$C$DW$739	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Diags_LEVEL2"), DW_AT_const_value(0x20)
	.dwattr $C$DW$739, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$739, DW_AT_decl_line(0x80)
	.dwattr $C$DW$739, DW_AT_decl_column(0x05)
$C$DW$740	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Diags_LEVEL3"), DW_AT_const_value(0x40)
	.dwattr $C$DW$740, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$740, DW_AT_decl_line(0x81)
	.dwattr $C$DW$740, DW_AT_decl_column(0x05)
$C$DW$741	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Diags_LEVEL4"), DW_AT_const_value(0x60)
	.dwattr $C$DW$741, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$741, DW_AT_decl_line(0x82)
	.dwattr $C$DW$741, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1358

	.dwattr $C$DW$T$1358, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1358, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$1358, DW_AT_decl_column(0x06)
$C$DW$T$1359	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Diags_EventLevel")
	.dwattr $C$DW$T$1359, DW_AT_type(*$C$DW$T$1358)
	.dwattr $C$DW$T$1359, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1359, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1359, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1359, DW_AT_decl_column(0x2b)

$C$DW$T$372	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$372, DW_AT_name("xdc_runtime_Error_Block")
	.dwattr $C$DW$T$372, DW_AT_byte_size(0x30)
$C$DW$742	.dwtag  DW_TAG_member
	.dwattr $C$DW$742, DW_AT_type(*$C$DW$T$304)
	.dwattr $C$DW$742, DW_AT_name("unused")
	.dwattr $C$DW$742, DW_AT_TI_symbol_name("unused")
	.dwattr $C$DW$742, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$742, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$742, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$742, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$742, DW_AT_decl_column(0x10)
$C$DW$743	.dwtag  DW_TAG_member
	.dwattr $C$DW$743, DW_AT_type(*$C$DW$T$364)
	.dwattr $C$DW$743, DW_AT_name("data")
	.dwattr $C$DW$743, DW_AT_TI_symbol_name("data")
	.dwattr $C$DW$743, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$743, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$743, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$743, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$743, DW_AT_decl_column(0x1c)
$C$DW$744	.dwtag  DW_TAG_member
	.dwattr $C$DW$744, DW_AT_type(*$C$DW$T$365)
	.dwattr $C$DW$744, DW_AT_name("id")
	.dwattr $C$DW$744, DW_AT_TI_symbol_name("id")
	.dwattr $C$DW$744, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$744, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$744, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$744, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$744, DW_AT_decl_column(0x1a)
$C$DW$745	.dwtag  DW_TAG_member
	.dwattr $C$DW$745, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$745, DW_AT_name("msg")
	.dwattr $C$DW$745, DW_AT_TI_symbol_name("msg")
	.dwattr $C$DW$745, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$745, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$745, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$745, DW_AT_decl_line(0x60)
	.dwattr $C$DW$745, DW_AT_decl_column(0x10)
$C$DW$746	.dwtag  DW_TAG_member
	.dwattr $C$DW$746, DW_AT_type(*$C$DW$T$368)
	.dwattr $C$DW$746, DW_AT_name("site")
	.dwattr $C$DW$746, DW_AT_TI_symbol_name("site")
	.dwattr $C$DW$746, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$746, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$746, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$746, DW_AT_decl_line(0x61)
	.dwattr $C$DW$746, DW_AT_decl_column(0x1c)
$C$DW$747	.dwtag  DW_TAG_member
	.dwattr $C$DW$747, DW_AT_type(*$C$DW$T$371)
	.dwattr $C$DW$747, DW_AT_name("xtra")
	.dwattr $C$DW$747, DW_AT_TI_symbol_name("xtra")
	.dwattr $C$DW$747, DW_AT_data_member_location[DW_OP_plus_uconst 0x20]
	.dwattr $C$DW$747, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$747, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$747, DW_AT_decl_line(0x62)
	.dwattr $C$DW$747, DW_AT_decl_column(0x28)
	.dwendtag $C$DW$T$372

	.dwattr $C$DW$T$372, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$372, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$T$372, DW_AT_decl_column(0x08)
$C$DW$T$181	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_Block")
	.dwattr $C$DW$T$181, DW_AT_type(*$C$DW$T$372)
	.dwattr $C$DW$T$181, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$181, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$181, DW_AT_decl_line(0x2e)
	.dwattr $C$DW$T$181, DW_AT_decl_column(0x28)
$C$DW$T$182	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$182, DW_AT_type(*$C$DW$T$181)
	.dwattr $C$DW$T$182, DW_AT_address_class(0x20)

$C$DW$T$376	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$376, DW_AT_name("xdc_runtime_Error_Data")
	.dwattr $C$DW$T$376, DW_AT_byte_size(0x08)
$C$DW$748	.dwtag  DW_TAG_member
	.dwattr $C$DW$748, DW_AT_type(*$C$DW$T$375)
	.dwattr $C$DW$748, DW_AT_name("arg")
	.dwattr $C$DW$748, DW_AT_TI_symbol_name("arg")
	.dwattr $C$DW$748, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$748, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$748, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$748, DW_AT_decl_line(0x55)
	.dwattr $C$DW$748, DW_AT_decl_column(0x26)
	.dwendtag $C$DW$T$376

	.dwattr $C$DW$T$376, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$376, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$376, DW_AT_decl_column(0x08)
$C$DW$T$364	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_Data")
	.dwattr $C$DW$T$364, DW_AT_type(*$C$DW$T$376)
	.dwattr $C$DW$T$364, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$364, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$364, DW_AT_decl_line(0x2d)
	.dwattr $C$DW$T$364, DW_AT_decl_column(0x27)

$C$DW$T$55	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$55, DW_AT_name("xdc_runtime_Error_Module_State")
	.dwattr $C$DW$T$55, DW_AT_declaration
	.dwendtag $C$DW$T$55

	.dwattr $C$DW$T$55, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$55, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$T$55, DW_AT_decl_column(0x10)
$C$DW$T$1360	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_Module_State")
	.dwattr $C$DW$T$1360, DW_AT_type(*$C$DW$T$55)
	.dwattr $C$DW$T$1360, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1360, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1360, DW_AT_decl_line(0x2f)
	.dwattr $C$DW$T$1360, DW_AT_decl_column(0x2f)

$C$DW$T$1361	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1361, DW_AT_name("xdc_runtime_Error_Policy")
	.dwattr $C$DW$T$1361, DW_AT_byte_size(0x01)
$C$DW$749	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Error_TERMINATE"), DW_AT_const_value(0x00)
	.dwattr $C$DW$749, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$749, DW_AT_decl_line(0x43)
	.dwattr $C$DW$749, DW_AT_decl_column(0x05)
$C$DW$750	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Error_UNWIND"), DW_AT_const_value(0x01)
	.dwattr $C$DW$750, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$750, DW_AT_decl_line(0x44)
	.dwattr $C$DW$750, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1361

	.dwattr $C$DW$T$1361, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1361, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$1361, DW_AT_decl_column(0x06)
$C$DW$T$1362	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Error_Policy")
	.dwattr $C$DW$T$1362, DW_AT_type(*$C$DW$T$1361)
	.dwattr $C$DW$T$1362, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1362, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1362, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$1362, DW_AT_decl_column(0x27)
$C$DW$T$1363	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_policy")
	.dwattr $C$DW$T$1363, DW_AT_type(*$C$DW$T$1362)
	.dwattr $C$DW$T$1363, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1363, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1363, DW_AT_decl_line(0xd0)
	.dwattr $C$DW$T$1363, DW_AT_decl_column(0x22)

$C$DW$T$56	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$56, DW_AT_name("xdc_runtime_GateNull_Fxns__")
	.dwattr $C$DW$T$56, DW_AT_declaration
	.dwendtag $C$DW$T$56

	.dwattr $C$DW$T$56, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$56, DW_AT_decl_line(0x43)
	.dwattr $C$DW$T$56, DW_AT_decl_column(0x10)
$C$DW$T$1364	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Fxns__")
	.dwattr $C$DW$T$1364, DW_AT_type(*$C$DW$T$56)
	.dwattr $C$DW$T$1364, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1364, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1364, DW_AT_decl_line(0x43)
	.dwattr $C$DW$T$1364, DW_AT_decl_column(0x2c)
$C$DW$T$1365	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1365, DW_AT_type(*$C$DW$T$1364)
$C$DW$T$1366	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1366, DW_AT_type(*$C$DW$T$1365)
	.dwattr $C$DW$T$1366, DW_AT_address_class(0x20)
$C$DW$T$1367	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Module")
	.dwattr $C$DW$T$1367, DW_AT_type(*$C$DW$T$1366)
	.dwattr $C$DW$T$1367, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1367, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1367, DW_AT_decl_line(0x44)
	.dwattr $C$DW$T$1367, DW_AT_decl_column(0x2c)

$C$DW$T$57	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$57, DW_AT_name("xdc_runtime_GateNull_Object")
	.dwattr $C$DW$T$57, DW_AT_declaration
	.dwendtag $C$DW$T$57

	.dwattr $C$DW$T$57, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$57, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$57, DW_AT_decl_column(0x10)
$C$DW$T$1368	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Object")
	.dwattr $C$DW$T$1368, DW_AT_type(*$C$DW$T$57)
	.dwattr $C$DW$T$1368, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1368, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1368, DW_AT_decl_line(0x46)
	.dwattr $C$DW$T$1368, DW_AT_decl_column(0x2c)
$C$DW$T$1369	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1369, DW_AT_type(*$C$DW$T$1368)
	.dwattr $C$DW$T$1369, DW_AT_address_class(0x20)
$C$DW$T$1370	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Handle")
	.dwattr $C$DW$T$1370, DW_AT_type(*$C$DW$T$1369)
	.dwattr $C$DW$T$1370, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1370, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1370, DW_AT_decl_line(0x48)
	.dwattr $C$DW$T$1370, DW_AT_decl_column(0x26)
$C$DW$T$1371	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Instance")
	.dwattr $C$DW$T$1371, DW_AT_type(*$C$DW$T$1369)
	.dwattr $C$DW$T$1371, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1371, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1371, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$T$1371, DW_AT_decl_column(0x26)

$C$DW$T$58	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$58, DW_AT_name("xdc_runtime_GateNull_Object__")
	.dwattr $C$DW$T$58, DW_AT_declaration
	.dwendtag $C$DW$T$58

	.dwattr $C$DW$T$58, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$58, DW_AT_decl_line(0x49)
	.dwattr $C$DW$T$58, DW_AT_decl_column(0x10)
$C$DW$T$1372	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Instance_State")
	.dwattr $C$DW$T$1372, DW_AT_type(*$C$DW$T$58)
	.dwattr $C$DW$T$1372, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1372, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1372, DW_AT_decl_line(0x49)
	.dwattr $C$DW$T$1372, DW_AT_decl_column(0x2e)

$C$DW$T$59	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$59, DW_AT_name("xdc_runtime_GateNull_Params")
	.dwattr $C$DW$T$59, DW_AT_declaration
	.dwendtag $C$DW$T$59

	.dwattr $C$DW$T$59, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$59, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$59, DW_AT_decl_column(0x10)
$C$DW$T$1373	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Params")
	.dwattr $C$DW$T$1373, DW_AT_type(*$C$DW$T$59)
	.dwattr $C$DW$T$1373, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1373, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1373, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$1373, DW_AT_decl_column(0x2c)

$C$DW$T$60	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$60, DW_AT_name("xdc_runtime_GateNull_Struct")
	.dwattr $C$DW$T$60, DW_AT_declaration
	.dwendtag $C$DW$T$60

	.dwattr $C$DW$T$60, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$60, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$60, DW_AT_decl_column(0x10)
$C$DW$T$1374	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_GateNull_Struct")
	.dwattr $C$DW$T$1374, DW_AT_type(*$C$DW$T$60)
	.dwattr $C$DW$T$1374, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1374, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1374, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$1374, DW_AT_decl_column(0x2c)

$C$DW$T$61	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$61, DW_AT_name("xdc_runtime_HeapMin_Fxns__")
	.dwattr $C$DW$T$61, DW_AT_declaration
	.dwendtag $C$DW$T$61

	.dwattr $C$DW$T$61, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$61, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$61, DW_AT_decl_column(0x10)
$C$DW$T$1375	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Fxns__")
	.dwattr $C$DW$T$1375, DW_AT_type(*$C$DW$T$61)
	.dwattr $C$DW$T$1375, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1375, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1375, DW_AT_decl_line(0xa6)
	.dwattr $C$DW$T$1375, DW_AT_decl_column(0x2b)
$C$DW$T$1376	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1376, DW_AT_type(*$C$DW$T$1375)
$C$DW$T$1377	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1377, DW_AT_type(*$C$DW$T$1376)
	.dwattr $C$DW$T$1377, DW_AT_address_class(0x20)
$C$DW$T$1378	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Module")
	.dwattr $C$DW$T$1378, DW_AT_type(*$C$DW$T$1377)
	.dwattr $C$DW$T$1378, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1378, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1378, DW_AT_decl_line(0xa7)
	.dwattr $C$DW$T$1378, DW_AT_decl_column(0x2b)

$C$DW$T$62	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$62, DW_AT_name("xdc_runtime_HeapMin_Object")
	.dwattr $C$DW$T$62, DW_AT_declaration
	.dwendtag $C$DW$T$62

	.dwattr $C$DW$T$62, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$62, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$62, DW_AT_decl_column(0x10)
$C$DW$T$1379	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Object")
	.dwattr $C$DW$T$1379, DW_AT_type(*$C$DW$T$62)
	.dwattr $C$DW$T$1379, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1379, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1379, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$1379, DW_AT_decl_column(0x2b)
$C$DW$T$1380	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1380, DW_AT_type(*$C$DW$T$1379)
	.dwattr $C$DW$T$1380, DW_AT_address_class(0x20)
$C$DW$T$1381	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Handle")
	.dwattr $C$DW$T$1381, DW_AT_type(*$C$DW$T$1380)
	.dwattr $C$DW$T$1381, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1381, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1381, DW_AT_decl_line(0xab)
	.dwattr $C$DW$T$1381, DW_AT_decl_column(0x25)
$C$DW$T$1382	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Instance")
	.dwattr $C$DW$T$1382, DW_AT_type(*$C$DW$T$1380)
	.dwattr $C$DW$T$1382, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1382, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1382, DW_AT_decl_line(0xad)
	.dwattr $C$DW$T$1382, DW_AT_decl_column(0x25)

$C$DW$T$63	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$63, DW_AT_name("xdc_runtime_HeapMin_Object__")
	.dwattr $C$DW$T$63, DW_AT_declaration
	.dwendtag $C$DW$T$63

	.dwattr $C$DW$T$63, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$63, DW_AT_decl_line(0xac)
	.dwattr $C$DW$T$63, DW_AT_decl_column(0x10)
$C$DW$T$1383	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Instance_State")
	.dwattr $C$DW$T$1383, DW_AT_type(*$C$DW$T$63)
	.dwattr $C$DW$T$1383, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1383, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1383, DW_AT_decl_line(0xac)
	.dwattr $C$DW$T$1383, DW_AT_decl_column(0x2d)

$C$DW$T$64	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$64, DW_AT_name("xdc_runtime_HeapMin_Params")
	.dwattr $C$DW$T$64, DW_AT_declaration
	.dwendtag $C$DW$T$64

	.dwattr $C$DW$T$64, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$64, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$64, DW_AT_decl_column(0x10)
$C$DW$T$1384	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Params")
	.dwattr $C$DW$T$1384, DW_AT_type(*$C$DW$T$64)
	.dwattr $C$DW$T$1384, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1384, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1384, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$1384, DW_AT_decl_column(0x2b)

$C$DW$T$65	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$65, DW_AT_name("xdc_runtime_HeapMin_Struct")
	.dwattr $C$DW$T$65, DW_AT_declaration
	.dwendtag $C$DW$T$65

	.dwattr $C$DW$T$65, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$65, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$T$65, DW_AT_decl_column(0x10)
$C$DW$T$1385	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapMin_Struct")
	.dwattr $C$DW$T$1385, DW_AT_type(*$C$DW$T$65)
	.dwattr $C$DW$T$1385, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1385, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1385, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$T$1385, DW_AT_decl_column(0x2b)

$C$DW$T$66	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$66, DW_AT_name("xdc_runtime_HeapStd_Fxns__")
	.dwattr $C$DW$T$66, DW_AT_declaration
	.dwendtag $C$DW$T$66

	.dwattr $C$DW$T$66, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$66, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$T$66, DW_AT_decl_column(0x10)
$C$DW$T$1386	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Fxns__")
	.dwattr $C$DW$T$1386, DW_AT_type(*$C$DW$T$66)
	.dwattr $C$DW$T$1386, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1386, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1386, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$T$1386, DW_AT_decl_column(0x2b)
$C$DW$T$1387	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1387, DW_AT_type(*$C$DW$T$1386)
$C$DW$T$1388	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1388, DW_AT_type(*$C$DW$T$1387)
	.dwattr $C$DW$T$1388, DW_AT_address_class(0x20)
$C$DW$T$1389	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Module")
	.dwattr $C$DW$T$1389, DW_AT_type(*$C$DW$T$1388)
	.dwattr $C$DW$T$1389, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1389, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1389, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$T$1389, DW_AT_decl_column(0x2b)

$C$DW$T$67	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$67, DW_AT_name("xdc_runtime_HeapStd_Module_State")
	.dwattr $C$DW$T$67, DW_AT_declaration
	.dwendtag $C$DW$T$67

	.dwattr $C$DW$T$67, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$67, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$T$67, DW_AT_decl_column(0x10)
$C$DW$T$1390	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Module_State")
	.dwattr $C$DW$T$1390, DW_AT_type(*$C$DW$T$67)
	.dwattr $C$DW$T$1390, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1390, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1390, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$T$1390, DW_AT_decl_column(0x31)

$C$DW$T$68	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$68, DW_AT_name("xdc_runtime_HeapStd_Object")
	.dwattr $C$DW$T$68, DW_AT_declaration
	.dwendtag $C$DW$T$68

	.dwattr $C$DW$T$68, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$68, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$68, DW_AT_decl_column(0x10)
$C$DW$T$1391	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Object")
	.dwattr $C$DW$T$1391, DW_AT_type(*$C$DW$T$68)
	.dwattr $C$DW$T$1391, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1391, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1391, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$T$1391, DW_AT_decl_column(0x2b)
$C$DW$T$1392	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1392, DW_AT_type(*$C$DW$T$1391)
	.dwattr $C$DW$T$1392, DW_AT_address_class(0x20)
$C$DW$T$1393	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Handle")
	.dwattr $C$DW$T$1393, DW_AT_type(*$C$DW$T$1392)
	.dwattr $C$DW$T$1393, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1393, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1393, DW_AT_decl_line(0xb9)
	.dwattr $C$DW$T$1393, DW_AT_decl_column(0x25)
$C$DW$T$1394	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Instance")
	.dwattr $C$DW$T$1394, DW_AT_type(*$C$DW$T$1392)
	.dwattr $C$DW$T$1394, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1394, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1394, DW_AT_decl_line(0xbb)
	.dwattr $C$DW$T$1394, DW_AT_decl_column(0x25)

$C$DW$T$69	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$69, DW_AT_name("xdc_runtime_HeapStd_Object__")
	.dwattr $C$DW$T$69, DW_AT_declaration
	.dwendtag $C$DW$T$69

	.dwattr $C$DW$T$69, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$69, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$69, DW_AT_decl_column(0x10)
$C$DW$T$1395	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Instance_State")
	.dwattr $C$DW$T$1395, DW_AT_type(*$C$DW$T$69)
	.dwattr $C$DW$T$1395, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1395, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1395, DW_AT_decl_line(0xba)
	.dwattr $C$DW$T$1395, DW_AT_decl_column(0x2d)

$C$DW$T$70	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$70, DW_AT_name("xdc_runtime_HeapStd_Params")
	.dwattr $C$DW$T$70, DW_AT_declaration
	.dwendtag $C$DW$T$70

	.dwattr $C$DW$T$70, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$70, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$T$70, DW_AT_decl_column(0x10)
$C$DW$T$1396	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Params")
	.dwattr $C$DW$T$1396, DW_AT_type(*$C$DW$T$70)
	.dwattr $C$DW$T$1396, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1396, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1396, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$T$1396, DW_AT_decl_column(0x2b)

$C$DW$T$71	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$71, DW_AT_name("xdc_runtime_HeapStd_Struct")
	.dwattr $C$DW$T$71, DW_AT_declaration
	.dwendtag $C$DW$T$71

	.dwattr $C$DW$T$71, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$71, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$T$71, DW_AT_decl_column(0x10)
$C$DW$T$1397	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_HeapStd_Struct")
	.dwattr $C$DW$T$1397, DW_AT_type(*$C$DW$T$71)
	.dwattr $C$DW$T$1397, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1397, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1397, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$T$1397, DW_AT_decl_column(0x2b)

$C$DW$T$72	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$72, DW_AT_name("xdc_runtime_IFilterLogger_Fxns__")
	.dwattr $C$DW$T$72, DW_AT_declaration
	.dwendtag $C$DW$T$72

	.dwattr $C$DW$T$72, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$72, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$T$72, DW_AT_decl_column(0x10)
$C$DW$T$377	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IFilterLogger_Fxns__")
	.dwattr $C$DW$T$377, DW_AT_type(*$C$DW$T$72)
	.dwattr $C$DW$T$377, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$377, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$377, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$T$377, DW_AT_decl_column(0x31)
$C$DW$T$378	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$378, DW_AT_type(*$C$DW$T$377)
	.dwattr $C$DW$T$378, DW_AT_address_class(0x20)
$C$DW$T$1398	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1398, DW_AT_type(*$C$DW$T$377)
$C$DW$T$1399	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1399, DW_AT_type(*$C$DW$T$1398)
	.dwattr $C$DW$T$1399, DW_AT_address_class(0x20)
$C$DW$T$1400	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IFilterLogger_Module")
	.dwattr $C$DW$T$1400, DW_AT_type(*$C$DW$T$1399)
	.dwattr $C$DW$T$1400, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1400, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1400, DW_AT_decl_line(0x60)
	.dwattr $C$DW$T$1400, DW_AT_decl_column(0x31)

$C$DW$T$73	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$73, DW_AT_name("xdc_runtime_IFilterLogger_Params")
	.dwattr $C$DW$T$73, DW_AT_declaration
	.dwendtag $C$DW$T$73

	.dwattr $C$DW$T$73, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$73, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$73, DW_AT_decl_column(0x10)
$C$DW$T$1401	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IFilterLogger_Params")
	.dwattr $C$DW$T$1401, DW_AT_type(*$C$DW$T$73)
	.dwattr $C$DW$T$1401, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1401, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1401, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$1401, DW_AT_decl_column(0x31)

$C$DW$T$379	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$379, DW_AT_name("xdc_runtime_IFilterLogger___Object")
	.dwattr $C$DW$T$379, DW_AT_byte_size(0x08)
$C$DW$751	.dwtag  DW_TAG_member
	.dwattr $C$DW$751, DW_AT_type(*$C$DW$T$378)
	.dwattr $C$DW$751, DW_AT_name("__fxns")
	.dwattr $C$DW$751, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$751, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$751, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$751, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$751, DW_AT_decl_line(0x62)
	.dwattr $C$DW$751, DW_AT_decl_column(0x57)
$C$DW$752	.dwtag  DW_TAG_member
	.dwattr $C$DW$752, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$752, DW_AT_name("__label")
	.dwattr $C$DW$752, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$752, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$752, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$752, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$752, DW_AT_decl_line(0x62)
	.dwattr $C$DW$752, DW_AT_decl_column(0x6a)
	.dwendtag $C$DW$T$379

	.dwattr $C$DW$T$379, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$379, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$379, DW_AT_decl_column(0x10)
$C$DW$T$1402	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1402, DW_AT_type(*$C$DW$T$379)
	.dwattr $C$DW$T$1402, DW_AT_address_class(0x20)
$C$DW$T$1403	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IFilterLogger_Handle")
	.dwattr $C$DW$T$1403, DW_AT_type(*$C$DW$T$1402)
	.dwattr $C$DW$T$1403, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1403, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1403, DW_AT_decl_line(0x62)
	.dwattr $C$DW$T$1403, DW_AT_decl_column(0x76)

$C$DW$T$384	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$384, DW_AT_name("xdc_runtime_IGateProvider_Fxns__")
	.dwattr $C$DW$T$384, DW_AT_byte_size(0x24)
$C$DW$753	.dwtag  DW_TAG_member
	.dwattr $C$DW$753, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$753, DW_AT_name("__base")
	.dwattr $C$DW$753, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$753, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$753, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$753, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$753, DW_AT_decl_line(0x59)
	.dwattr $C$DW$753, DW_AT_decl_column(0x1d)
$C$DW$754	.dwtag  DW_TAG_member
	.dwattr $C$DW$754, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$754, DW_AT_name("__sysp")
	.dwattr $C$DW$754, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$754, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$754, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$754, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$754, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$754, DW_AT_decl_column(0x27)
$C$DW$755	.dwtag  DW_TAG_member
	.dwattr $C$DW$755, DW_AT_type(*$C$DW$T$150)
	.dwattr $C$DW$755, DW_AT_name("query")
	.dwattr $C$DW$755, DW_AT_TI_symbol_name("query")
	.dwattr $C$DW$755, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$755, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$755, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$755, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$755, DW_AT_decl_column(0x10)
$C$DW$756	.dwtag  DW_TAG_member
	.dwattr $C$DW$756, DW_AT_type(*$C$DW$T$381)
	.dwattr $C$DW$756, DW_AT_name("enter")
	.dwattr $C$DW$756, DW_AT_TI_symbol_name("enter")
	.dwattr $C$DW$756, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$756, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$756, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$756, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$756, DW_AT_decl_column(0x10)
$C$DW$757	.dwtag  DW_TAG_member
	.dwattr $C$DW$757, DW_AT_type(*$C$DW$T$383)
	.dwattr $C$DW$757, DW_AT_name("leave")
	.dwattr $C$DW$757, DW_AT_TI_symbol_name("leave")
	.dwattr $C$DW$757, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$757, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$757, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$757, DW_AT_decl_line(0x5d)
	.dwattr $C$DW$757, DW_AT_decl_column(0x10)
$C$DW$758	.dwtag  DW_TAG_member
	.dwattr $C$DW$758, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$758, DW_AT_name("__sfxns")
	.dwattr $C$DW$758, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$758, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$758, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$758, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$758, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$758, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$384

	.dwattr $C$DW$T$384, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$T$384, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$384, DW_AT_decl_column(0x08)
$C$DW$T$386	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_Fxns__")
	.dwattr $C$DW$T$386, DW_AT_type(*$C$DW$T$384)
	.dwattr $C$DW$T$386, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$386, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$386, DW_AT_decl_line(0x3a)
	.dwattr $C$DW$T$386, DW_AT_decl_column(0x31)
$C$DW$T$387	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$387, DW_AT_type(*$C$DW$T$386)
	.dwattr $C$DW$T$387, DW_AT_address_class(0x20)
$C$DW$T$1404	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1404, DW_AT_type(*$C$DW$T$386)
$C$DW$T$1405	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1405, DW_AT_type(*$C$DW$T$1404)
	.dwattr $C$DW$T$1405, DW_AT_address_class(0x20)
$C$DW$T$1406	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_Module")
	.dwattr $C$DW$T$1406, DW_AT_type(*$C$DW$T$1405)
	.dwattr $C$DW$T$1406, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1406, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1406, DW_AT_decl_line(0x3b)
	.dwattr $C$DW$T$1406, DW_AT_decl_column(0x31)

$C$DW$T$385	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$385, DW_AT_name("xdc_runtime_IGateProvider_Params")
	.dwattr $C$DW$T$385, DW_AT_byte_size(0x10)
$C$DW$759	.dwtag  DW_TAG_member
	.dwattr $C$DW$759, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$759, DW_AT_name("__size")
	.dwattr $C$DW$759, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$759, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$759, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$759, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$759, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$759, DW_AT_decl_column(0x0c)
$C$DW$760	.dwtag  DW_TAG_member
	.dwattr $C$DW$760, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$760, DW_AT_name("__self")
	.dwattr $C$DW$760, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$760, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$760, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$760, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$760, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$760, DW_AT_decl_column(0x11)
$C$DW$761	.dwtag  DW_TAG_member
	.dwattr $C$DW$761, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$761, DW_AT_name("__fxns")
	.dwattr $C$DW$761, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$761, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$761, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$761, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$761, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$761, DW_AT_decl_column(0x0b)
$C$DW$762	.dwtag  DW_TAG_member
	.dwattr $C$DW$762, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$762, DW_AT_name("instance")
	.dwattr $C$DW$762, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$762, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$762, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$762, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$762, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$762, DW_AT_decl_column(0x23)
	.dwendtag $C$DW$T$385

	.dwattr $C$DW$T$385, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IGateProvider.h")
	.dwattr $C$DW$T$385, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$T$385, DW_AT_decl_column(0x08)
$C$DW$T$1407	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_Params")
	.dwattr $C$DW$T$1407, DW_AT_type(*$C$DW$T$385)
	.dwattr $C$DW$T$1407, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1407, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1407, DW_AT_decl_line(0x3c)
	.dwattr $C$DW$T$1407, DW_AT_decl_column(0x31)

$C$DW$T$388	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$388, DW_AT_name("xdc_runtime_IGateProvider___Object")
	.dwattr $C$DW$T$388, DW_AT_byte_size(0x08)
$C$DW$763	.dwtag  DW_TAG_member
	.dwattr $C$DW$763, DW_AT_type(*$C$DW$T$387)
	.dwattr $C$DW$763, DW_AT_name("__fxns")
	.dwattr $C$DW$763, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$763, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$763, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$763, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$763, DW_AT_decl_line(0x3d)
	.dwattr $C$DW$763, DW_AT_decl_column(0x57)
$C$DW$764	.dwtag  DW_TAG_member
	.dwattr $C$DW$764, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$764, DW_AT_name("__label")
	.dwattr $C$DW$764, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$764, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$764, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$764, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$764, DW_AT_decl_line(0x3d)
	.dwattr $C$DW$764, DW_AT_decl_column(0x6a)
	.dwendtag $C$DW$T$388

	.dwattr $C$DW$T$388, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$388, DW_AT_decl_line(0x3d)
	.dwattr $C$DW$T$388, DW_AT_decl_column(0x10)
$C$DW$T$151	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$151, DW_AT_type(*$C$DW$T$388)
	.dwattr $C$DW$T$151, DW_AT_address_class(0x20)
$C$DW$T$152	.dwtag  DW_TAG_typedef, DW_AT_name("ti_sysbios_BIOS_RtsGateProxy_Handle")
	.dwattr $C$DW$T$152, DW_AT_type(*$C$DW$T$151)
	.dwattr $C$DW$T$152, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$152, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/package.defs.h")
	.dwattr $C$DW$T$152, DW_AT_decl_line(0x1a)
	.dwattr $C$DW$T$152, DW_AT_decl_column(0x34)
$C$DW$T$1408	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IGateProvider_Handle")
	.dwattr $C$DW$T$1408, DW_AT_type(*$C$DW$T$151)
	.dwattr $C$DW$T$1408, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1408, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1408, DW_AT_decl_line(0x3d)
	.dwattr $C$DW$T$1408, DW_AT_decl_column(0x76)
$C$DW$T$1409	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Handle")
	.dwattr $C$DW$T$1409, DW_AT_type(*$C$DW$T$151)
	.dwattr $C$DW$T$1409, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1409, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1409, DW_AT_decl_line(0x14b)
	.dwattr $C$DW$T$1409, DW_AT_decl_column(0x34)
$C$DW$T$419	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Handle")
	.dwattr $C$DW$T$419, DW_AT_type(*$C$DW$T$151)
	.dwattr $C$DW$T$419, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$419, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$419, DW_AT_decl_line(0x15b)
	.dwattr $C$DW$T$419, DW_AT_decl_column(0x34)
$C$DW$T$1410	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_Module_GateProxy_Handle")
	.dwattr $C$DW$T$1410, DW_AT_type(*$C$DW$T$151)
	.dwattr $C$DW$T$1410, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1410, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1410, DW_AT_decl_line(0x174)
	.dwattr $C$DW$T$1410, DW_AT_decl_column(0x34)

$C$DW$T$399	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$399, DW_AT_name("xdc_runtime_IHeap_Fxns__")
	.dwattr $C$DW$T$399, DW_AT_byte_size(0x28)
$C$DW$765	.dwtag  DW_TAG_member
	.dwattr $C$DW$765, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$765, DW_AT_name("__base")
	.dwattr $C$DW$765, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$765, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$765, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$765, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$765, DW_AT_decl_line(0x55)
	.dwattr $C$DW$765, DW_AT_decl_column(0x1d)
$C$DW$766	.dwtag  DW_TAG_member
	.dwattr $C$DW$766, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$766, DW_AT_name("__sysp")
	.dwattr $C$DW$766, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$766, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$766, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$766, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$766, DW_AT_decl_line(0x56)
	.dwattr $C$DW$766, DW_AT_decl_column(0x27)
$C$DW$767	.dwtag  DW_TAG_member
	.dwattr $C$DW$767, DW_AT_type(*$C$DW$T$390)
	.dwattr $C$DW$767, DW_AT_name("alloc")
	.dwattr $C$DW$767, DW_AT_TI_symbol_name("alloc")
	.dwattr $C$DW$767, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$767, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$767, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$767, DW_AT_decl_line(0x57)
	.dwattr $C$DW$767, DW_AT_decl_column(0x0f)
$C$DW$768	.dwtag  DW_TAG_member
	.dwattr $C$DW$768, DW_AT_type(*$C$DW$T$392)
	.dwattr $C$DW$768, DW_AT_name("free")
	.dwattr $C$DW$768, DW_AT_TI_symbol_name("free")
	.dwattr $C$DW$768, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$768, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$768, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$768, DW_AT_decl_line(0x58)
	.dwattr $C$DW$768, DW_AT_decl_column(0x10)
$C$DW$769	.dwtag  DW_TAG_member
	.dwattr $C$DW$769, DW_AT_type(*$C$DW$T$394)
	.dwattr $C$DW$769, DW_AT_name("isBlocking")
	.dwattr $C$DW$769, DW_AT_TI_symbol_name("isBlocking")
	.dwattr $C$DW$769, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$769, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$769, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$769, DW_AT_decl_line(0x59)
	.dwattr $C$DW$769, DW_AT_decl_column(0x10)
$C$DW$770	.dwtag  DW_TAG_member
	.dwattr $C$DW$770, DW_AT_type(*$C$DW$T$398)
	.dwattr $C$DW$770, DW_AT_name("getStats")
	.dwattr $C$DW$770, DW_AT_TI_symbol_name("getStats")
	.dwattr $C$DW$770, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$770, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$770, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$770, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$770, DW_AT_decl_column(0x10)
$C$DW$771	.dwtag  DW_TAG_member
	.dwattr $C$DW$771, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$771, DW_AT_name("__sfxns")
	.dwattr $C$DW$771, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$771, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$771, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$771, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$771, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$771, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$399

	.dwattr $C$DW$T$399, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$399, DW_AT_decl_line(0x54)
	.dwattr $C$DW$T$399, DW_AT_decl_column(0x08)
$C$DW$T$401	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_Fxns__")
	.dwattr $C$DW$T$401, DW_AT_type(*$C$DW$T$399)
	.dwattr $C$DW$T$401, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$401, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$401, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$401, DW_AT_decl_column(0x29)
$C$DW$T$402	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$402, DW_AT_type(*$C$DW$T$401)
	.dwattr $C$DW$T$402, DW_AT_address_class(0x20)
$C$DW$T$1411	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1411, DW_AT_type(*$C$DW$T$401)
$C$DW$T$1412	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1412, DW_AT_type(*$C$DW$T$1411)
	.dwattr $C$DW$T$1412, DW_AT_address_class(0x20)
$C$DW$T$1413	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_Module")
	.dwattr $C$DW$T$1413, DW_AT_type(*$C$DW$T$1412)
	.dwattr $C$DW$T$1413, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1413, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1413, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$T$1413, DW_AT_decl_column(0x29)

$C$DW$T$400	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$400, DW_AT_name("xdc_runtime_IHeap_Params")
	.dwattr $C$DW$T$400, DW_AT_byte_size(0x10)
$C$DW$772	.dwtag  DW_TAG_member
	.dwattr $C$DW$772, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$772, DW_AT_name("__size")
	.dwattr $C$DW$772, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$772, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$772, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$772, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$772, DW_AT_decl_line(0x48)
	.dwattr $C$DW$772, DW_AT_decl_column(0x0c)
$C$DW$773	.dwtag  DW_TAG_member
	.dwattr $C$DW$773, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$773, DW_AT_name("__self")
	.dwattr $C$DW$773, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$773, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$773, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$773, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$773, DW_AT_decl_line(0x49)
	.dwattr $C$DW$773, DW_AT_decl_column(0x11)
$C$DW$774	.dwtag  DW_TAG_member
	.dwattr $C$DW$774, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$774, DW_AT_name("__fxns")
	.dwattr $C$DW$774, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$774, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$774, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$774, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$774, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$774, DW_AT_decl_column(0x0b)
$C$DW$775	.dwtag  DW_TAG_member
	.dwattr $C$DW$775, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$775, DW_AT_name("instance")
	.dwattr $C$DW$775, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$775, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$775, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$775, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$775, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$775, DW_AT_decl_column(0x23)
	.dwendtag $C$DW$T$400

	.dwattr $C$DW$T$400, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IHeap.h")
	.dwattr $C$DW$T$400, DW_AT_decl_line(0x47)
	.dwattr $C$DW$T$400, DW_AT_decl_column(0x08)
$C$DW$T$1414	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_Params")
	.dwattr $C$DW$T$1414, DW_AT_type(*$C$DW$T$400)
	.dwattr $C$DW$T$1414, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1414, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1414, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$T$1414, DW_AT_decl_column(0x29)

$C$DW$T$403	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$403, DW_AT_name("xdc_runtime_IHeap___Object")
	.dwattr $C$DW$T$403, DW_AT_byte_size(0x08)
$C$DW$776	.dwtag  DW_TAG_member
	.dwattr $C$DW$776, DW_AT_type(*$C$DW$T$402)
	.dwattr $C$DW$776, DW_AT_name("__fxns")
	.dwattr $C$DW$776, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$776, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$776, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$776, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$776, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$776, DW_AT_decl_column(0x47)
$C$DW$777	.dwtag  DW_TAG_member
	.dwattr $C$DW$777, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$777, DW_AT_name("__label")
	.dwattr $C$DW$777, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$777, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$777, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$777, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$777, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$777, DW_AT_decl_column(0x5a)
	.dwendtag $C$DW$T$403

	.dwattr $C$DW$T$403, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$403, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$403, DW_AT_decl_column(0x10)
$C$DW$T$340	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$340, DW_AT_type(*$C$DW$T$403)
	.dwattr $C$DW$T$340, DW_AT_address_class(0x20)
$C$DW$T$341	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IHeap_Handle")
	.dwattr $C$DW$T$341, DW_AT_type(*$C$DW$T$340)
	.dwattr $C$DW$T$341, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$341, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$341, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$341, DW_AT_decl_column(0x66)
$C$DW$T$1415	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_Object__heap")
	.dwattr $C$DW$T$1415, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1415, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1415, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1415, DW_AT_decl_line(0xc0)
	.dwattr $C$DW$T$1415, DW_AT_decl_column(0x22)
$C$DW$T$1416	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_RtsGateProxy_Object__heap")
	.dwattr $C$DW$T$1416, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1416, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1416, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/package/BIOS_RtsGateProxy.h")
	.dwattr $C$DW$T$1416, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$1416, DW_AT_decl_column(0x22)
$C$DW$T$1417	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_Object__heap")
	.dwattr $C$DW$T$1417, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1417, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1417, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Clock.h")
	.dwattr $C$DW$T$1417, DW_AT_decl_line(0xad)
	.dwattr $C$DW$T$1417, DW_AT_decl_column(0x22)
$C$DW$T$1418	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Clock_TimerProxy_Object__heap")
	.dwattr $C$DW$T$1418, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1418, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1418, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Clock_TimerProxy.h")
	.dwattr $C$DW$T$1418, DW_AT_decl_line(0xa1)
	.dwattr $C$DW$T$1418, DW_AT_decl_column(0x22)
$C$DW$T$1419	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Event_Object__heap")
	.dwattr $C$DW$T$1419, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1419, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1419, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Event.h")
	.dwattr $C$DW$T$1419, DW_AT_decl_line(0x104)
	.dwattr $C$DW$T$1419, DW_AT_decl_column(0x22)
$C$DW$T$1420	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Queue_Object__heap")
	.dwattr $C$DW$T$1420, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1420, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1420, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Queue.h")
	.dwattr $C$DW$T$1420, DW_AT_decl_line(0x8e)
	.dwattr $C$DW$T$1420, DW_AT_decl_column(0x22)
$C$DW$T$1421	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Semaphore_Object__heap")
	.dwattr $C$DW$T$1421, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1421, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1421, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Semaphore.h")
	.dwattr $C$DW$T$1421, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$T$1421, DW_AT_decl_column(0x22)
$C$DW$T$1422	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Swi_Object__heap")
	.dwattr $C$DW$T$1422, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1422, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1422, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Swi.h")
	.dwattr $C$DW$T$1422, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$T$1422, DW_AT_decl_column(0x22)
$C$DW$T$1423	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_Object__heap")
	.dwattr $C$DW$T$1423, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1423, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1423, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1423, DW_AT_decl_line(0xec)
	.dwattr $C$DW$T$1423, DW_AT_decl_column(0x22)
$C$DW$T$1424	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_SupportProxy_Object__heap")
	.dwattr $C$DW$T$1424, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1424, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1424, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/package/Task_SupportProxy.h")
	.dwattr $C$DW$T$1424, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1424, DW_AT_decl_column(0x22)
$C$DW$T$1425	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_knl_Task_defaultStackHeap")
	.dwattr $C$DW$T$1425, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1425, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1425, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/knl/Task.h")
	.dwattr $C$DW$T$1425, DW_AT_decl_line(0x179)
	.dwattr $C$DW$T$1425, DW_AT_decl_column(0x22)
$C$DW$T$1426	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Assert_Object__heap")
	.dwattr $C$DW$T$1426, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1426, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1426, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Assert.h")
	.dwattr $C$DW$T$1426, DW_AT_decl_line(0x8c)
	.dwattr $C$DW$T$1426, DW_AT_decl_column(0x22)
$C$DW$T$1427	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Diags_Object__heap")
	.dwattr $C$DW$T$1427, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1427, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1427, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Diags.h")
	.dwattr $C$DW$T$1427, DW_AT_decl_line(0xdf)
	.dwattr $C$DW$T$1427, DW_AT_decl_column(0x22)
$C$DW$T$1428	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Error_Object__heap")
	.dwattr $C$DW$T$1428, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1428, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1428, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Error.h")
	.dwattr $C$DW$T$1428, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$T$1428, DW_AT_decl_column(0x22)
$C$DW$T$1429	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Log_Object__heap")
	.dwattr $C$DW$T$1429, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1429, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1429, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$1429, DW_AT_decl_line(0xa0)
	.dwattr $C$DW$T$1429, DW_AT_decl_column(0x22)
$C$DW$T$1430	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Module_GateProxy_Object__heap")
	.dwattr $C$DW$T$1430, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1430, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1430, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$1430, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$1430, DW_AT_decl_column(0x22)
$C$DW$T$1431	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Main_Object__heap")
	.dwattr $C$DW$T$1431, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1431, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1431, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Main.h")
	.dwattr $C$DW$T$1431, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$1431, DW_AT_decl_column(0x22)
$C$DW$T$1432	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_HeapProxy_Object__heap")
	.dwattr $C$DW$T$1432, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1432, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1432, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$1432, DW_AT_decl_line(0x83)
	.dwattr $C$DW$T$1432, DW_AT_decl_column(0x22)
$C$DW$T$1433	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_Object__heap")
	.dwattr $C$DW$T$1433, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1433, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1433, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$1433, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$1433, DW_AT_decl_column(0x22)
$C$DW$T$1434	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Memory_defaultHeapInstance")
	.dwattr $C$DW$T$1434, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1434, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1434, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$1434, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$1434, DW_AT_decl_column(0x22)
$C$DW$T$1435	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_Object__heap")
	.dwattr $C$DW$T$1435, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1435, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1435, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1435, DW_AT_decl_line(0xad)
	.dwattr $C$DW$T$1435, DW_AT_decl_column(0x22)
$C$DW$T$1436	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Types_Object__heap")
	.dwattr $C$DW$T$1436, DW_AT_type(*$C$DW$T$341)
	.dwattr $C$DW$T$1436, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1436, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1436, DW_AT_decl_line(0x112)
	.dwattr $C$DW$T$1436, DW_AT_decl_column(0x22)
$C$DW$T$430	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_HeapProxy_Handle")
	.dwattr $C$DW$T$430, DW_AT_type(*$C$DW$T$340)
	.dwattr $C$DW$T$430, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$430, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$430, DW_AT_decl_line(0x164)
	.dwattr $C$DW$T$430, DW_AT_decl_column(0x2c)

$C$DW$T$404	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$404, DW_AT_name("xdc_runtime_IInstance_Fxns__")
	.dwattr $C$DW$T$404, DW_AT_byte_size(0x18)
$C$DW$778	.dwtag  DW_TAG_member
	.dwattr $C$DW$778, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$778, DW_AT_name("__base")
	.dwattr $C$DW$778, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$778, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$778, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$778, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$778, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$778, DW_AT_decl_column(0x1d)
$C$DW$779	.dwtag  DW_TAG_member
	.dwattr $C$DW$779, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$779, DW_AT_name("__sysp")
	.dwattr $C$DW$779, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$779, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$779, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$779, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$779, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$779, DW_AT_decl_column(0x27)
$C$DW$780	.dwtag  DW_TAG_member
	.dwattr $C$DW$780, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$780, DW_AT_name("__sfxns")
	.dwattr $C$DW$780, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$780, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$780, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$780, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$780, DW_AT_decl_line(0x50)
	.dwattr $C$DW$780, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$404

	.dwattr $C$DW$T$404, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$T$404, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$404, DW_AT_decl_column(0x08)
$C$DW$T$406	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IInstance_Fxns__")
	.dwattr $C$DW$T$406, DW_AT_type(*$C$DW$T$404)
	.dwattr $C$DW$T$406, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$406, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$406, DW_AT_decl_line(0x138)
	.dwattr $C$DW$T$406, DW_AT_decl_column(0x2d)
$C$DW$T$407	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$407, DW_AT_type(*$C$DW$T$406)
	.dwattr $C$DW$T$407, DW_AT_address_class(0x20)
$C$DW$T$1437	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1437, DW_AT_type(*$C$DW$T$406)
$C$DW$T$1438	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1438, DW_AT_type(*$C$DW$T$1437)
	.dwattr $C$DW$T$1438, DW_AT_address_class(0x20)
$C$DW$T$1439	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IInstance_Module")
	.dwattr $C$DW$T$1439, DW_AT_type(*$C$DW$T$1438)
	.dwattr $C$DW$T$1439, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1439, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1439, DW_AT_decl_line(0x139)
	.dwattr $C$DW$T$1439, DW_AT_decl_column(0x2d)

$C$DW$T$405	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$405, DW_AT_name("xdc_runtime_IInstance_Params")
	.dwattr $C$DW$T$405, DW_AT_byte_size(0x08)
$C$DW$781	.dwtag  DW_TAG_member
	.dwattr $C$DW$781, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$781, DW_AT_name("__size")
	.dwattr $C$DW$781, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$781, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$781, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$781, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$781, DW_AT_decl_line(0x43)
	.dwattr $C$DW$781, DW_AT_decl_column(0x0c)
$C$DW$782	.dwtag  DW_TAG_member
	.dwattr $C$DW$782, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$782, DW_AT_name("name")
	.dwattr $C$DW$782, DW_AT_TI_symbol_name("name")
	.dwattr $C$DW$782, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$782, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$782, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$782, DW_AT_decl_line(0x44)
	.dwattr $C$DW$782, DW_AT_decl_column(0x10)
	.dwendtag $C$DW$T$405

	.dwattr $C$DW$T$405, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IInstance.h")
	.dwattr $C$DW$T$405, DW_AT_decl_line(0x42)
	.dwattr $C$DW$T$405, DW_AT_decl_column(0x08)
$C$DW$T$161	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IInstance_Params")
	.dwattr $C$DW$T$161, DW_AT_type(*$C$DW$T$405)
	.dwattr $C$DW$T$161, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$161, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$161, DW_AT_decl_line(0x13a)
	.dwattr $C$DW$T$161, DW_AT_decl_column(0x2d)
$C$DW$T$162	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$162, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$T$162, DW_AT_address_class(0x20)

$C$DW$T$408	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$408, DW_AT_name("xdc_runtime_IInstance___Object")
	.dwattr $C$DW$T$408, DW_AT_byte_size(0x08)
$C$DW$783	.dwtag  DW_TAG_member
	.dwattr $C$DW$783, DW_AT_type(*$C$DW$T$407)
	.dwattr $C$DW$783, DW_AT_name("__fxns")
	.dwattr $C$DW$783, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$783, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$783, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$783, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$783, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$783, DW_AT_decl_column(0x4f)
$C$DW$784	.dwtag  DW_TAG_member
	.dwattr $C$DW$784, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$784, DW_AT_name("__label")
	.dwattr $C$DW$784, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$784, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$784, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$784, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$784, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$784, DW_AT_decl_column(0x62)
	.dwendtag $C$DW$T$408

	.dwattr $C$DW$T$408, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$408, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$T$408, DW_AT_decl_column(0x10)
$C$DW$T$1440	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1440, DW_AT_type(*$C$DW$T$408)
	.dwattr $C$DW$T$1440, DW_AT_address_class(0x20)
$C$DW$T$1441	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IInstance_Handle")
	.dwattr $C$DW$T$1441, DW_AT_type(*$C$DW$T$1440)
	.dwattr $C$DW$T$1441, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1441, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1441, DW_AT_decl_line(0x13b)
	.dwattr $C$DW$T$1441, DW_AT_decl_column(0x6e)

$C$DW$T$74	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$74, DW_AT_name("xdc_runtime_ILogger_Fxns__")
	.dwattr $C$DW$T$74, DW_AT_declaration
	.dwendtag $C$DW$T$74

	.dwattr $C$DW$T$74, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$74, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$74, DW_AT_decl_column(0x10)
$C$DW$T$409	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ILogger_Fxns__")
	.dwattr $C$DW$T$409, DW_AT_type(*$C$DW$T$74)
	.dwattr $C$DW$T$409, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$409, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$409, DW_AT_decl_line(0x56)
	.dwattr $C$DW$T$409, DW_AT_decl_column(0x2b)
$C$DW$T$410	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$410, DW_AT_type(*$C$DW$T$409)
	.dwattr $C$DW$T$410, DW_AT_address_class(0x20)
$C$DW$T$1442	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1442, DW_AT_type(*$C$DW$T$409)
$C$DW$T$1443	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1443, DW_AT_type(*$C$DW$T$1442)
	.dwattr $C$DW$T$1443, DW_AT_address_class(0x20)
$C$DW$T$1444	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ILogger_Module")
	.dwattr $C$DW$T$1444, DW_AT_type(*$C$DW$T$1443)
	.dwattr $C$DW$T$1444, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1444, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1444, DW_AT_decl_line(0x57)
	.dwattr $C$DW$T$1444, DW_AT_decl_column(0x2b)

$C$DW$T$75	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$75, DW_AT_name("xdc_runtime_ILogger_Params")
	.dwattr $C$DW$T$75, DW_AT_declaration
	.dwendtag $C$DW$T$75

	.dwattr $C$DW$T$75, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$75, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$75, DW_AT_decl_column(0x10)
$C$DW$T$1445	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ILogger_Params")
	.dwattr $C$DW$T$1445, DW_AT_type(*$C$DW$T$75)
	.dwattr $C$DW$T$1445, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1445, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1445, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$1445, DW_AT_decl_column(0x2b)

$C$DW$T$411	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$411, DW_AT_name("xdc_runtime_ILogger___Object")
	.dwattr $C$DW$T$411, DW_AT_byte_size(0x08)
$C$DW$785	.dwtag  DW_TAG_member
	.dwattr $C$DW$785, DW_AT_type(*$C$DW$T$410)
	.dwattr $C$DW$785, DW_AT_name("__fxns")
	.dwattr $C$DW$785, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$785, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$785, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$785, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$785, DW_AT_decl_line(0x59)
	.dwattr $C$DW$785, DW_AT_decl_column(0x4b)
$C$DW$786	.dwtag  DW_TAG_member
	.dwattr $C$DW$786, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$786, DW_AT_name("__label")
	.dwattr $C$DW$786, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$786, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$786, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$786, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$786, DW_AT_decl_line(0x59)
	.dwattr $C$DW$786, DW_AT_decl_column(0x5e)
	.dwendtag $C$DW$T$411

	.dwattr $C$DW$T$411, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$411, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$411, DW_AT_decl_column(0x10)
$C$DW$T$1446	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1446, DW_AT_type(*$C$DW$T$411)
	.dwattr $C$DW$T$1446, DW_AT_address_class(0x20)
$C$DW$T$1447	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ILogger_Handle")
	.dwattr $C$DW$T$1447, DW_AT_type(*$C$DW$T$1446)
	.dwattr $C$DW$T$1447, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1447, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1447, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$1447, DW_AT_decl_column(0x6a)

$C$DW$T$412	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$412, DW_AT_name("xdc_runtime_IModule_Fxns__")
	.dwattr $C$DW$T$412, DW_AT_byte_size(0x18)
$C$DW$787	.dwtag  DW_TAG_member
	.dwattr $C$DW$787, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$787, DW_AT_name("__base")
	.dwattr $C$DW$787, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$787, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$787, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$787, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IModule.h")
	.dwattr $C$DW$787, DW_AT_decl_line(0x46)
	.dwattr $C$DW$787, DW_AT_decl_column(0x1d)
$C$DW$788	.dwtag  DW_TAG_member
	.dwattr $C$DW$788, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$788, DW_AT_name("__sysp")
	.dwattr $C$DW$788, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$788, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$788, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$788, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IModule.h")
	.dwattr $C$DW$788, DW_AT_decl_line(0x47)
	.dwattr $C$DW$788, DW_AT_decl_column(0x27)
$C$DW$789	.dwtag  DW_TAG_member
	.dwattr $C$DW$789, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$789, DW_AT_name("__sfxns")
	.dwattr $C$DW$789, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$789, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$789, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$789, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IModule.h")
	.dwattr $C$DW$789, DW_AT_decl_line(0x48)
	.dwattr $C$DW$789, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$412

	.dwattr $C$DW$T$412, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/IModule.h")
	.dwattr $C$DW$T$412, DW_AT_decl_line(0x45)
	.dwattr $C$DW$T$412, DW_AT_decl_column(0x08)
$C$DW$T$1448	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IModule_Fxns__")
	.dwattr $C$DW$T$1448, DW_AT_type(*$C$DW$T$412)
	.dwattr $C$DW$T$1448, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1448, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1448, DW_AT_decl_line(0x10)
	.dwattr $C$DW$T$1448, DW_AT_decl_column(0x2b)
$C$DW$T$1449	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1449, DW_AT_type(*$C$DW$T$1448)
$C$DW$T$1450	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1450, DW_AT_type(*$C$DW$T$1449)
	.dwattr $C$DW$T$1450, DW_AT_address_class(0x20)
$C$DW$T$1451	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_IModule_Module")
	.dwattr $C$DW$T$1451, DW_AT_type(*$C$DW$T$1450)
	.dwattr $C$DW$T$1451, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1451, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1451, DW_AT_decl_line(0x11)
	.dwattr $C$DW$T$1451, DW_AT_decl_column(0x2b)

$C$DW$T$76	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$76, DW_AT_name("xdc_runtime_ISystemSupport_Fxns__")
	.dwattr $C$DW$T$76, DW_AT_declaration
	.dwendtag $C$DW$T$76

	.dwattr $C$DW$T$76, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$76, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$76, DW_AT_decl_column(0x10)
$C$DW$T$1452	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ISystemSupport_Fxns__")
	.dwattr $C$DW$T$1452, DW_AT_type(*$C$DW$T$76)
	.dwattr $C$DW$T$1452, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1452, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1452, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$1452, DW_AT_decl_column(0x32)
$C$DW$T$1453	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1453, DW_AT_type(*$C$DW$T$1452)
$C$DW$T$1454	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1454, DW_AT_type(*$C$DW$T$1453)
	.dwattr $C$DW$T$1454, DW_AT_address_class(0x20)
$C$DW$T$1455	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ISystemSupport_Module")
	.dwattr $C$DW$T$1455, DW_AT_type(*$C$DW$T$1454)
	.dwattr $C$DW$T$1455, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1455, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1455, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$T$1455, DW_AT_decl_column(0x32)

$C$DW$T$77	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$77, DW_AT_name("xdc_runtime_ITimestampClient_Fxns__")
	.dwattr $C$DW$T$77, DW_AT_declaration
	.dwendtag $C$DW$T$77

	.dwattr $C$DW$T$77, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$77, DW_AT_decl_line(0x102)
	.dwattr $C$DW$T$77, DW_AT_decl_column(0x10)
$C$DW$T$1456	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ITimestampClient_Fxns__")
	.dwattr $C$DW$T$1456, DW_AT_type(*$C$DW$T$77)
	.dwattr $C$DW$T$1456, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1456, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1456, DW_AT_decl_line(0x102)
	.dwattr $C$DW$T$1456, DW_AT_decl_column(0x34)
$C$DW$T$1457	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1457, DW_AT_type(*$C$DW$T$1456)
$C$DW$T$1458	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1458, DW_AT_type(*$C$DW$T$1457)
	.dwattr $C$DW$T$1458, DW_AT_address_class(0x20)
$C$DW$T$1459	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ITimestampClient_Module")
	.dwattr $C$DW$T$1459, DW_AT_type(*$C$DW$T$1458)
	.dwattr $C$DW$T$1459, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1459, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1459, DW_AT_decl_line(0x103)
	.dwattr $C$DW$T$1459, DW_AT_decl_column(0x34)

$C$DW$T$78	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$78, DW_AT_name("xdc_runtime_ITimestampProvider_Fxns__")
	.dwattr $C$DW$T$78, DW_AT_declaration
	.dwendtag $C$DW$T$78

	.dwattr $C$DW$T$78, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$78, DW_AT_decl_line(0x110)
	.dwattr $C$DW$T$78, DW_AT_decl_column(0x10)
$C$DW$T$1460	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ITimestampProvider_Fxns__")
	.dwattr $C$DW$T$1460, DW_AT_type(*$C$DW$T$78)
	.dwattr $C$DW$T$1460, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1460, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1460, DW_AT_decl_line(0x110)
	.dwattr $C$DW$T$1460, DW_AT_decl_column(0x36)
$C$DW$T$1461	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1461, DW_AT_type(*$C$DW$T$1460)
$C$DW$T$1462	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1462, DW_AT_type(*$C$DW$T$1461)
	.dwattr $C$DW$T$1462, DW_AT_address_class(0x20)
$C$DW$T$1463	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_ITimestampProvider_Module")
	.dwattr $C$DW$T$1463, DW_AT_type(*$C$DW$T$1462)
	.dwattr $C$DW$T$1463, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1463, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1463, DW_AT_decl_line(0x111)
	.dwattr $C$DW$T$1463, DW_AT_decl_column(0x36)

$C$DW$T$418	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$418, DW_AT_name("xdc_runtime_Log_EventRec")
	.dwattr $C$DW$T$418, DW_AT_byte_size(0x30)
$C$DW$790	.dwtag  DW_TAG_member
	.dwattr $C$DW$790, DW_AT_type(*$C$DW$T$413)
	.dwattr $C$DW$790, DW_AT_name("tstamp")
	.dwattr $C$DW$790, DW_AT_TI_symbol_name("tstamp")
	.dwattr $C$DW$790, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$790, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$790, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$790, DW_AT_decl_line(0x4e)
	.dwattr $C$DW$790, DW_AT_decl_column(0x23)
$C$DW$791	.dwtag  DW_TAG_member
	.dwattr $C$DW$791, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$791, DW_AT_name("serial")
	.dwattr $C$DW$791, DW_AT_TI_symbol_name("serial")
	.dwattr $C$DW$791, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$791, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$791, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$791, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$791, DW_AT_decl_column(0x10)
$C$DW$792	.dwtag  DW_TAG_member
	.dwattr $C$DW$792, DW_AT_type(*$C$DW$T$414)
	.dwattr $C$DW$792, DW_AT_name("evt")
	.dwattr $C$DW$792, DW_AT_TI_symbol_name("evt")
	.dwattr $C$DW$792, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$792, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$792, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$792, DW_AT_decl_line(0x50)
	.dwattr $C$DW$792, DW_AT_decl_column(0x1d)
$C$DW$793	.dwtag  DW_TAG_member
	.dwattr $C$DW$793, DW_AT_type(*$C$DW$T$417)
	.dwattr $C$DW$793, DW_AT_name("arg")
	.dwattr $C$DW$793, DW_AT_TI_symbol_name("arg")
	.dwattr $C$DW$793, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$793, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$793, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$793, DW_AT_decl_line(0x51)
	.dwattr $C$DW$793, DW_AT_decl_column(0x28)
	.dwendtag $C$DW$T$418

	.dwattr $C$DW$T$418, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Log.h")
	.dwattr $C$DW$T$418, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$418, DW_AT_decl_column(0x08)
$C$DW$T$1464	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Log_EventRec")
	.dwattr $C$DW$T$1464, DW_AT_type(*$C$DW$T$418)
	.dwattr $C$DW$T$1464, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1464, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1464, DW_AT_decl_line(0x50)
	.dwattr $C$DW$T$1464, DW_AT_decl_column(0x29)

$C$DW$T$79	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$79, DW_AT_name("xdc_runtime_LoggerBuf_Entry")
	.dwattr $C$DW$T$79, DW_AT_declaration
	.dwendtag $C$DW$T$79

	.dwattr $C$DW$T$79, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$79, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$79, DW_AT_decl_column(0x10)
$C$DW$T$1465	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Entry")
	.dwattr $C$DW$T$1465, DW_AT_type(*$C$DW$T$79)
	.dwattr $C$DW$T$1465, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1465, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1465, DW_AT_decl_line(0x68)
	.dwattr $C$DW$T$1465, DW_AT_decl_column(0x2c)

$C$DW$T$80	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$80, DW_AT_name("xdc_runtime_LoggerBuf_Fxns__")
	.dwattr $C$DW$T$80, DW_AT_declaration
	.dwendtag $C$DW$T$80

	.dwattr $C$DW$T$80, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$80, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$80, DW_AT_decl_column(0x10)
$C$DW$T$1466	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Fxns__")
	.dwattr $C$DW$T$1466, DW_AT_type(*$C$DW$T$80)
	.dwattr $C$DW$T$1466, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1466, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1466, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$T$1466, DW_AT_decl_column(0x2d)
$C$DW$T$1467	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1467, DW_AT_type(*$C$DW$T$1466)
$C$DW$T$1468	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1468, DW_AT_type(*$C$DW$T$1467)
	.dwattr $C$DW$T$1468, DW_AT_address_class(0x20)
$C$DW$T$1469	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module")
	.dwattr $C$DW$T$1469, DW_AT_type(*$C$DW$T$1468)
	.dwattr $C$DW$T$1469, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1469, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1469, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$T$1469, DW_AT_decl_column(0x2d)

$C$DW$T$81	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$81, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$81, DW_AT_declaration
	.dwendtag $C$DW$T$81

	.dwattr $C$DW$T$81, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$81, DW_AT_decl_line(0x148)
	.dwattr $C$DW$T$81, DW_AT_decl_column(0x10)
$C$DW$T$1470	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$1470, DW_AT_type(*$C$DW$T$81)
	.dwattr $C$DW$T$1470, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1470, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1470, DW_AT_decl_line(0x148)
	.dwattr $C$DW$T$1470, DW_AT_decl_column(0x3e)
$C$DW$T$1471	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1471, DW_AT_type(*$C$DW$T$1470)
$C$DW$T$1472	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1472, DW_AT_type(*$C$DW$T$1471)
	.dwattr $C$DW$T$1472, DW_AT_address_class(0x20)
$C$DW$T$1473	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Module")
	.dwattr $C$DW$T$1473, DW_AT_type(*$C$DW$T$1472)
	.dwattr $C$DW$T$1473, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1473, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1473, DW_AT_decl_line(0x149)
	.dwattr $C$DW$T$1473, DW_AT_decl_column(0x3e)

$C$DW$T$82	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$82, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Params")
	.dwattr $C$DW$T$82, DW_AT_declaration
	.dwendtag $C$DW$T$82

	.dwattr $C$DW$T$82, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$82, DW_AT_decl_line(0x14a)
	.dwattr $C$DW$T$82, DW_AT_decl_column(0x10)
$C$DW$T$1474	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module_GateProxy_Params")
	.dwattr $C$DW$T$1474, DW_AT_type(*$C$DW$T$82)
	.dwattr $C$DW$T$1474, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1474, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1474, DW_AT_decl_line(0x14a)
	.dwattr $C$DW$T$1474, DW_AT_decl_column(0x3e)

$C$DW$T$83	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$83, DW_AT_name("xdc_runtime_LoggerBuf_Module_State")
	.dwattr $C$DW$T$83, DW_AT_declaration
	.dwendtag $C$DW$T$83

	.dwattr $C$DW$T$83, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$83, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$83, DW_AT_decl_column(0x10)
$C$DW$T$1475	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Module_State")
	.dwattr $C$DW$T$1475, DW_AT_type(*$C$DW$T$83)
	.dwattr $C$DW$T$1475, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1475, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1475, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$1475, DW_AT_decl_column(0x33)

$C$DW$T$84	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$84, DW_AT_name("xdc_runtime_LoggerBuf_Object")
	.dwattr $C$DW$T$84, DW_AT_declaration
	.dwendtag $C$DW$T$84

	.dwattr $C$DW$T$84, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$84, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$84, DW_AT_decl_column(0x10)
$C$DW$T$1476	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Object")
	.dwattr $C$DW$T$1476, DW_AT_type(*$C$DW$T$84)
	.dwattr $C$DW$T$1476, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1476, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1476, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$T$1476, DW_AT_decl_column(0x2d)
$C$DW$T$1477	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1477, DW_AT_type(*$C$DW$T$1476)
	.dwattr $C$DW$T$1477, DW_AT_address_class(0x20)
$C$DW$T$1478	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Handle")
	.dwattr $C$DW$T$1478, DW_AT_type(*$C$DW$T$1477)
	.dwattr $C$DW$T$1478, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1478, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1478, DW_AT_decl_line(0x6f)
	.dwattr $C$DW$T$1478, DW_AT_decl_column(0x27)
$C$DW$T$1479	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Instance")
	.dwattr $C$DW$T$1479, DW_AT_type(*$C$DW$T$1477)
	.dwattr $C$DW$T$1479, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1479, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1479, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$1479, DW_AT_decl_column(0x27)

$C$DW$T$85	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$85, DW_AT_name("xdc_runtime_LoggerBuf_Object__")
	.dwattr $C$DW$T$85, DW_AT_declaration
	.dwendtag $C$DW$T$85

	.dwattr $C$DW$T$85, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$85, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$85, DW_AT_decl_column(0x10)
$C$DW$T$1480	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Instance_State")
	.dwattr $C$DW$T$1480, DW_AT_type(*$C$DW$T$85)
	.dwattr $C$DW$T$1480, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1480, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1480, DW_AT_decl_line(0x70)
	.dwattr $C$DW$T$1480, DW_AT_decl_column(0x2f)

$C$DW$T$86	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$86, DW_AT_name("xdc_runtime_LoggerBuf_Params")
	.dwattr $C$DW$T$86, DW_AT_declaration
	.dwendtag $C$DW$T$86

	.dwattr $C$DW$T$86, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$86, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$86, DW_AT_decl_column(0x10)
$C$DW$T$1481	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Params")
	.dwattr $C$DW$T$1481, DW_AT_type(*$C$DW$T$86)
	.dwattr $C$DW$T$1481, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1481, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1481, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$T$1481, DW_AT_decl_column(0x2d)

$C$DW$T$87	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$87, DW_AT_name("xdc_runtime_LoggerBuf_Struct")
	.dwattr $C$DW$T$87, DW_AT_declaration
	.dwendtag $C$DW$T$87

	.dwattr $C$DW$T$87, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$87, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$87, DW_AT_decl_column(0x10)
$C$DW$T$1482	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_Struct")
	.dwattr $C$DW$T$1482, DW_AT_type(*$C$DW$T$87)
	.dwattr $C$DW$T$1482, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1482, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1482, DW_AT_decl_line(0x6e)
	.dwattr $C$DW$T$1482, DW_AT_decl_column(0x2d)

$C$DW$T$88	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$88, DW_AT_name("xdc_runtime_LoggerBuf_TimestampProxy_Fxns__")
	.dwattr $C$DW$T$88, DW_AT_declaration
	.dwendtag $C$DW$T$88

	.dwattr $C$DW$T$88, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$88, DW_AT_decl_line(0x141)
	.dwattr $C$DW$T$88, DW_AT_decl_column(0x10)
$C$DW$T$1483	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_TimestampProxy_Fxns__")
	.dwattr $C$DW$T$1483, DW_AT_type(*$C$DW$T$88)
	.dwattr $C$DW$T$1483, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1483, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1483, DW_AT_decl_line(0x141)
	.dwattr $C$DW$T$1483, DW_AT_decl_column(0x3c)
$C$DW$T$1484	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1484, DW_AT_type(*$C$DW$T$1483)
$C$DW$T$1485	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1485, DW_AT_type(*$C$DW$T$1484)
	.dwattr $C$DW$T$1485, DW_AT_address_class(0x20)
$C$DW$T$1486	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerBuf_TimestampProxy_Module")
	.dwattr $C$DW$T$1486, DW_AT_type(*$C$DW$T$1485)
	.dwattr $C$DW$T$1486, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1486, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1486, DW_AT_decl_line(0x142)
	.dwattr $C$DW$T$1486, DW_AT_decl_column(0x3c)

$C$DW$T$89	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$89, DW_AT_name("xdc_runtime_LoggerCallback_Fxns__")
	.dwattr $C$DW$T$89, DW_AT_declaration
	.dwendtag $C$DW$T$89

	.dwattr $C$DW$T$89, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$89, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$89, DW_AT_decl_column(0x10)
$C$DW$T$1487	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Fxns__")
	.dwattr $C$DW$T$1487, DW_AT_type(*$C$DW$T$89)
	.dwattr $C$DW$T$1487, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1487, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1487, DW_AT_decl_line(0x77)
	.dwattr $C$DW$T$1487, DW_AT_decl_column(0x32)
$C$DW$T$1488	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1488, DW_AT_type(*$C$DW$T$1487)
$C$DW$T$1489	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1489, DW_AT_type(*$C$DW$T$1488)
	.dwattr $C$DW$T$1489, DW_AT_address_class(0x20)
$C$DW$T$1490	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Module")
	.dwattr $C$DW$T$1490, DW_AT_type(*$C$DW$T$1489)
	.dwattr $C$DW$T$1490, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1490, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1490, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$1490, DW_AT_decl_column(0x32)

$C$DW$T$90	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$90, DW_AT_name("xdc_runtime_LoggerCallback_Object")
	.dwattr $C$DW$T$90, DW_AT_declaration
	.dwendtag $C$DW$T$90

	.dwattr $C$DW$T$90, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$90, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$90, DW_AT_decl_column(0x10)
$C$DW$T$1491	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Object")
	.dwattr $C$DW$T$1491, DW_AT_type(*$C$DW$T$90)
	.dwattr $C$DW$T$1491, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1491, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1491, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$T$1491, DW_AT_decl_column(0x32)
$C$DW$T$1492	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1492, DW_AT_type(*$C$DW$T$1491)
	.dwattr $C$DW$T$1492, DW_AT_address_class(0x20)
$C$DW$T$1493	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Handle")
	.dwattr $C$DW$T$1493, DW_AT_type(*$C$DW$T$1492)
	.dwattr $C$DW$T$1493, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1493, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1493, DW_AT_decl_line(0x7c)
	.dwattr $C$DW$T$1493, DW_AT_decl_column(0x2c)
$C$DW$T$1494	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Instance")
	.dwattr $C$DW$T$1494, DW_AT_type(*$C$DW$T$1492)
	.dwattr $C$DW$T$1494, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1494, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1494, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$1494, DW_AT_decl_column(0x2c)

$C$DW$T$91	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$91, DW_AT_name("xdc_runtime_LoggerCallback_Object__")
	.dwattr $C$DW$T$91, DW_AT_declaration
	.dwendtag $C$DW$T$91

	.dwattr $C$DW$T$91, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$91, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$91, DW_AT_decl_column(0x10)
$C$DW$T$1495	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Instance_State")
	.dwattr $C$DW$T$1495, DW_AT_type(*$C$DW$T$91)
	.dwattr $C$DW$T$1495, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1495, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1495, DW_AT_decl_line(0x7d)
	.dwattr $C$DW$T$1495, DW_AT_decl_column(0x34)

$C$DW$T$92	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$92, DW_AT_name("xdc_runtime_LoggerCallback_Params")
	.dwattr $C$DW$T$92, DW_AT_declaration
	.dwendtag $C$DW$T$92

	.dwattr $C$DW$T$92, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$92, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$92, DW_AT_decl_column(0x10)
$C$DW$T$1496	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Params")
	.dwattr $C$DW$T$1496, DW_AT_type(*$C$DW$T$92)
	.dwattr $C$DW$T$1496, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1496, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1496, DW_AT_decl_line(0x79)
	.dwattr $C$DW$T$1496, DW_AT_decl_column(0x32)

$C$DW$T$93	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$93, DW_AT_name("xdc_runtime_LoggerCallback_Struct")
	.dwattr $C$DW$T$93, DW_AT_declaration
	.dwendtag $C$DW$T$93

	.dwattr $C$DW$T$93, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$93, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$93, DW_AT_decl_column(0x10)
$C$DW$T$1497	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerCallback_Struct")
	.dwattr $C$DW$T$1497, DW_AT_type(*$C$DW$T$93)
	.dwattr $C$DW$T$1497, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1497, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1497, DW_AT_decl_line(0x7b)
	.dwattr $C$DW$T$1497, DW_AT_decl_column(0x32)

$C$DW$T$94	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$94, DW_AT_name("xdc_runtime_LoggerSys_Fxns__")
	.dwattr $C$DW$T$94, DW_AT_declaration
	.dwendtag $C$DW$T$94

	.dwattr $C$DW$T$94, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$94, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$94, DW_AT_decl_column(0x10)
$C$DW$T$1498	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Fxns__")
	.dwattr $C$DW$T$1498, DW_AT_type(*$C$DW$T$94)
	.dwattr $C$DW$T$1498, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1498, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1498, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$1498, DW_AT_decl_column(0x2d)
$C$DW$T$1499	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1499, DW_AT_type(*$C$DW$T$1498)
$C$DW$T$1500	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1500, DW_AT_type(*$C$DW$T$1499)
	.dwattr $C$DW$T$1500, DW_AT_address_class(0x20)
$C$DW$T$1501	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Module")
	.dwattr $C$DW$T$1501, DW_AT_type(*$C$DW$T$1500)
	.dwattr $C$DW$T$1501, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1501, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1501, DW_AT_decl_line(0x85)
	.dwattr $C$DW$T$1501, DW_AT_decl_column(0x2d)

$C$DW$T$95	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$95, DW_AT_name("xdc_runtime_LoggerSys_Object")
	.dwattr $C$DW$T$95, DW_AT_declaration
	.dwendtag $C$DW$T$95

	.dwattr $C$DW$T$95, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$95, DW_AT_decl_line(0x87)
	.dwattr $C$DW$T$95, DW_AT_decl_column(0x10)
$C$DW$T$1502	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Object")
	.dwattr $C$DW$T$1502, DW_AT_type(*$C$DW$T$95)
	.dwattr $C$DW$T$1502, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1502, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1502, DW_AT_decl_line(0x87)
	.dwattr $C$DW$T$1502, DW_AT_decl_column(0x2d)
$C$DW$T$1503	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1503, DW_AT_type(*$C$DW$T$1502)
	.dwattr $C$DW$T$1503, DW_AT_address_class(0x20)
$C$DW$T$1504	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Handle")
	.dwattr $C$DW$T$1504, DW_AT_type(*$C$DW$T$1503)
	.dwattr $C$DW$T$1504, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1504, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1504, DW_AT_decl_line(0x89)
	.dwattr $C$DW$T$1504, DW_AT_decl_column(0x27)
$C$DW$T$1505	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Instance")
	.dwattr $C$DW$T$1505, DW_AT_type(*$C$DW$T$1503)
	.dwattr $C$DW$T$1505, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1505, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1505, DW_AT_decl_line(0x8b)
	.dwattr $C$DW$T$1505, DW_AT_decl_column(0x27)

$C$DW$T$96	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$96, DW_AT_name("xdc_runtime_LoggerSys_Object__")
	.dwattr $C$DW$T$96, DW_AT_declaration
	.dwendtag $C$DW$T$96

	.dwattr $C$DW$T$96, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$96, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$96, DW_AT_decl_column(0x10)
$C$DW$T$1506	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Instance_State")
	.dwattr $C$DW$T$1506, DW_AT_type(*$C$DW$T$96)
	.dwattr $C$DW$T$1506, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1506, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1506, DW_AT_decl_line(0x8a)
	.dwattr $C$DW$T$1506, DW_AT_decl_column(0x2f)

$C$DW$T$97	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$97, DW_AT_name("xdc_runtime_LoggerSys_Params")
	.dwattr $C$DW$T$97, DW_AT_declaration
	.dwendtag $C$DW$T$97

	.dwattr $C$DW$T$97, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$97, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$97, DW_AT_decl_column(0x10)
$C$DW$T$1507	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Params")
	.dwattr $C$DW$T$1507, DW_AT_type(*$C$DW$T$97)
	.dwattr $C$DW$T$1507, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1507, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1507, DW_AT_decl_line(0x86)
	.dwattr $C$DW$T$1507, DW_AT_decl_column(0x2d)

$C$DW$T$98	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$98, DW_AT_name("xdc_runtime_LoggerSys_Struct")
	.dwattr $C$DW$T$98, DW_AT_declaration
	.dwendtag $C$DW$T$98

	.dwattr $C$DW$T$98, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$98, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$98, DW_AT_decl_column(0x10)
$C$DW$T$1508	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_Struct")
	.dwattr $C$DW$T$1508, DW_AT_type(*$C$DW$T$98)
	.dwattr $C$DW$T$1508, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1508, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1508, DW_AT_decl_line(0x88)
	.dwattr $C$DW$T$1508, DW_AT_decl_column(0x2d)

$C$DW$T$99	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$99, DW_AT_name("xdc_runtime_LoggerSys_TimestampProxy_Fxns__")
	.dwattr $C$DW$T$99, DW_AT_declaration
	.dwendtag $C$DW$T$99

	.dwattr $C$DW$T$99, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$99, DW_AT_decl_line(0x151)
	.dwattr $C$DW$T$99, DW_AT_decl_column(0x10)
$C$DW$T$1509	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_TimestampProxy_Fxns__")
	.dwattr $C$DW$T$1509, DW_AT_type(*$C$DW$T$99)
	.dwattr $C$DW$T$1509, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1509, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1509, DW_AT_decl_line(0x151)
	.dwattr $C$DW$T$1509, DW_AT_decl_column(0x3c)
$C$DW$T$1510	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1510, DW_AT_type(*$C$DW$T$1509)
$C$DW$T$1511	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1511, DW_AT_type(*$C$DW$T$1510)
	.dwattr $C$DW$T$1511, DW_AT_address_class(0x20)
$C$DW$T$1512	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_LoggerSys_TimestampProxy_Module")
	.dwattr $C$DW$T$1512, DW_AT_type(*$C$DW$T$1511)
	.dwattr $C$DW$T$1512, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1512, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1512, DW_AT_decl_line(0x152)
	.dwattr $C$DW$T$1512, DW_AT_decl_column(0x3c)

$C$DW$T$424	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$424, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$424, DW_AT_byte_size(0x24)
$C$DW$794	.dwtag  DW_TAG_member
	.dwattr $C$DW$794, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$794, DW_AT_name("__base")
	.dwattr $C$DW$794, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$794, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$794, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$794, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$794, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$794, DW_AT_decl_column(0x1d)
$C$DW$795	.dwtag  DW_TAG_member
	.dwattr $C$DW$795, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$795, DW_AT_name("__sysp")
	.dwattr $C$DW$795, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$795, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$795, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$795, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$795, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$795, DW_AT_decl_column(0x27)
$C$DW$796	.dwtag  DW_TAG_member
	.dwattr $C$DW$796, DW_AT_type(*$C$DW$T$150)
	.dwattr $C$DW$796, DW_AT_name("query")
	.dwattr $C$DW$796, DW_AT_TI_symbol_name("query")
	.dwattr $C$DW$796, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$796, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$796, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$796, DW_AT_decl_line(0xb1)
	.dwattr $C$DW$796, DW_AT_decl_column(0x10)
$C$DW$797	.dwtag  DW_TAG_member
	.dwattr $C$DW$797, DW_AT_type(*$C$DW$T$421)
	.dwattr $C$DW$797, DW_AT_name("enter")
	.dwattr $C$DW$797, DW_AT_TI_symbol_name("enter")
	.dwattr $C$DW$797, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$797, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$797, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$797, DW_AT_decl_line(0xb2)
	.dwattr $C$DW$797, DW_AT_decl_column(0x10)
$C$DW$798	.dwtag  DW_TAG_member
	.dwattr $C$DW$798, DW_AT_type(*$C$DW$T$423)
	.dwattr $C$DW$798, DW_AT_name("leave")
	.dwattr $C$DW$798, DW_AT_TI_symbol_name("leave")
	.dwattr $C$DW$798, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$798, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$798, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$798, DW_AT_decl_line(0xb3)
	.dwattr $C$DW$798, DW_AT_decl_column(0x10)
$C$DW$799	.dwtag  DW_TAG_member
	.dwattr $C$DW$799, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$799, DW_AT_name("__sfxns")
	.dwattr $C$DW$799, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$799, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$799, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$799, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$799, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$799, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$424

	.dwattr $C$DW$T$424, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$424, DW_AT_decl_line(0xae)
	.dwattr $C$DW$T$424, DW_AT_decl_column(0x08)
$C$DW$T$426	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$426, DW_AT_type(*$C$DW$T$424)
	.dwattr $C$DW$T$426, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$426, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$426, DW_AT_decl_line(0x158)
	.dwattr $C$DW$T$426, DW_AT_decl_column(0x39)
$C$DW$T$427	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$427, DW_AT_type(*$C$DW$T$426)
$C$DW$T$428	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$428, DW_AT_type(*$C$DW$T$427)
	.dwattr $C$DW$T$428, DW_AT_address_class(0x20)
$C$DW$T$1513	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Module")
	.dwattr $C$DW$T$1513, DW_AT_type(*$C$DW$T$428)
	.dwattr $C$DW$T$1513, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1513, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1513, DW_AT_decl_line(0x159)
	.dwattr $C$DW$T$1513, DW_AT_decl_column(0x39)

$C$DW$T$425	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$425, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Params")
	.dwattr $C$DW$T$425, DW_AT_byte_size(0x18)
$C$DW$800	.dwtag  DW_TAG_member
	.dwattr $C$DW$800, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$800, DW_AT_name("__size")
	.dwattr $C$DW$800, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$800, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$800, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$800, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$800, DW_AT_decl_line(0x9b)
	.dwattr $C$DW$800, DW_AT_decl_column(0x0c)
$C$DW$801	.dwtag  DW_TAG_member
	.dwattr $C$DW$801, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$801, DW_AT_name("__self")
	.dwattr $C$DW$801, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$801, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$801, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$801, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$801, DW_AT_decl_line(0x9c)
	.dwattr $C$DW$801, DW_AT_decl_column(0x11)
$C$DW$802	.dwtag  DW_TAG_member
	.dwattr $C$DW$802, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$802, DW_AT_name("__fxns")
	.dwattr $C$DW$802, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$802, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$802, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$802, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$802, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$802, DW_AT_decl_column(0x0b)
$C$DW$803	.dwtag  DW_TAG_member
	.dwattr $C$DW$803, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$803, DW_AT_name("instance")
	.dwattr $C$DW$803, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$803, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$803, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$803, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$803, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$803, DW_AT_decl_column(0x23)
$C$DW$804	.dwtag  DW_TAG_member
	.dwattr $C$DW$804, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$804, DW_AT_name("__iprms")
	.dwattr $C$DW$804, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$804, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$804, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$804, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$804, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$804, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$425

	.dwattr $C$DW$T$425, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$425, DW_AT_decl_line(0x9a)
	.dwattr $C$DW$T$425, DW_AT_decl_column(0x08)
$C$DW$T$1514	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Params")
	.dwattr $C$DW$T$1514, DW_AT_type(*$C$DW$T$425)
	.dwattr $C$DW$T$1514, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1514, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1514, DW_AT_decl_line(0x15a)
	.dwattr $C$DW$T$1514, DW_AT_decl_column(0x39)

$C$DW$T$429	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$429, DW_AT_name("xdc_runtime_Main_Module_GateProxy_Struct")
	.dwattr $C$DW$T$429, DW_AT_byte_size(0x08)
$C$DW$805	.dwtag  DW_TAG_member
	.dwattr $C$DW$805, DW_AT_type(*$C$DW$T$428)
	.dwattr $C$DW$805, DW_AT_name("__fxns")
	.dwattr $C$DW$805, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$805, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$805, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$805, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$805, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$805, DW_AT_decl_column(0x35)
$C$DW$806	.dwtag  DW_TAG_member
	.dwattr $C$DW$806, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$806, DW_AT_name("__name")
	.dwattr $C$DW$806, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$806, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$806, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$806, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$806, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$806, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$429

	.dwattr $C$DW$T$429, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Main_Module_GateProxy.h")
	.dwattr $C$DW$T$429, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$429, DW_AT_decl_column(0x08)

$C$DW$T$439	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$439, DW_AT_name("xdc_runtime_Memory_HeapProxy_Fxns__")
	.dwattr $C$DW$T$439, DW_AT_byte_size(0x28)
$C$DW$807	.dwtag  DW_TAG_member
	.dwattr $C$DW$807, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$807, DW_AT_name("__base")
	.dwattr $C$DW$807, DW_AT_TI_symbol_name("__base")
	.dwattr $C$DW$807, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$807, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$807, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$807, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$807, DW_AT_decl_column(0x1d)
$C$DW$808	.dwtag  DW_TAG_member
	.dwattr $C$DW$808, DW_AT_type(*$C$DW$T$146)
	.dwattr $C$DW$808, DW_AT_name("__sysp")
	.dwattr $C$DW$808, DW_AT_TI_symbol_name("__sysp")
	.dwattr $C$DW$808, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$808, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$808, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$808, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$808, DW_AT_decl_column(0x27)
$C$DW$809	.dwtag  DW_TAG_member
	.dwattr $C$DW$809, DW_AT_type(*$C$DW$T$432)
	.dwattr $C$DW$809, DW_AT_name("alloc")
	.dwattr $C$DW$809, DW_AT_TI_symbol_name("alloc")
	.dwattr $C$DW$809, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$809, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$809, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$809, DW_AT_decl_line(0xab)
	.dwattr $C$DW$809, DW_AT_decl_column(0x0f)
$C$DW$810	.dwtag  DW_TAG_member
	.dwattr $C$DW$810, DW_AT_type(*$C$DW$T$434)
	.dwattr $C$DW$810, DW_AT_name("free")
	.dwattr $C$DW$810, DW_AT_TI_symbol_name("free")
	.dwattr $C$DW$810, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$810, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$810, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$810, DW_AT_decl_line(0xac)
	.dwattr $C$DW$810, DW_AT_decl_column(0x10)
$C$DW$811	.dwtag  DW_TAG_member
	.dwattr $C$DW$811, DW_AT_type(*$C$DW$T$436)
	.dwattr $C$DW$811, DW_AT_name("isBlocking")
	.dwattr $C$DW$811, DW_AT_TI_symbol_name("isBlocking")
	.dwattr $C$DW$811, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$811, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$811, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$811, DW_AT_decl_line(0xad)
	.dwattr $C$DW$811, DW_AT_decl_column(0x10)
$C$DW$812	.dwtag  DW_TAG_member
	.dwattr $C$DW$812, DW_AT_type(*$C$DW$T$438)
	.dwattr $C$DW$812, DW_AT_name("getStats")
	.dwattr $C$DW$812, DW_AT_TI_symbol_name("getStats")
	.dwattr $C$DW$812, DW_AT_data_member_location[DW_OP_plus_uconst 0x14]
	.dwattr $C$DW$812, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$812, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$812, DW_AT_decl_line(0xae)
	.dwattr $C$DW$812, DW_AT_decl_column(0x10)
$C$DW$813	.dwtag  DW_TAG_member
	.dwattr $C$DW$813, DW_AT_type(*$C$DW$T$144)
	.dwattr $C$DW$813, DW_AT_name("__sfxns")
	.dwattr $C$DW$813, DW_AT_TI_symbol_name("__sfxns")
	.dwattr $C$DW$813, DW_AT_data_member_location[DW_OP_plus_uconst 0x18]
	.dwattr $C$DW$813, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$813, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$813, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$813, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$439

	.dwattr $C$DW$T$439, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$439, DW_AT_decl_line(0xa8)
	.dwattr $C$DW$T$439, DW_AT_decl_column(0x08)
$C$DW$T$441	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_HeapProxy_Fxns__")
	.dwattr $C$DW$T$441, DW_AT_type(*$C$DW$T$439)
	.dwattr $C$DW$T$441, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$441, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$441, DW_AT_decl_line(0x161)
	.dwattr $C$DW$T$441, DW_AT_decl_column(0x34)
$C$DW$T$442	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$442, DW_AT_type(*$C$DW$T$441)
$C$DW$T$443	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$443, DW_AT_type(*$C$DW$T$442)
	.dwattr $C$DW$T$443, DW_AT_address_class(0x20)
$C$DW$T$1515	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_HeapProxy_Module")
	.dwattr $C$DW$T$1515, DW_AT_type(*$C$DW$T$443)
	.dwattr $C$DW$T$1515, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1515, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1515, DW_AT_decl_line(0x162)
	.dwattr $C$DW$T$1515, DW_AT_decl_column(0x34)

$C$DW$T$440	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$440, DW_AT_name("xdc_runtime_Memory_HeapProxy_Params")
	.dwattr $C$DW$T$440, DW_AT_byte_size(0x18)
$C$DW$814	.dwtag  DW_TAG_member
	.dwattr $C$DW$814, DW_AT_type(*$C$DW$T$158)
	.dwattr $C$DW$814, DW_AT_name("__size")
	.dwattr $C$DW$814, DW_AT_TI_symbol_name("__size")
	.dwattr $C$DW$814, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$814, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$814, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$814, DW_AT_decl_line(0x95)
	.dwattr $C$DW$814, DW_AT_decl_column(0x0c)
$C$DW$815	.dwtag  DW_TAG_member
	.dwattr $C$DW$815, DW_AT_type(*$C$DW$T$160)
	.dwattr $C$DW$815, DW_AT_name("__self")
	.dwattr $C$DW$815, DW_AT_TI_symbol_name("__self")
	.dwattr $C$DW$815, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$815, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$815, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$815, DW_AT_decl_line(0x96)
	.dwattr $C$DW$815, DW_AT_decl_column(0x11)
$C$DW$816	.dwtag  DW_TAG_member
	.dwattr $C$DW$816, DW_AT_type(*$C$DW$T$3)
	.dwattr $C$DW$816, DW_AT_name("__fxns")
	.dwattr $C$DW$816, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$816, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$816, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$816, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$816, DW_AT_decl_line(0x97)
	.dwattr $C$DW$816, DW_AT_decl_column(0x0b)
$C$DW$817	.dwtag  DW_TAG_member
	.dwattr $C$DW$817, DW_AT_type(*$C$DW$T$162)
	.dwattr $C$DW$817, DW_AT_name("instance")
	.dwattr $C$DW$817, DW_AT_TI_symbol_name("instance")
	.dwattr $C$DW$817, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$817, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$817, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$817, DW_AT_decl_line(0x98)
	.dwattr $C$DW$817, DW_AT_decl_column(0x23)
$C$DW$818	.dwtag  DW_TAG_member
	.dwattr $C$DW$818, DW_AT_type(*$C$DW$T$161)
	.dwattr $C$DW$818, DW_AT_name("__iprms")
	.dwattr $C$DW$818, DW_AT_TI_symbol_name("__iprms")
	.dwattr $C$DW$818, DW_AT_data_member_location[DW_OP_plus_uconst 0x10]
	.dwattr $C$DW$818, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$818, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$818, DW_AT_decl_line(0x99)
	.dwattr $C$DW$818, DW_AT_decl_column(0x22)
	.dwendtag $C$DW$T$440

	.dwattr $C$DW$T$440, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$440, DW_AT_decl_line(0x94)
	.dwattr $C$DW$T$440, DW_AT_decl_column(0x08)
$C$DW$T$1516	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_HeapProxy_Params")
	.dwattr $C$DW$T$1516, DW_AT_type(*$C$DW$T$440)
	.dwattr $C$DW$T$1516, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1516, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1516, DW_AT_decl_line(0x163)
	.dwattr $C$DW$T$1516, DW_AT_decl_column(0x34)

$C$DW$T$444	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$444, DW_AT_name("xdc_runtime_Memory_HeapProxy_Struct")
	.dwattr $C$DW$T$444, DW_AT_byte_size(0x08)
$C$DW$819	.dwtag  DW_TAG_member
	.dwattr $C$DW$819, DW_AT_type(*$C$DW$T$443)
	.dwattr $C$DW$819, DW_AT_name("__fxns")
	.dwattr $C$DW$819, DW_AT_TI_symbol_name("__fxns")
	.dwattr $C$DW$819, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$819, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$819, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$819, DW_AT_decl_line(0x9e)
	.dwattr $C$DW$819, DW_AT_decl_column(0x30)
$C$DW$820	.dwtag  DW_TAG_member
	.dwattr $C$DW$820, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$820, DW_AT_name("__name")
	.dwattr $C$DW$820, DW_AT_TI_symbol_name("__name")
	.dwattr $C$DW$820, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$820, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$820, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$820, DW_AT_decl_line(0x9f)
	.dwattr $C$DW$820, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$444

	.dwattr $C$DW$T$444, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/Memory_HeapProxy.h")
	.dwattr $C$DW$T$444, DW_AT_decl_line(0x9d)
	.dwattr $C$DW$T$444, DW_AT_decl_column(0x08)

$C$DW$T$100	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$100, DW_AT_name("xdc_runtime_Memory_Module_State")
	.dwattr $C$DW$T$100, DW_AT_declaration
	.dwendtag $C$DW$T$100

	.dwattr $C$DW$T$100, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$100, DW_AT_decl_line(0x97)
	.dwattr $C$DW$T$100, DW_AT_decl_column(0x10)
$C$DW$T$1517	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_Module_State")
	.dwattr $C$DW$T$1517, DW_AT_type(*$C$DW$T$100)
	.dwattr $C$DW$T$1517, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1517, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1517, DW_AT_decl_line(0x97)
	.dwattr $C$DW$T$1517, DW_AT_decl_column(0x30)

$C$DW$T$446	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$446, DW_AT_name("xdc_runtime_Memory_Stats")
	.dwattr $C$DW$T$446, DW_AT_byte_size(0x0c)
$C$DW$821	.dwtag  DW_TAG_member
	.dwattr $C$DW$821, DW_AT_type(*$C$DW$T$445)
	.dwattr $C$DW$821, DW_AT_name("totalSize")
	.dwattr $C$DW$821, DW_AT_TI_symbol_name("totalSize")
	.dwattr $C$DW$821, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$821, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$821, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$821, DW_AT_decl_line(0x4a)
	.dwattr $C$DW$821, DW_AT_decl_column(0x1d)
$C$DW$822	.dwtag  DW_TAG_member
	.dwattr $C$DW$822, DW_AT_type(*$C$DW$T$445)
	.dwattr $C$DW$822, DW_AT_name("totalFreeSize")
	.dwattr $C$DW$822, DW_AT_TI_symbol_name("totalFreeSize")
	.dwattr $C$DW$822, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$822, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$822, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$822, DW_AT_decl_line(0x4b)
	.dwattr $C$DW$822, DW_AT_decl_column(0x1d)
$C$DW$823	.dwtag  DW_TAG_member
	.dwattr $C$DW$823, DW_AT_type(*$C$DW$T$445)
	.dwattr $C$DW$823, DW_AT_name("largestFreeSize")
	.dwattr $C$DW$823, DW_AT_TI_symbol_name("largestFreeSize")
	.dwattr $C$DW$823, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$823, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$823, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$823, DW_AT_decl_line(0x4c)
	.dwattr $C$DW$823, DW_AT_decl_column(0x1d)
	.dwendtag $C$DW$T$446

	.dwattr $C$DW$T$446, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Memory.h")
	.dwattr $C$DW$T$446, DW_AT_decl_line(0x49)
	.dwattr $C$DW$T$446, DW_AT_decl_column(0x08)
$C$DW$T$395	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Memory_Stats")
	.dwattr $C$DW$T$395, DW_AT_type(*$C$DW$T$446)
	.dwattr $C$DW$T$395, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$395, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$395, DW_AT_decl_line(0x96)
	.dwattr $C$DW$T$395, DW_AT_decl_column(0x29)
$C$DW$T$396	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$396, DW_AT_type(*$C$DW$T$395)
	.dwattr $C$DW$T$396, DW_AT_address_class(0x20)

$C$DW$T$101	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$101, DW_AT_name("xdc_runtime_Registry_Module_State")
	.dwattr $C$DW$T$101, DW_AT_declaration
	.dwendtag $C$DW$T$101

	.dwattr $C$DW$T$101, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$101, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$101, DW_AT_decl_column(0x10)
$C$DW$T$1518	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Registry_Module_State")
	.dwattr $C$DW$T$1518, DW_AT_type(*$C$DW$T$101)
	.dwattr $C$DW$T$1518, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1518, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1518, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$1518, DW_AT_decl_column(0x32)

$C$DW$T$102	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$102, DW_AT_name("xdc_runtime_Rta_CommandPacket")
	.dwattr $C$DW$T$102, DW_AT_declaration
	.dwendtag $C$DW$T$102

	.dwattr $C$DW$T$102, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$102, DW_AT_decl_line(0xc7)
	.dwattr $C$DW$T$102, DW_AT_decl_column(0x10)
$C$DW$T$1519	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Rta_CommandPacket")
	.dwattr $C$DW$T$1519, DW_AT_type(*$C$DW$T$102)
	.dwattr $C$DW$T$1519, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1519, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1519, DW_AT_decl_line(0xc7)
	.dwattr $C$DW$T$1519, DW_AT_decl_column(0x2e)

$C$DW$T$103	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$103, DW_AT_name("xdc_runtime_Rta_ResponsePacket")
	.dwattr $C$DW$T$103, DW_AT_declaration
	.dwendtag $C$DW$T$103

	.dwattr $C$DW$T$103, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$103, DW_AT_decl_line(0xc8)
	.dwattr $C$DW$T$103, DW_AT_decl_column(0x10)
$C$DW$T$1520	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Rta_ResponsePacket")
	.dwattr $C$DW$T$1520, DW_AT_type(*$C$DW$T$103)
	.dwattr $C$DW$T$1520, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1520, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1520, DW_AT_decl_line(0xc8)
	.dwattr $C$DW$T$1520, DW_AT_decl_column(0x2f)

$C$DW$T$104	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$104, DW_AT_name("xdc_runtime_Startup_IdMap")
	.dwattr $C$DW$T$104, DW_AT_declaration
	.dwendtag $C$DW$T$104

	.dwattr $C$DW$T$104, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$104, DW_AT_decl_line(0xce)
	.dwattr $C$DW$T$104, DW_AT_decl_column(0x10)
$C$DW$T$1521	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Startup_IdMap")
	.dwattr $C$DW$T$1521, DW_AT_type(*$C$DW$T$104)
	.dwattr $C$DW$T$1521, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1521, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1521, DW_AT_decl_line(0xce)
	.dwattr $C$DW$T$1521, DW_AT_decl_column(0x2a)

$C$DW$T$105	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$105, DW_AT_name("xdc_runtime_Startup_Module_State")
	.dwattr $C$DW$T$105, DW_AT_declaration
	.dwendtag $C$DW$T$105

	.dwattr $C$DW$T$105, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$105, DW_AT_decl_line(0xcf)
	.dwattr $C$DW$T$105, DW_AT_decl_column(0x10)
$C$DW$T$1522	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Startup_Module_State")
	.dwattr $C$DW$T$1522, DW_AT_type(*$C$DW$T$105)
	.dwattr $C$DW$T$1522, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1522, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1522, DW_AT_decl_line(0xcf)
	.dwattr $C$DW$T$1522, DW_AT_decl_column(0x31)

$C$DW$T$106	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$106, DW_AT_name("xdc_runtime_SysCallback_Fxns__")
	.dwattr $C$DW$T$106, DW_AT_declaration
	.dwendtag $C$DW$T$106

	.dwattr $C$DW$T$106, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$106, DW_AT_decl_line(0xe3)
	.dwattr $C$DW$T$106, DW_AT_decl_column(0x10)
$C$DW$T$1523	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysCallback_Fxns__")
	.dwattr $C$DW$T$1523, DW_AT_type(*$C$DW$T$106)
	.dwattr $C$DW$T$1523, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1523, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1523, DW_AT_decl_line(0xe3)
	.dwattr $C$DW$T$1523, DW_AT_decl_column(0x2f)
$C$DW$T$1524	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1524, DW_AT_type(*$C$DW$T$1523)
$C$DW$T$1525	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1525, DW_AT_type(*$C$DW$T$1524)
	.dwattr $C$DW$T$1525, DW_AT_address_class(0x20)
$C$DW$T$1526	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysCallback_Module")
	.dwattr $C$DW$T$1526, DW_AT_type(*$C$DW$T$1525)
	.dwattr $C$DW$T$1526, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1526, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1526, DW_AT_decl_line(0xe4)
	.dwattr $C$DW$T$1526, DW_AT_decl_column(0x2f)

$C$DW$T$107	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$107, DW_AT_name("xdc_runtime_SysMin_Fxns__")
	.dwattr $C$DW$T$107, DW_AT_declaration
	.dwendtag $C$DW$T$107

	.dwattr $C$DW$T$107, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$107, DW_AT_decl_line(0xeb)
	.dwattr $C$DW$T$107, DW_AT_decl_column(0x10)
$C$DW$T$1527	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysMin_Fxns__")
	.dwattr $C$DW$T$1527, DW_AT_type(*$C$DW$T$107)
	.dwattr $C$DW$T$1527, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1527, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1527, DW_AT_decl_line(0xeb)
	.dwattr $C$DW$T$1527, DW_AT_decl_column(0x2a)
$C$DW$T$1528	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1528, DW_AT_type(*$C$DW$T$1527)
$C$DW$T$1529	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1529, DW_AT_type(*$C$DW$T$1528)
	.dwattr $C$DW$T$1529, DW_AT_address_class(0x20)
$C$DW$T$1530	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysMin_Module")
	.dwattr $C$DW$T$1530, DW_AT_type(*$C$DW$T$1529)
	.dwattr $C$DW$T$1530, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1530, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1530, DW_AT_decl_line(0xec)
	.dwattr $C$DW$T$1530, DW_AT_decl_column(0x2a)

$C$DW$T$108	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$108, DW_AT_name("xdc_runtime_SysMin_Module_State")
	.dwattr $C$DW$T$108, DW_AT_declaration
	.dwendtag $C$DW$T$108

	.dwattr $C$DW$T$108, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$108, DW_AT_decl_line(0xea)
	.dwattr $C$DW$T$108, DW_AT_decl_column(0x10)
$C$DW$T$1531	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysMin_Module_State")
	.dwattr $C$DW$T$1531, DW_AT_type(*$C$DW$T$108)
	.dwattr $C$DW$T$1531, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1531, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1531, DW_AT_decl_line(0xea)
	.dwattr $C$DW$T$1531, DW_AT_decl_column(0x30)

$C$DW$T$109	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$109, DW_AT_name("xdc_runtime_SysStd_Fxns__")
	.dwattr $C$DW$T$109, DW_AT_declaration
	.dwendtag $C$DW$T$109

	.dwattr $C$DW$T$109, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$109, DW_AT_decl_line(0xf2)
	.dwattr $C$DW$T$109, DW_AT_decl_column(0x10)
$C$DW$T$1532	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysStd_Fxns__")
	.dwattr $C$DW$T$1532, DW_AT_type(*$C$DW$T$109)
	.dwattr $C$DW$T$1532, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1532, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1532, DW_AT_decl_line(0xf2)
	.dwattr $C$DW$T$1532, DW_AT_decl_column(0x2a)
$C$DW$T$1533	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1533, DW_AT_type(*$C$DW$T$1532)
$C$DW$T$1534	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1534, DW_AT_type(*$C$DW$T$1533)
	.dwattr $C$DW$T$1534, DW_AT_address_class(0x20)
$C$DW$T$1535	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_SysStd_Module")
	.dwattr $C$DW$T$1535, DW_AT_type(*$C$DW$T$1534)
	.dwattr $C$DW$T$1535, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1535, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1535, DW_AT_decl_line(0xf3)
	.dwattr $C$DW$T$1535, DW_AT_decl_column(0x2a)

$C$DW$T$110	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$110, DW_AT_name("xdc_runtime_System_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$110, DW_AT_declaration
	.dwendtag $C$DW$T$110

	.dwattr $C$DW$T$110, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$110, DW_AT_decl_line(0x171)
	.dwattr $C$DW$T$110, DW_AT_decl_column(0x10)
$C$DW$T$1536	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_Module_GateProxy_Fxns__")
	.dwattr $C$DW$T$1536, DW_AT_type(*$C$DW$T$110)
	.dwattr $C$DW$T$1536, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1536, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1536, DW_AT_decl_line(0x171)
	.dwattr $C$DW$T$1536, DW_AT_decl_column(0x3b)
$C$DW$T$1537	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1537, DW_AT_type(*$C$DW$T$1536)
$C$DW$T$1538	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1538, DW_AT_type(*$C$DW$T$1537)
	.dwattr $C$DW$T$1538, DW_AT_address_class(0x20)
$C$DW$T$1539	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_Module_GateProxy_Module")
	.dwattr $C$DW$T$1539, DW_AT_type(*$C$DW$T$1538)
	.dwattr $C$DW$T$1539, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1539, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1539, DW_AT_decl_line(0x172)
	.dwattr $C$DW$T$1539, DW_AT_decl_column(0x3b)

$C$DW$T$111	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$111, DW_AT_name("xdc_runtime_System_Module_GateProxy_Params")
	.dwattr $C$DW$T$111, DW_AT_declaration
	.dwendtag $C$DW$T$111

	.dwattr $C$DW$T$111, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$111, DW_AT_decl_line(0x173)
	.dwattr $C$DW$T$111, DW_AT_decl_column(0x10)
$C$DW$T$1540	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_Module_GateProxy_Params")
	.dwattr $C$DW$T$1540, DW_AT_type(*$C$DW$T$111)
	.dwattr $C$DW$T$1540, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1540, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1540, DW_AT_decl_line(0x173)
	.dwattr $C$DW$T$1540, DW_AT_decl_column(0x3b)

$C$DW$T$112	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$112, DW_AT_name("xdc_runtime_System_Module_State")
	.dwattr $C$DW$T$112, DW_AT_declaration
	.dwendtag $C$DW$T$112

	.dwattr $C$DW$T$112, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$112, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$T$112, DW_AT_decl_column(0x10)
$C$DW$T$1541	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_Module_State")
	.dwattr $C$DW$T$1541, DW_AT_type(*$C$DW$T$112)
	.dwattr $C$DW$T$1541, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1541, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1541, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$T$1541, DW_AT_decl_column(0x30)

$C$DW$T$113	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$113, DW_AT_name("xdc_runtime_System_ParseData")
	.dwattr $C$DW$T$113, DW_AT_declaration
	.dwendtag $C$DW$T$113

	.dwattr $C$DW$T$113, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$113, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$113, DW_AT_decl_column(0x10)
$C$DW$T$1542	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_ParseData")
	.dwattr $C$DW$T$1542, DW_AT_type(*$C$DW$T$113)
	.dwattr $C$DW$T$1542, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1542, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1542, DW_AT_decl_line(0xd5)
	.dwattr $C$DW$T$1542, DW_AT_decl_column(0x2d)

$C$DW$T$114	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$114, DW_AT_name("xdc_runtime_System_SupportProxy_Fxns__")
	.dwattr $C$DW$T$114, DW_AT_declaration
	.dwendtag $C$DW$T$114

	.dwattr $C$DW$T$114, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$114, DW_AT_decl_line(0x16a)
	.dwattr $C$DW$T$114, DW_AT_decl_column(0x10)
$C$DW$T$1543	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_SupportProxy_Fxns__")
	.dwattr $C$DW$T$1543, DW_AT_type(*$C$DW$T$114)
	.dwattr $C$DW$T$1543, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1543, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1543, DW_AT_decl_line(0x16a)
	.dwattr $C$DW$T$1543, DW_AT_decl_column(0x37)
$C$DW$T$1544	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1544, DW_AT_type(*$C$DW$T$1543)
$C$DW$T$1545	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1545, DW_AT_type(*$C$DW$T$1544)
	.dwattr $C$DW$T$1545, DW_AT_address_class(0x20)
$C$DW$T$1546	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_System_SupportProxy_Module")
	.dwattr $C$DW$T$1546, DW_AT_type(*$C$DW$T$1545)
	.dwattr $C$DW$T$1546, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1546, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1546, DW_AT_decl_line(0x16b)
	.dwattr $C$DW$T$1546, DW_AT_decl_column(0x37)

$C$DW$T$451	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$451, DW_AT_name("xdc_runtime_Text_MatchVisState")
	.dwattr $C$DW$T$451, DW_AT_byte_size(0x0c)
$C$DW$824	.dwtag  DW_TAG_member
	.dwattr $C$DW$824, DW_AT_type(*$C$DW$T$449)
	.dwattr $C$DW$824, DW_AT_name("pat")
	.dwattr $C$DW$824, DW_AT_TI_symbol_name("pat")
	.dwattr $C$DW$824, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$824, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$824, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$824, DW_AT_decl_line(0x59)
	.dwattr $C$DW$824, DW_AT_decl_column(0x11)
$C$DW$825	.dwtag  DW_TAG_member
	.dwattr $C$DW$825, DW_AT_type(*$C$DW$T$450)
	.dwattr $C$DW$825, DW_AT_name("lenp")
	.dwattr $C$DW$825, DW_AT_TI_symbol_name("lenp")
	.dwattr $C$DW$825, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$825, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$825, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$825, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$825, DW_AT_decl_column(0x0e)
$C$DW$826	.dwtag  DW_TAG_member
	.dwattr $C$DW$826, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$826, DW_AT_name("res")
	.dwattr $C$DW$826, DW_AT_TI_symbol_name("res")
	.dwattr $C$DW$826, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$826, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$826, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$826, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$826, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$451

	.dwattr $C$DW$T$451, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$451, DW_AT_decl_line(0x58)
	.dwattr $C$DW$T$451, DW_AT_decl_column(0x08)
$C$DW$T$1547	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_MatchVisState")
	.dwattr $C$DW$T$1547, DW_AT_type(*$C$DW$T$451)
	.dwattr $C$DW$T$1547, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1547, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1547, DW_AT_decl_line(0xfa)
	.dwattr $C$DW$T$1547, DW_AT_decl_column(0x2f)

$C$DW$T$115	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$115, DW_AT_name("xdc_runtime_Text_Module_State")
	.dwattr $C$DW$T$115, DW_AT_declaration
	.dwendtag $C$DW$T$115

	.dwattr $C$DW$T$115, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$115, DW_AT_decl_line(0xfc)
	.dwattr $C$DW$T$115, DW_AT_decl_column(0x10)
$C$DW$T$1548	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_Module_State")
	.dwattr $C$DW$T$1548, DW_AT_type(*$C$DW$T$115)
	.dwattr $C$DW$T$1548, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1548, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1548, DW_AT_decl_line(0xfc)
	.dwattr $C$DW$T$1548, DW_AT_decl_column(0x2e)

$C$DW$T$453	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$453, DW_AT_name("xdc_runtime_Text_Node")
	.dwattr $C$DW$T$453, DW_AT_byte_size(0x04)
$C$DW$827	.dwtag  DW_TAG_member
	.dwattr $C$DW$827, DW_AT_type(*$C$DW$T$452)
	.dwattr $C$DW$827, DW_AT_name("left")
	.dwattr $C$DW$827, DW_AT_TI_symbol_name("left")
	.dwattr $C$DW$827, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$827, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$827, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$827, DW_AT_decl_line(0x50)
	.dwattr $C$DW$827, DW_AT_decl_column(0x1e)
$C$DW$828	.dwtag  DW_TAG_member
	.dwattr $C$DW$828, DW_AT_type(*$C$DW$T$452)
	.dwattr $C$DW$828, DW_AT_name("right")
	.dwattr $C$DW$828, DW_AT_TI_symbol_name("right")
	.dwattr $C$DW$828, DW_AT_data_member_location[DW_OP_plus_uconst 0x2]
	.dwattr $C$DW$828, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$828, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$828, DW_AT_decl_line(0x51)
	.dwattr $C$DW$828, DW_AT_decl_column(0x1e)
	.dwendtag $C$DW$T$453

	.dwattr $C$DW$T$453, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$453, DW_AT_decl_line(0x4f)
	.dwattr $C$DW$T$453, DW_AT_decl_column(0x08)
$C$DW$T$1549	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_Node")
	.dwattr $C$DW$T$1549, DW_AT_type(*$C$DW$T$453)
	.dwattr $C$DW$T$1549, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1549, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1549, DW_AT_decl_line(0xf9)
	.dwattr $C$DW$T$1549, DW_AT_decl_column(0x26)
$C$DW$T$1550	.dwtag  DW_TAG_typedef, DW_AT_name("__T1_xdc_runtime_Text_nodeTab")
	.dwattr $C$DW$T$1550, DW_AT_type(*$C$DW$T$1549)
	.dwattr $C$DW$T$1550, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1550, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1550, DW_AT_decl_line(0xda)
	.dwattr $C$DW$T$1550, DW_AT_decl_column(0x1f)
$C$DW$T$1551	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1551, DW_AT_type(*$C$DW$T$1549)
	.dwattr $C$DW$T$1551, DW_AT_address_class(0x20)
$C$DW$T$1552	.dwtag  DW_TAG_typedef, DW_AT_name("__ARRAY1_xdc_runtime_Text_nodeTab")
	.dwattr $C$DW$T$1552, DW_AT_type(*$C$DW$T$1551)
	.dwattr $C$DW$T$1552, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1552, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1552, DW_AT_decl_line(0xdb)
	.dwattr $C$DW$T$1552, DW_AT_decl_column(0x20)
$C$DW$T$1553	.dwtag  DW_TAG_typedef, DW_AT_name("__TA_xdc_runtime_Text_nodeTab")
	.dwattr $C$DW$T$1553, DW_AT_type(*$C$DW$T$1552)
	.dwattr $C$DW$T$1553, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1553, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1553, DW_AT_decl_line(0xdc)
	.dwattr $C$DW$T$1553, DW_AT_decl_column(0x2b)
$C$DW$T$1554	.dwtag  DW_TAG_typedef, DW_AT_name("CT__xdc_runtime_Text_nodeTab")
	.dwattr $C$DW$T$1554, DW_AT_type(*$C$DW$T$1553)
	.dwattr $C$DW$T$1554, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1554, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1554, DW_AT_decl_line(0xdd)
	.dwattr $C$DW$T$1554, DW_AT_decl_column(0x27)

$C$DW$T$455	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$455, DW_AT_name("xdc_runtime_Text_PrintVisState")
	.dwattr $C$DW$T$455, DW_AT_byte_size(0x0c)
$C$DW$829	.dwtag  DW_TAG_member
	.dwattr $C$DW$829, DW_AT_type(*$C$DW$T$454)
	.dwattr $C$DW$829, DW_AT_name("bufp")
	.dwattr $C$DW$829, DW_AT_TI_symbol_name("bufp")
	.dwattr $C$DW$829, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$829, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$829, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$829, DW_AT_decl_line(0x60)
	.dwattr $C$DW$829, DW_AT_decl_column(0x10)
$C$DW$830	.dwtag  DW_TAG_member
	.dwattr $C$DW$830, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$830, DW_AT_name("len")
	.dwattr $C$DW$830, DW_AT_TI_symbol_name("len")
	.dwattr $C$DW$830, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$830, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$830, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$830, DW_AT_decl_line(0x61)
	.dwattr $C$DW$830, DW_AT_decl_column(0x0d)
$C$DW$831	.dwtag  DW_TAG_member
	.dwattr $C$DW$831, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$831, DW_AT_name("res")
	.dwattr $C$DW$831, DW_AT_TI_symbol_name("res")
	.dwattr $C$DW$831, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$831, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$831, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$831, DW_AT_decl_line(0x62)
	.dwattr $C$DW$831, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$455

	.dwattr $C$DW$T$455, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$455, DW_AT_decl_line(0x5f)
	.dwattr $C$DW$T$455, DW_AT_decl_column(0x08)
$C$DW$T$1555	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_PrintVisState")
	.dwattr $C$DW$T$1555, DW_AT_type(*$C$DW$T$455)
	.dwattr $C$DW$T$1555, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1555, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1555, DW_AT_decl_line(0xfb)
	.dwattr $C$DW$T$1555, DW_AT_decl_column(0x2f)

$C$DW$T$116	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$116, DW_AT_name("xdc_runtime_TimestampNull_Fxns__")
	.dwattr $C$DW$T$116, DW_AT_declaration
	.dwendtag $C$DW$T$116

	.dwattr $C$DW$T$116, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$116, DW_AT_decl_line(0x117)
	.dwattr $C$DW$T$116, DW_AT_decl_column(0x10)
$C$DW$T$1556	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_TimestampNull_Fxns__")
	.dwattr $C$DW$T$1556, DW_AT_type(*$C$DW$T$116)
	.dwattr $C$DW$T$1556, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1556, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1556, DW_AT_decl_line(0x117)
	.dwattr $C$DW$T$1556, DW_AT_decl_column(0x31)
$C$DW$T$1557	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1557, DW_AT_type(*$C$DW$T$1556)
$C$DW$T$1558	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1558, DW_AT_type(*$C$DW$T$1557)
	.dwattr $C$DW$T$1558, DW_AT_address_class(0x20)
$C$DW$T$1559	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_TimestampNull_Module")
	.dwattr $C$DW$T$1559, DW_AT_type(*$C$DW$T$1558)
	.dwattr $C$DW$T$1559, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1559, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1559, DW_AT_decl_line(0x118)
	.dwattr $C$DW$T$1559, DW_AT_decl_column(0x31)

$C$DW$T$117	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$117, DW_AT_name("xdc_runtime_TimestampStd_Fxns__")
	.dwattr $C$DW$T$117, DW_AT_declaration
	.dwendtag $C$DW$T$117

	.dwattr $C$DW$T$117, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$117, DW_AT_decl_line(0x11e)
	.dwattr $C$DW$T$117, DW_AT_decl_column(0x10)
$C$DW$T$1560	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_TimestampStd_Fxns__")
	.dwattr $C$DW$T$1560, DW_AT_type(*$C$DW$T$117)
	.dwattr $C$DW$T$1560, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1560, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1560, DW_AT_decl_line(0x11e)
	.dwattr $C$DW$T$1560, DW_AT_decl_column(0x30)
$C$DW$T$1561	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1561, DW_AT_type(*$C$DW$T$1560)
$C$DW$T$1562	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1562, DW_AT_type(*$C$DW$T$1561)
	.dwattr $C$DW$T$1562, DW_AT_address_class(0x20)
$C$DW$T$1563	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_TimestampStd_Module")
	.dwattr $C$DW$T$1563, DW_AT_type(*$C$DW$T$1562)
	.dwattr $C$DW$T$1563, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1563, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1563, DW_AT_decl_line(0x11f)
	.dwattr $C$DW$T$1563, DW_AT_decl_column(0x30)

$C$DW$T$118	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$118, DW_AT_name("xdc_runtime_Timestamp_Fxns__")
	.dwattr $C$DW$T$118, DW_AT_declaration
	.dwendtag $C$DW$T$118

	.dwattr $C$DW$T$118, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$118, DW_AT_decl_line(0x109)
	.dwattr $C$DW$T$118, DW_AT_decl_column(0x10)
$C$DW$T$1564	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Timestamp_Fxns__")
	.dwattr $C$DW$T$1564, DW_AT_type(*$C$DW$T$118)
	.dwattr $C$DW$T$1564, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1564, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1564, DW_AT_decl_line(0x109)
	.dwattr $C$DW$T$1564, DW_AT_decl_column(0x2d)
$C$DW$T$1565	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1565, DW_AT_type(*$C$DW$T$1564)
$C$DW$T$1566	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1566, DW_AT_type(*$C$DW$T$1565)
	.dwattr $C$DW$T$1566, DW_AT_address_class(0x20)
$C$DW$T$1567	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Timestamp_Module")
	.dwattr $C$DW$T$1567, DW_AT_type(*$C$DW$T$1566)
	.dwattr $C$DW$T$1567, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1567, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1567, DW_AT_decl_line(0x10a)
	.dwattr $C$DW$T$1567, DW_AT_decl_column(0x2d)

$C$DW$T$119	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$119, DW_AT_name("xdc_runtime_Timestamp_SupportProxy_Fxns__")
	.dwattr $C$DW$T$119, DW_AT_declaration
	.dwendtag $C$DW$T$119

	.dwattr $C$DW$T$119, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$119, DW_AT_decl_line(0x17a)
	.dwattr $C$DW$T$119, DW_AT_decl_column(0x10)
$C$DW$T$1568	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Timestamp_SupportProxy_Fxns__")
	.dwattr $C$DW$T$1568, DW_AT_type(*$C$DW$T$119)
	.dwattr $C$DW$T$1568, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1568, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1568, DW_AT_decl_line(0x17a)
	.dwattr $C$DW$T$1568, DW_AT_decl_column(0x3a)
$C$DW$T$1569	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$1569, DW_AT_type(*$C$DW$T$1568)
$C$DW$T$1570	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1570, DW_AT_type(*$C$DW$T$1569)
	.dwattr $C$DW$T$1570, DW_AT_address_class(0x20)
$C$DW$T$1571	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Timestamp_SupportProxy_Module")
	.dwattr $C$DW$T$1571, DW_AT_type(*$C$DW$T$1570)
	.dwattr $C$DW$T$1571, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1571, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1571, DW_AT_decl_line(0x17b)
	.dwattr $C$DW$T$1571, DW_AT_decl_column(0x3a)

$C$DW$T$456	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$456, DW_AT_name("xdc_runtime_Types_Base")
	.dwattr $C$DW$T$456, DW_AT_byte_size(0x04)
$C$DW$832	.dwtag  DW_TAG_member
	.dwattr $C$DW$832, DW_AT_type(*$C$DW$T$143)
	.dwattr $C$DW$832, DW_AT_name("base")
	.dwattr $C$DW$832, DW_AT_TI_symbol_name("base")
	.dwattr $C$DW$832, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$832, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$832, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$832, DW_AT_decl_line(0xbd)
	.dwattr $C$DW$832, DW_AT_decl_column(0x1d)
	.dwendtag $C$DW$T$456

	.dwattr $C$DW$T$456, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$456, DW_AT_decl_line(0xbc)
	.dwattr $C$DW$T$456, DW_AT_decl_column(0x08)
$C$DW$T$142	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Base")
	.dwattr $C$DW$T$142, DW_AT_type(*$C$DW$T$456)
	.dwattr $C$DW$T$142, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$142, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$142, DW_AT_decl_line(0x130)
	.dwattr $C$DW$T$142, DW_AT_decl_column(0x27)
$C$DW$T$143	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$143, DW_AT_type(*$C$DW$T$142)
	.dwattr $C$DW$T$143, DW_AT_address_class(0x20)

$C$DW$T$120	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$120, DW_AT_name("xdc_runtime_Types_CordAddr__")
	.dwattr $C$DW$T$120, DW_AT_declaration
	.dwendtag $C$DW$T$120

	.dwattr $C$DW$T$120, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$120, DW_AT_decl_line(0x125)
	.dwattr $C$DW$T$120, DW_AT_decl_column(0x10)
$C$DW$T$167	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_CordAddr__")
	.dwattr $C$DW$T$167, DW_AT_type(*$C$DW$T$120)
	.dwattr $C$DW$T$167, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$167, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$167, DW_AT_decl_line(0x125)
	.dwattr $C$DW$T$167, DW_AT_decl_column(0x2d)
$C$DW$T$168	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$168, DW_AT_type(*$C$DW$T$167)
	.dwattr $C$DW$T$168, DW_AT_address_class(0x20)
$C$DW$T$169	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_CordAddr")
	.dwattr $C$DW$T$169, DW_AT_type(*$C$DW$T$168)
	.dwattr $C$DW$T$169, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$169, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$169, DW_AT_decl_line(0x4d)
	.dwattr $C$DW$T$169, DW_AT_decl_column(0x27)
$C$DW$T$1572	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_CordAddr")
	.dwattr $C$DW$T$1572, DW_AT_type(*$C$DW$T$169)
	.dwattr $C$DW$T$1572, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1572, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1572, DW_AT_decl_line(0x41)
	.dwattr $C$DW$T$1572, DW_AT_decl_column(0x24)

$C$DW$T$1573	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1573, DW_AT_name("xdc_runtime_Types_CreatePolicy")
	.dwattr $C$DW$T$1573, DW_AT_byte_size(0x01)
$C$DW$833	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_STATIC_POLICY"), DW_AT_const_value(0x00)
	.dwattr $C$DW$833, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$833, DW_AT_decl_line(0x5a)
	.dwattr $C$DW$833, DW_AT_decl_column(0x05)
$C$DW$834	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_CREATE_POLICY"), DW_AT_const_value(0x01)
	.dwattr $C$DW$834, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$834, DW_AT_decl_line(0x5b)
	.dwattr $C$DW$834, DW_AT_decl_column(0x05)
$C$DW$835	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_DELETE_POLICY"), DW_AT_const_value(0x02)
	.dwattr $C$DW$835, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$835, DW_AT_decl_line(0x5c)
	.dwattr $C$DW$835, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1573

	.dwattr $C$DW$T$1573, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1573, DW_AT_decl_line(0x59)
	.dwattr $C$DW$T$1573, DW_AT_decl_column(0x06)
$C$DW$T$1574	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_CreatePolicy")
	.dwattr $C$DW$T$1574, DW_AT_type(*$C$DW$T$1573)
	.dwattr $C$DW$T$1574, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1574, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1574, DW_AT_decl_line(0x5e)
	.dwattr $C$DW$T$1574, DW_AT_decl_column(0x2d)

$C$DW$T$457	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$457, DW_AT_name("xdc_runtime_Types_FreqHz")
	.dwattr $C$DW$T$457, DW_AT_byte_size(0x08)
$C$DW$836	.dwtag  DW_TAG_member
	.dwattr $C$DW$836, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$836, DW_AT_name("hi")
	.dwattr $C$DW$836, DW_AT_TI_symbol_name("hi")
	.dwattr $C$DW$836, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$836, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$836, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$836, DW_AT_decl_line(0x7f)
	.dwattr $C$DW$836, DW_AT_decl_column(0x10)
$C$DW$837	.dwtag  DW_TAG_member
	.dwattr $C$DW$837, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$837, DW_AT_name("lo")
	.dwattr $C$DW$837, DW_AT_TI_symbol_name("lo")
	.dwattr $C$DW$837, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$837, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$837, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$837, DW_AT_decl_line(0x80)
	.dwattr $C$DW$837, DW_AT_decl_column(0x10)
	.dwendtag $C$DW$T$457

	.dwattr $C$DW$T$457, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$457, DW_AT_decl_line(0x7e)
	.dwattr $C$DW$T$457, DW_AT_decl_column(0x08)
$C$DW$T$222	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_FreqHz")
	.dwattr $C$DW$T$222, DW_AT_type(*$C$DW$T$457)
	.dwattr $C$DW$T$222, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$222, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$222, DW_AT_decl_line(0x12a)
	.dwattr $C$DW$T$222, DW_AT_decl_column(0x29)
$C$DW$T$1575	.dwtag  DW_TAG_typedef, DW_AT_name("CT__ti_sysbios_BIOS_cpuFreq")
	.dwattr $C$DW$T$1575, DW_AT_type(*$C$DW$T$222)
	.dwattr $C$DW$T$1575, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1575, DW_AT_decl_file("C:/ti/tirtos_tivac_2_00_02_36/products/bios_6_40_02_27/packages/ti/sysbios/BIOS.h")
	.dwattr $C$DW$T$1575, DW_AT_decl_line(0xd6)
	.dwattr $C$DW$T$1575, DW_AT_decl_column(0x22)
$C$DW$T$223	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$223, DW_AT_type(*$C$DW$T$222)
	.dwattr $C$DW$T$223, DW_AT_address_class(0x20)

$C$DW$T$121	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$121, DW_AT_name("xdc_runtime_Types_GateRef__")
	.dwattr $C$DW$T$121, DW_AT_declaration
	.dwendtag $C$DW$T$121

	.dwattr $C$DW$T$121, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$121, DW_AT_decl_line(0x126)
	.dwattr $C$DW$T$121, DW_AT_decl_column(0x10)
$C$DW$T$1576	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_GateRef__")
	.dwattr $C$DW$T$1576, DW_AT_type(*$C$DW$T$121)
	.dwattr $C$DW$T$1576, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1576, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1576, DW_AT_decl_line(0x126)
	.dwattr $C$DW$T$1576, DW_AT_decl_column(0x2c)
$C$DW$T$1577	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$1577, DW_AT_type(*$C$DW$T$1576)
	.dwattr $C$DW$T$1577, DW_AT_address_class(0x20)
$C$DW$T$1578	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_GateRef")
	.dwattr $C$DW$T$1578, DW_AT_type(*$C$DW$T$1577)
	.dwattr $C$DW$T$1578, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1578, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1578, DW_AT_decl_line(0x53)
	.dwattr $C$DW$T$1578, DW_AT_decl_column(0x26)

$C$DW$T$459	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$459, DW_AT_name("xdc_runtime_Types_InstHdr")
	.dwattr $C$DW$T$459, DW_AT_byte_size(0x08)
$C$DW$838	.dwtag  DW_TAG_member
	.dwattr $C$DW$838, DW_AT_type(*$C$DW$T$458)
	.dwattr $C$DW$838, DW_AT_name("link")
	.dwattr $C$DW$838, DW_AT_TI_symbol_name("link")
	.dwattr $C$DW$838, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$838, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$838, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$838, DW_AT_decl_line(0xb0)
	.dwattr $C$DW$838, DW_AT_decl_column(0x1c)
	.dwendtag $C$DW$T$459

	.dwattr $C$DW$T$459, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$459, DW_AT_decl_line(0xaf)
	.dwattr $C$DW$T$459, DW_AT_decl_column(0x08)
$C$DW$T$1579	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_InstHdr")
	.dwattr $C$DW$T$1579, DW_AT_type(*$C$DW$T$459)
	.dwattr $C$DW$T$1579, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1579, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1579, DW_AT_decl_line(0x12e)
	.dwattr $C$DW$T$1579, DW_AT_decl_column(0x2a)

$C$DW$T$460	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$460, DW_AT_name("xdc_runtime_Types_Label")
	.dwattr $C$DW$T$460, DW_AT_byte_size(0x10)
$C$DW$839	.dwtag  DW_TAG_member
	.dwattr $C$DW$839, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$839, DW_AT_name("handle")
	.dwattr $C$DW$839, DW_AT_TI_symbol_name("handle")
	.dwattr $C$DW$839, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$839, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$839, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$839, DW_AT_decl_line(0x6a)
	.dwattr $C$DW$839, DW_AT_decl_column(0x0d)
$C$DW$840	.dwtag  DW_TAG_member
	.dwattr $C$DW$840, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$840, DW_AT_name("modId")
	.dwattr $C$DW$840, DW_AT_TI_symbol_name("modId")
	.dwattr $C$DW$840, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$840, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$840, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$840, DW_AT_decl_line(0x6b)
	.dwattr $C$DW$840, DW_AT_decl_column(0x20)
$C$DW$841	.dwtag  DW_TAG_member
	.dwattr $C$DW$841, DW_AT_type(*$C$DW$T$367)
	.dwattr $C$DW$841, DW_AT_name("iname")
	.dwattr $C$DW$841, DW_AT_TI_symbol_name("iname")
	.dwattr $C$DW$841, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$841, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$841, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$841, DW_AT_decl_line(0x6c)
	.dwattr $C$DW$841, DW_AT_decl_column(0x10)
$C$DW$842	.dwtag  DW_TAG_member
	.dwattr $C$DW$842, DW_AT_type(*$C$DW$T$147)
	.dwattr $C$DW$842, DW_AT_name("named")
	.dwattr $C$DW$842, DW_AT_TI_symbol_name("named")
	.dwattr $C$DW$842, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$842, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$842, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$842, DW_AT_decl_line(0x6d)
	.dwattr $C$DW$842, DW_AT_decl_column(0x0e)
	.dwendtag $C$DW$T$460

	.dwattr $C$DW$T$460, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$460, DW_AT_decl_line(0x69)
	.dwattr $C$DW$T$460, DW_AT_decl_column(0x08)
$C$DW$T$473	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Label")
	.dwattr $C$DW$T$473, DW_AT_type(*$C$DW$T$460)
	.dwattr $C$DW$T$473, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$473, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$473, DW_AT_decl_line(0x127)
	.dwattr $C$DW$T$473, DW_AT_decl_column(0x28)
$C$DW$T$474	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$474, DW_AT_type(*$C$DW$T$473)
	.dwattr $C$DW$T$474, DW_AT_address_class(0x20)

$C$DW$T$475	.dwtag  DW_TAG_subroutine_type
	.dwattr $C$DW$T$475, DW_AT_type(*$C$DW$T$474)
	.dwattr $C$DW$T$475, DW_AT_language(DW_LANG_C)
$C$DW$843	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$843, DW_AT_type(*$C$DW$T$177)
$C$DW$844	.dwtag  DW_TAG_formal_parameter
	.dwattr $C$DW$844, DW_AT_type(*$C$DW$T$474)
	.dwendtag $C$DW$T$475

$C$DW$T$476	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$476, DW_AT_type(*$C$DW$T$475)
	.dwattr $C$DW$T$476, DW_AT_address_class(0x20)
$C$DW$T$1580	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Text_Label")
	.dwattr $C$DW$T$1580, DW_AT_type(*$C$DW$T$473)
	.dwattr $C$DW$T$1580, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1580, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Text.h")
	.dwattr $C$DW$T$1580, DW_AT_decl_line(0x44)
	.dwattr $C$DW$T$1580, DW_AT_decl_column(0x21)

$C$DW$T$462	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$462, DW_AT_name("xdc_runtime_Types_Link")
	.dwattr $C$DW$T$462, DW_AT_byte_size(0x08)
$C$DW$845	.dwtag  DW_TAG_member
	.dwattr $C$DW$845, DW_AT_type(*$C$DW$T$461)
	.dwattr $C$DW$845, DW_AT_name("next")
	.dwattr $C$DW$845, DW_AT_TI_symbol_name("next")
	.dwattr $C$DW$845, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$845, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$845, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$845, DW_AT_decl_line(0xaa)
	.dwattr $C$DW$845, DW_AT_decl_column(0x1d)
$C$DW$846	.dwtag  DW_TAG_member
	.dwattr $C$DW$846, DW_AT_type(*$C$DW$T$461)
	.dwattr $C$DW$846, DW_AT_name("prev")
	.dwattr $C$DW$846, DW_AT_TI_symbol_name("prev")
	.dwattr $C$DW$846, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$846, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$846, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$846, DW_AT_decl_line(0xab)
	.dwattr $C$DW$846, DW_AT_decl_column(0x1d)
	.dwendtag $C$DW$T$462

	.dwattr $C$DW$T$462, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$462, DW_AT_decl_line(0xa9)
	.dwattr $C$DW$T$462, DW_AT_decl_column(0x08)
$C$DW$T$458	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Link")
	.dwattr $C$DW$T$458, DW_AT_type(*$C$DW$T$462)
	.dwattr $C$DW$T$458, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$458, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$458, DW_AT_decl_line(0x12d)
	.dwattr $C$DW$T$458, DW_AT_decl_column(0x27)
$C$DW$T$461	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$461, DW_AT_type(*$C$DW$T$458)
	.dwattr $C$DW$T$461, DW_AT_address_class(0x20)

$C$DW$T$1581	.dwtag  DW_TAG_enumeration_type
	.dwattr $C$DW$T$1581, DW_AT_name("xdc_runtime_Types_OutputPolicy")
	.dwattr $C$DW$T$1581, DW_AT_byte_size(0x01)
$C$DW$847	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_COMMON_FILE"), DW_AT_const_value(0x00)
	.dwattr $C$DW$847, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$847, DW_AT_decl_line(0x62)
	.dwattr $C$DW$847, DW_AT_decl_column(0x05)
$C$DW$848	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_SEPARATE_FILE"), DW_AT_const_value(0x01)
	.dwattr $C$DW$848, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$848, DW_AT_decl_line(0x63)
	.dwattr $C$DW$848, DW_AT_decl_column(0x05)
$C$DW$849	.dwtag  DW_TAG_enumerator, DW_AT_name("xdc_runtime_Types_NO_FILE"), DW_AT_const_value(0x02)
	.dwattr $C$DW$849, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$849, DW_AT_decl_line(0x64)
	.dwattr $C$DW$849, DW_AT_decl_column(0x05)
	.dwendtag $C$DW$T$1581

	.dwattr $C$DW$T$1581, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1581, DW_AT_decl_line(0x61)
	.dwattr $C$DW$T$1581, DW_AT_decl_column(0x06)
$C$DW$T$1582	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_OutputPolicy")
	.dwattr $C$DW$T$1582, DW_AT_type(*$C$DW$T$1581)
	.dwattr $C$DW$T$1582, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1582, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$1582, DW_AT_decl_line(0x66)
	.dwattr $C$DW$T$1582, DW_AT_decl_column(0x2d)

$C$DW$T$463	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$463, DW_AT_name("xdc_runtime_Types_PrmsHdr")
	.dwattr $C$DW$T$463, DW_AT_byte_size(0x10)
$C$DW$850	.dwtag  DW_TAG_member
	.dwattr $C$DW$850, DW_AT_type(*$C$DW$T$191)
	.dwattr $C$DW$850, DW_AT_name("size")
	.dwattr $C$DW$850, DW_AT_TI_symbol_name("size")
	.dwattr $C$DW$850, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$850, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$850, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$850, DW_AT_decl_line(0xb5)
	.dwattr $C$DW$850, DW_AT_decl_column(0x0f)
$C$DW$851	.dwtag  DW_TAG_member
	.dwattr $C$DW$851, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$851, DW_AT_name("self")
	.dwattr $C$DW$851, DW_AT_TI_symbol_name("self")
	.dwattr $C$DW$851, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$851, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$851, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$851, DW_AT_decl_line(0xb6)
	.dwattr $C$DW$851, DW_AT_decl_column(0x0d)
$C$DW$852	.dwtag  DW_TAG_member
	.dwattr $C$DW$852, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$852, DW_AT_name("modFxns")
	.dwattr $C$DW$852, DW_AT_TI_symbol_name("modFxns")
	.dwattr $C$DW$852, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$852, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$852, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$852, DW_AT_decl_line(0xb7)
	.dwattr $C$DW$852, DW_AT_decl_column(0x0d)
$C$DW$853	.dwtag  DW_TAG_member
	.dwattr $C$DW$853, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$853, DW_AT_name("instPrms")
	.dwattr $C$DW$853, DW_AT_TI_symbol_name("instPrms")
	.dwattr $C$DW$853, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$853, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$853, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$853, DW_AT_decl_line(0xb8)
	.dwattr $C$DW$853, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$463

	.dwattr $C$DW$T$463, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$463, DW_AT_decl_line(0xb4)
	.dwattr $C$DW$T$463, DW_AT_decl_column(0x08)
$C$DW$T$1583	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_PrmsHdr")
	.dwattr $C$DW$T$1583, DW_AT_type(*$C$DW$T$463)
	.dwattr $C$DW$T$1583, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1583, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1583, DW_AT_decl_line(0x12f)
	.dwattr $C$DW$T$1583, DW_AT_decl_column(0x2a)

$C$DW$T$466	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$466, DW_AT_name("xdc_runtime_Types_RegDesc")
	.dwattr $C$DW$T$466, DW_AT_byte_size(0x0c)
$C$DW$854	.dwtag  DW_TAG_member
	.dwattr $C$DW$854, DW_AT_type(*$C$DW$T$465)
	.dwattr $C$DW$854, DW_AT_name("next")
	.dwattr $C$DW$854, DW_AT_TI_symbol_name("next")
	.dwattr $C$DW$854, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$854, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$854, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$854, DW_AT_decl_line(0x85)
	.dwattr $C$DW$854, DW_AT_decl_column(0x20)
$C$DW$855	.dwtag  DW_TAG_member
	.dwattr $C$DW$855, DW_AT_type(*$C$DW$T$449)
	.dwattr $C$DW$855, DW_AT_name("modName")
	.dwattr $C$DW$855, DW_AT_TI_symbol_name("modName")
	.dwattr $C$DW$855, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$855, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$855, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$855, DW_AT_decl_line(0x86)
	.dwattr $C$DW$855, DW_AT_decl_column(0x11)
$C$DW$856	.dwtag  DW_TAG_member
	.dwattr $C$DW$856, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$856, DW_AT_name("id")
	.dwattr $C$DW$856, DW_AT_TI_symbol_name("id")
	.dwattr $C$DW$856, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$856, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$856, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$856, DW_AT_decl_line(0x87)
	.dwattr $C$DW$856, DW_AT_decl_column(0x20)
$C$DW$857	.dwtag  DW_TAG_member
	.dwattr $C$DW$857, DW_AT_type(*$C$DW$T$360)
	.dwattr $C$DW$857, DW_AT_name("mask")
	.dwattr $C$DW$857, DW_AT_TI_symbol_name("mask")
	.dwattr $C$DW$857, DW_AT_data_member_location[DW_OP_plus_uconst 0xa]
	.dwattr $C$DW$857, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$857, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$857, DW_AT_decl_line(0x88)
	.dwattr $C$DW$857, DW_AT_decl_column(0x21)
	.dwendtag $C$DW$T$466

	.dwattr $C$DW$T$466, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$466, DW_AT_decl_line(0x84)
	.dwattr $C$DW$T$466, DW_AT_decl_column(0x08)
$C$DW$T$464	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_RegDesc")
	.dwattr $C$DW$T$464, DW_AT_type(*$C$DW$T$466)
	.dwattr $C$DW$T$464, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$464, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$464, DW_AT_decl_line(0x12b)
	.dwattr $C$DW$T$464, DW_AT_decl_column(0x2a)
$C$DW$T$465	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$465, DW_AT_type(*$C$DW$T$464)
	.dwattr $C$DW$T$465, DW_AT_address_class(0x20)

$C$DW$T$467	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$467, DW_AT_name("xdc_runtime_Types_Site")
	.dwattr $C$DW$T$467, DW_AT_byte_size(0x0c)
$C$DW$858	.dwtag  DW_TAG_member
	.dwattr $C$DW$858, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$858, DW_AT_name("mod")
	.dwattr $C$DW$858, DW_AT_TI_symbol_name("mod")
	.dwattr $C$DW$858, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$858, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$858, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$858, DW_AT_decl_line(0x72)
	.dwattr $C$DW$858, DW_AT_decl_column(0x20)
$C$DW$859	.dwtag  DW_TAG_member
	.dwattr $C$DW$859, DW_AT_type(*$C$DW$T$449)
	.dwattr $C$DW$859, DW_AT_name("file")
	.dwattr $C$DW$859, DW_AT_TI_symbol_name("file")
	.dwattr $C$DW$859, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$859, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$859, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$859, DW_AT_decl_line(0x73)
	.dwattr $C$DW$859, DW_AT_decl_column(0x11)
$C$DW$860	.dwtag  DW_TAG_member
	.dwattr $C$DW$860, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$860, DW_AT_name("line")
	.dwattr $C$DW$860, DW_AT_TI_symbol_name("line")
	.dwattr $C$DW$860, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$860, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$860, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$860, DW_AT_decl_line(0x74)
	.dwattr $C$DW$860, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$467

	.dwattr $C$DW$T$467, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$467, DW_AT_decl_line(0x71)
	.dwattr $C$DW$T$467, DW_AT_decl_column(0x08)
$C$DW$T$368	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Site")
	.dwattr $C$DW$T$368, DW_AT_type(*$C$DW$T$467)
	.dwattr $C$DW$T$368, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$368, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$368, DW_AT_decl_line(0x128)
	.dwattr $C$DW$T$368, DW_AT_decl_column(0x27)

$C$DW$T$477	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$477, DW_AT_name("xdc_runtime_Types_SysFxns")
	.dwattr $C$DW$T$477, DW_AT_byte_size(0x10)
$C$DW$861	.dwtag  DW_TAG_member
	.dwattr $C$DW$861, DW_AT_type(*$C$DW$T$470)
	.dwattr $C$DW$861, DW_AT_name("__create")
	.dwattr $C$DW$861, DW_AT_TI_symbol_name("__create")
	.dwattr $C$DW$861, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$861, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$861, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$861, DW_AT_decl_line(0xc2)
	.dwattr $C$DW$861, DW_AT_decl_column(0x0f)
$C$DW$862	.dwtag  DW_TAG_member
	.dwattr $C$DW$862, DW_AT_type(*$C$DW$T$472)
	.dwattr $C$DW$862, DW_AT_name("__delete")
	.dwattr $C$DW$862, DW_AT_TI_symbol_name("__delete")
	.dwattr $C$DW$862, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$862, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$862, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$862, DW_AT_decl_line(0xc3)
	.dwattr $C$DW$862, DW_AT_decl_column(0x10)
$C$DW$863	.dwtag  DW_TAG_member
	.dwattr $C$DW$863, DW_AT_type(*$C$DW$T$476)
	.dwattr $C$DW$863, DW_AT_name("__label")
	.dwattr $C$DW$863, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$863, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$863, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$863, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$863, DW_AT_decl_line(0xc4)
	.dwattr $C$DW$863, DW_AT_decl_column(0x20)
$C$DW$864	.dwtag  DW_TAG_member
	.dwattr $C$DW$864, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$864, DW_AT_name("__mid")
	.dwattr $C$DW$864, DW_AT_TI_symbol_name("__mid")
	.dwattr $C$DW$864, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$864, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$864, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$864, DW_AT_decl_line(0xc5)
	.dwattr $C$DW$864, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$477

	.dwattr $C$DW$T$477, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$477, DW_AT_decl_line(0xc1)
	.dwattr $C$DW$T$477, DW_AT_decl_column(0x08)
$C$DW$T$1584	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_SysFxns")
	.dwattr $C$DW$T$1584, DW_AT_type(*$C$DW$T$477)
	.dwattr $C$DW$T$1584, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1584, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1584, DW_AT_decl_line(0x131)
	.dwattr $C$DW$T$1584, DW_AT_decl_column(0x2a)

$C$DW$T$483	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$483, DW_AT_name("xdc_runtime_Types_SysFxns2")
	.dwattr $C$DW$T$483, DW_AT_byte_size(0x10)
$C$DW$865	.dwtag  DW_TAG_member
	.dwattr $C$DW$865, DW_AT_type(*$C$DW$T$482)
	.dwattr $C$DW$865, DW_AT_name("__create")
	.dwattr $C$DW$865, DW_AT_TI_symbol_name("__create")
	.dwattr $C$DW$865, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$865, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$865, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$865, DW_AT_decl_line(0xca)
	.dwattr $C$DW$865, DW_AT_decl_column(0x0f)
$C$DW$866	.dwtag  DW_TAG_member
	.dwattr $C$DW$866, DW_AT_type(*$C$DW$T$472)
	.dwattr $C$DW$866, DW_AT_name("__delete")
	.dwattr $C$DW$866, DW_AT_TI_symbol_name("__delete")
	.dwattr $C$DW$866, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$866, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$866, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$866, DW_AT_decl_line(0xcb)
	.dwattr $C$DW$866, DW_AT_decl_column(0x10)
$C$DW$867	.dwtag  DW_TAG_member
	.dwattr $C$DW$867, DW_AT_type(*$C$DW$T$476)
	.dwattr $C$DW$867, DW_AT_name("__label")
	.dwattr $C$DW$867, DW_AT_TI_symbol_name("__label")
	.dwattr $C$DW$867, DW_AT_data_member_location[DW_OP_plus_uconst 0x8]
	.dwattr $C$DW$867, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$867, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$867, DW_AT_decl_line(0xcc)
	.dwattr $C$DW$867, DW_AT_decl_column(0x20)
$C$DW$868	.dwtag  DW_TAG_member
	.dwattr $C$DW$868, DW_AT_type(*$C$DW$T$359)
	.dwattr $C$DW$868, DW_AT_name("__mid")
	.dwattr $C$DW$868, DW_AT_TI_symbol_name("__mid")
	.dwattr $C$DW$868, DW_AT_data_member_location[DW_OP_plus_uconst 0xc]
	.dwattr $C$DW$868, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$868, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$868, DW_AT_decl_line(0xcd)
	.dwattr $C$DW$868, DW_AT_decl_column(0x20)
	.dwendtag $C$DW$T$483

	.dwattr $C$DW$T$483, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$483, DW_AT_decl_line(0xc9)
	.dwattr $C$DW$T$483, DW_AT_decl_column(0x08)
$C$DW$T$144	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_SysFxns2")
	.dwattr $C$DW$T$144, DW_AT_type(*$C$DW$T$483)
	.dwattr $C$DW$T$144, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$144, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$144, DW_AT_decl_line(0x132)
	.dwattr $C$DW$T$144, DW_AT_decl_column(0x2b)
$C$DW$T$145	.dwtag  DW_TAG_const_type
	.dwattr $C$DW$T$145, DW_AT_type(*$C$DW$T$144)
$C$DW$T$146	.dwtag  DW_TAG_pointer_type
	.dwattr $C$DW$T$146, DW_AT_type(*$C$DW$T$145)
	.dwattr $C$DW$T$146, DW_AT_address_class(0x20)

$C$DW$T$484	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$484, DW_AT_name("xdc_runtime_Types_Timestamp64")
	.dwattr $C$DW$T$484, DW_AT_byte_size(0x08)
$C$DW$869	.dwtag  DW_TAG_member
	.dwattr $C$DW$869, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$869, DW_AT_name("hi")
	.dwattr $C$DW$869, DW_AT_TI_symbol_name("hi")
	.dwattr $C$DW$869, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$869, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$869, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$869, DW_AT_decl_line(0x79)
	.dwattr $C$DW$869, DW_AT_decl_column(0x10)
$C$DW$870	.dwtag  DW_TAG_member
	.dwattr $C$DW$870, DW_AT_type(*$C$DW$T$175)
	.dwattr $C$DW$870, DW_AT_name("lo")
	.dwattr $C$DW$870, DW_AT_TI_symbol_name("lo")
	.dwattr $C$DW$870, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$870, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$870, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$870, DW_AT_decl_line(0x7a)
	.dwattr $C$DW$870, DW_AT_decl_column(0x10)
	.dwendtag $C$DW$T$484

	.dwattr $C$DW$T$484, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$484, DW_AT_decl_line(0x78)
	.dwattr $C$DW$T$484, DW_AT_decl_column(0x08)
$C$DW$T$413	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Timestamp64")
	.dwattr $C$DW$T$413, DW_AT_type(*$C$DW$T$484)
	.dwattr $C$DW$T$413, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$413, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$413, DW_AT_decl_line(0x129)
	.dwattr $C$DW$T$413, DW_AT_decl_column(0x2e)

$C$DW$T$485	.dwtag  DW_TAG_structure_type
	.dwattr $C$DW$T$485, DW_AT_name("xdc_runtime_Types_Vec")
	.dwattr $C$DW$T$485, DW_AT_byte_size(0x08)
$C$DW$871	.dwtag  DW_TAG_member
	.dwattr $C$DW$871, DW_AT_type(*$C$DW$T$148)
	.dwattr $C$DW$871, DW_AT_name("len")
	.dwattr $C$DW$871, DW_AT_TI_symbol_name("len")
	.dwattr $C$DW$871, DW_AT_data_member_location[DW_OP_plus_uconst 0x0]
	.dwattr $C$DW$871, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$871, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$871, DW_AT_decl_line(0xa4)
	.dwattr $C$DW$871, DW_AT_decl_column(0x0d)
$C$DW$872	.dwtag  DW_TAG_member
	.dwattr $C$DW$872, DW_AT_type(*$C$DW$T$177)
	.dwattr $C$DW$872, DW_AT_name("arr")
	.dwattr $C$DW$872, DW_AT_TI_symbol_name("arr")
	.dwattr $C$DW$872, DW_AT_data_member_location[DW_OP_plus_uconst 0x4]
	.dwattr $C$DW$872, DW_AT_accessibility(DW_ACCESS_public)
	.dwattr $C$DW$872, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$872, DW_AT_decl_line(0xa5)
	.dwattr $C$DW$872, DW_AT_decl_column(0x0d)
	.dwendtag $C$DW$T$485

	.dwattr $C$DW$T$485, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/Types.h")
	.dwattr $C$DW$T$485, DW_AT_decl_line(0xa3)
	.dwattr $C$DW$T$485, DW_AT_decl_column(0x08)
$C$DW$T$1585	.dwtag  DW_TAG_typedef, DW_AT_name("xdc_runtime_Types_Vec")
	.dwattr $C$DW$T$1585, DW_AT_type(*$C$DW$T$485)
	.dwattr $C$DW$T$1585, DW_AT_language(DW_LANG_C)
	.dwattr $C$DW$T$1585, DW_AT_decl_file("c:/ti/xdctools_3_30_01_25_core/packages/xdc/runtime/package/package.defs.h")
	.dwattr $C$DW$T$1585, DW_AT_decl_line(0x12c)
	.dwattr $C$DW$T$1585, DW_AT_decl_column(0x26)
	.dwattr $C$DW$CU, DW_AT_language(DW_LANG_C)

;***************************************************************
;* DWARF CIE ENTRIES                                           *
;***************************************************************

$C$DW$CIE	.dwcie 14
	.dwcfi	cfa_register, 13
	.dwcfi	cfa_offset, 0
	.dwcfi	undefined, 0
	.dwcfi	undefined, 1
	.dwcfi	undefined, 2
	.dwcfi	undefined, 3
	.dwcfi	same_value, 4
	.dwcfi	same_value, 5
	.dwcfi	same_value, 6
	.dwcfi	same_value, 7
	.dwcfi	same_value, 8
	.dwcfi	same_value, 9
	.dwcfi	same_value, 10
	.dwcfi	same_value, 11
	.dwcfi	undefined, 12
	.dwcfi	undefined, 13
	.dwcfi	undefined, 14
	.dwcfi	undefined, 14
	.dwcfi	undefined, 7
	.dwcfi	undefined, 64
	.dwcfi	undefined, 65
	.dwcfi	undefined, 66
	.dwcfi	undefined, 67
	.dwcfi	undefined, 68
	.dwcfi	undefined, 69
	.dwcfi	undefined, 70
	.dwcfi	undefined, 71
	.dwcfi	undefined, 72
	.dwcfi	undefined, 73
	.dwcfi	undefined, 74
	.dwcfi	undefined, 75
	.dwcfi	undefined, 76
	.dwcfi	undefined, 77
	.dwcfi	undefined, 78
	.dwcfi	undefined, 79
	.dwcfi	same_value, 80
	.dwcfi	same_value, 81
	.dwcfi	same_value, 82
	.dwcfi	same_value, 83
	.dwcfi	same_value, 84
	.dwcfi	same_value, 85
	.dwcfi	same_value, 86
	.dwcfi	same_value, 87
	.dwcfi	same_value, 88
	.dwcfi	same_value, 89
	.dwcfi	same_value, 90
	.dwcfi	same_value, 91
	.dwcfi	same_value, 92
	.dwcfi	same_value, 93
	.dwcfi	same_value, 94
	.dwcfi	same_value, 95
	.dwendentry
	.dwendtag $C$DW$CU

