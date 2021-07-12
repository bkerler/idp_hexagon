/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "hexagon.hpp"

// configuration flags
uint16_t idpflags = HEX_BRACES_FOR_SINGLE | HEX_CR_FOR_DUPLEX;

static const char* set_idp_options( const char *keyword, int value_type, const void *value )
{
    if( !keyword )
    {
        static const char form[] =
R"(HELP
Open brace is left alone
------------------------
If this option is on, the open brace of a packet will be
placed on its own in a line before packet body:

    {
      r2 = memh(r4 + #8)
      memw(r5) = r2.new }


Closing brace is left alone
---------------------------
If this option is on, the closing brace of a packet will be
placed on its own in a line after packet body:

    { r2 = memh(r4 + #8)
      memw(r5) = r2.new
    }


Use braces for single instructions
----------------------------------
If this option is off, packets with a single instruction
will not use packet braces.


Insert CR inside duplex instructions
------------------------------------
If this option is off, the sub-instructions inside duplex
or complex instructions will be separated by semicolon:

    r1 = #0xF; r0 = add(sp, #0x28)

If this option is on, the sub-instructions inside duplex
or complex instructions will be separated by new line:

    r1 = #0xF
    r0 = add(sp, #0x28)

ENDHELP
Hexagon specific options

<~O~pen brace is left alone:C>
<~C~losing brace is left alone:C>
<~U~se braces for single instructions:C>
<~I~nsert CR inside duplex instructions:C>>
)";
        ask_form( form, &idpflags );
        return IDPOPT_OK;
    }
    else
    {
        if( value_type != IDPOPT_BIT )
            return IDPOPT_BADTYPE;
        if( !strcmp( keyword, "HEX_OBRACE_ALONE" ) )
        {
            setflag( idpflags, HEX_OBRACE_ALONE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_CBRACE_ALONE" ) )
        {
            setflag( idpflags, HEX_CBRACE_ALONE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_BRACES_FOR_SINGLE" ) )
        {
            setflag( idpflags, HEX_BRACES_FOR_SINGLE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_CR_FOR_DUPLEX" ) )
        {
            setflag( idpflags, HEX_CR_FOR_DUPLEX, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        return IDPOPT_BADKEY;
    }
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new hexagon_t);
  return 0;
}

ssize_t idaapi hexagon_t::on_event(ssize_t notification_code, va_list va)
{
    switch( notification_code )
    {
    case processor_t::ev_set_idp_options: {
        auto keyword = va_arg( va, const char* );
        auto value_type = va_arg( va, int );
        auto value = va_arg( va, const void* );
        auto errbuf = va_arg( va, const char** );

        const char *err = set_idp_options( keyword, value_type, value );
        if( err == IDPOPT_OK ) return 1;
        if( errbuf ) *errbuf = err;
        return -1;
    }
    case processor_t::ev_loader_elf_machine: {
        // note: this callback is called only if the user clicked "Set" button
        // in "Load a new file" dialog
        auto li = va_arg( va, linput_t* );
        auto machine_type = va_arg( va, int );
        auto p_procname = va_arg( va, const char** );
        auto p_pd = va_arg( va, proc_def_t** );
        return loader_elf_machine( li, machine_type, p_procname, p_pd );
    }
    case processor_t::ev_ana_insn: {
        return ana( *va_arg( va, insn_t* ) );
    }
    case processor_t::ev_emu_insn: {
        return emu( *va_arg( va, const insn_t* ) );
    }
    case processor_t::ev_out_header: {
        out_header( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_footer: {
        out_footer( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_insn: {
        out_insn( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_operand: {
        auto ctx = va_arg( va, outctx_t* );
        auto op = va_arg( va, const op_t* );
        return out_operand( *ctx, *op );
    }
    case processor_t::ev_is_call_insn: {
        return hex_is_call_insn( *va_arg( va, const insn_t* ) )? 1 : -1;
    }
    case processor_t::ev_is_ret_insn: {
        // not strictly necessary, everything works as is
        auto insn = va_arg( va, const insn_t* );
        auto strict = va_argi( va, bool );
        return hex_is_ret_insn( *insn, strict )? 1 : -1;
    }
    case processor_t::ev_may_be_func: {
        auto insn = va_arg( va, const insn_t* );
        auto state = va_arg( va, int );
        return hex_may_be_func( *insn, state );
    }
    case processor_t::ev_is_align_insn: {
        return hex_is_align_insn( va_arg( va, ea_t ) );
    }
    case processor_t::ev_is_jump_func: {
        auto pfn = va_arg( va, func_t* );
        auto jump_target = va_arg( va, ea_t* );
        auto func_pointer = va_arg( va, ea_t* );
        return hex_is_jump_func( *pfn, jump_target, func_pointer )? 1 : 0;
    }
    case processor_t::ev_create_func_frame: {
        hex_create_func_frame( va_arg( va, func_t* ) );
        return 1;
    }
    case processor_t::ev_get_frame_retsize: {
        auto frsize = va_arg( va, int* );
        auto pfn = va_arg( va, const func_t* );
        *frsize = hex_get_frame_retsize( *pfn );
        return 1;
    }
    case processor_t::ev_is_sp_based: {
        auto mode = va_arg( va, int* );
        auto insn = va_arg( va, const insn_t* );
        auto op = va_arg( va, const op_t* );
        *mode = hex_is_sp_based( *insn, *op );
        return 1;
    }
    case processor_t::ev_realcvt: {
        // must be implemented for floats to work
        auto m = va_arg( va, void* );
        fpvalue_t* e = va_arg( va, fpvalue_t* );
        auto swt = va_argi( va, uint16 );
        int code = ieee_realcvt( m, e, swt );
        return code == 0? 1 : code;
    }
    //
    // type information callbacks
    //
    case processor_t::ev_decorate_name: {
        auto outbuf = va_arg( va, qstring* );
        auto name = va_arg( va, const char* );
        auto mangle = va_argi( va, bool );
        auto cc = va_argi( va, cm_t );
        auto type = va_arg( va, tinfo_t* );
        return gen_decorate_name( outbuf, name, mangle, cc, type );
    }
    case processor_t::ev_get_cc_regs: {
        auto regs = va_arg( va, callregs_t* );
        auto cc = va_arg( va, cm_t );
        hex_get_cc_regs( cc, *regs );
        return 1;
    }
    case processor_t::ev_get_stkarg_offset: {
        // offset from SP to the first stack argument
        return 0;
    }
    case processor_t::ev_calc_arglocs: {
        auto fti = va_arg( va, func_type_data_t* );
        return hex_calc_arglocs( *fti )? 1 : -1;
    }
    case processor_t::ev_calc_retloc: {
        auto retloc = va_arg( va, argloc_t* );
        auto rettype = va_arg( va, const tinfo_t* );
        auto cc = va_arg( va, cm_t );
        return hex_calc_retloc( cc, *rettype, *retloc )? 1 : -1;
    }
    case processor_t::ev_use_arg_types: {
        auto ea = va_arg( va, ea_t );
        auto fti = va_arg( va, func_type_data_t* );
        auto rargs = va_arg( va, funcargvec_t* );
        hex_use_arg_types( ea, *fti, *rargs );
        return 1;
    }
    case processor_t::ev_use_regarg_type: {
        auto idx = va_arg( va, int* );
        auto ea = va_arg( va, ea_t );
        auto rargs = va_arg( va, const funcargvec_t* );
        *idx = hex_use_regarg_type( ea, *rargs );
        return 1;
    }
    case processor_t::ev_max_ptr_size:
        return inf_get_cc_size_l();
    case processor_t::ev_get_default_enum_size:
        return inf_get_cc_size_e();
    }

    // by default always return 0
    return 0;
}

// GNU Assembler description
static const asm_t elf_asm = {
    ASH_HEXF3 |                 // hex 0x123 format
    ASD_DECF0 |                 // dec 123 format
    ASO_OCTF1 |                 // oct 012345 format
    ASB_BINF3 |                 // bin 0b110 format
    AS_N2CHR |                  // can't have 2 byte char consts
    AS_LALIGN |                 // labels at "align" keyword are supported
    AS_COLON,                   // create colons after data names
    0,                          // uflag
    "ELF Assembler",            // name
    0,                          // help
    NULL,                       // header
    ".org",                     // org directive
    ".end",                     // end directive
    "//",                       // comment string
    '"',                        // string delimiter
    '\'',                       // char delimiter (in fact it's a single left quote symbol)
    "\"'",                      // special symbols in char and string constants
    ".ascii",                   // ascii string directive
    ".byte",                    // byte directive
    ".short",                   // word directive, aka .half,.hword,.2byte
    ".long",                    // dword  (4 bytes), aka .word,.int,.4byte
    ".quad",                    // qword  (8 bytes)
    NULL,                       // oword  (16 bytes)
    ".float",                   // float  (4 bytes)
    ".double",                  // double (8 bytes)
    NULL,                       // long double (10/12 bytes)
    NULL,                       // packed decimal real
    "#d dup(#v)",               // dups (actually we need to use ".fill #d, #s(1,2,4,8,16), #v"
                                //       but IDA uses it exactly as dup in MASM)
    ".space %s",                // uninited arrays
    ".equ",                     // 'equ'
    NULL,                       // 'seg' prefix
    ".",                        // current instruction pointer
    NULL,                       // function header
    NULL,                       // function footer
    ".global",                  // public
    NULL,                       // weak
    NULL,                       // extrn
    ".common",                  // comdef
    NULL,                       // get name of type
    ".align",                   // align
    '(', ')',                   // lbrace, rbrace
    "%",                        // mod
    "&",                        // and
    "|",                        // or
    "^",                        // xor
    "~",                        // not
    ">>",                       // shl
    "<<",                       // shr
    NULL,                       // size of type (format string)
    0,                          // flag2
    NULL,                       // cmnt2
    NULL,                       // low8 operation
    NULL,                       // high8 operation
    "LO(%s)",                   // low16 operation
    "HI(%s)",                   // high16 operation
    NULL,                       // the include directive (format string)
    NULL,                       // vstruc
    NULL,                       // 'rva' keyword for image based offsets
    NULL,                       // 32-byte (256-bit) data
};

// supported assemblers
static const asm_t *const asms[] = { &elf_asm, NULL };

// short and long names for our module
static const char *const shnames[] = {
    "QDSP6",
    NULL
};
static const char *const lnames[] = {
    "Qualcomm Hexagon DSP",
    NULL
};

enum qdsp_reg_t
{
    QDSP_REG_R0          = 0,                // scalar registers
    QDSP_REG_P0          = REG_R0 + 32,      // scalar predicates
    QDSP_REG_V0          = REG_P0 + 4,       // vector registers
    QDSP_REG_Q0          = REG_V0 + 32,      // vector predicates
    QDSP_REG_Z           = REG_Q0 + 4,       // 2048 bits regsiter for NN
    QDSP_REG_VTMP        = REG_Z + 1,        // virtual register for temporary loads
    // user mode control registers
    QDSP_REG_C0          = REG_VTMP + 1,
    // guest mode control registers
    QDSP_REG_G0          = REG_C0 + 32,
    // monitor mode control registers
    QDSP_REG_S0          = REG_G0 + 32,
    rVcs         = REG_S0 + 128,
    rVds
};

static const char *const reg_names[]
{
    //general
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "sp", "fp", "lr",
    //predicates
    "p0", "p1", "p2", "p3",
    //vector
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", 
    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
    "q0", "q1", "q2", "q3",
    //zero, virtual temporary
    "z", "vtmp",
    //control   
    "c0", "c1", "c2", "c3", "c4", "c5", "m0", "m1", "c8", "pc", "c10", "gp", "c12", "c13", "c14", "c15", 
    "c16", "c17", "c18", "c19", "c20", "c21", "c22", "c23", "c24", "c25", "c26", "c27", "c28", "c29", "c30", "c31",
    //guest mode control
    "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8", "g9", "g10", "g11", "g12", "g13", "g14", "g15", 
    "g16", "g17", "g18", "g19", "g20", "g21", "g22", "g23", "g24", "g25", "g26", "g27", "g28", "g29", "g30", "g31",
    //monitor mode control
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15", 
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31", 
    "s32", "s33", "s34", "s35", "s36", "s37", "s38", "s39", "s40", "s41", "s42", "s43", "s44", "s45", "s46", "s47", 
    "s48", "s49", "s50", "s51", "s52", "s53", "s54", "s55", "s56", "s57", "s58", "s59", "s60", "s61", "s62", "s63", 
    "s64", "s65", "s66", "s67", "s68", "s69", "s70", "s71", "s72", "s73", "s74", "s75", "s76", "s77", "s78", "s79", 
    "s80", "s81", "s82", "s83", "s84", "s85", "s86", "s87", "s88", "s89", "s90", "s91", "s92", "s93", "s94", "s95", 
    "s96", "s97", "s98", "s99", "s100", "s101", "s102", "s103", "s104", "s105", "s106", "s107", "s108", "s109", "s110", "s111", 
    "s112", "s113", "s114", "s115", "s116", "s117", "s118", "s119", "s120", "s121", "s122", "s123", "s124", "s125", "s126", "s127", 
    //virtual segregs
    "cs", "ds"
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
    IDP_INTERFACE_VERSION,  // version
    0x8666,                 // id
                            // flag:
    PR_CNDINSNS |           // has conditional instructions
    PR_NO_SEGMOVE |         // the processor module doesn't support move_segm() (i.e. the user can't move segments)
    PR_USE32 |              // supports 32-bit addressing?
    PR_DEFSEG32 |           // segments are 32-bit by default
    PRN_HEX |               // default number representation: == hex
    PR_TYPEINFO |           // support the type system notifications
    PR_USE_ARG_TYPES,        // use processor_t::ev_use_arg_types callback
    //PR_ALIGN,               // all data items should be aligned properly
                            // flag2:
    PR2_REALCVT |           // the module has 'realcvt' event implementation
    PR2_IDP_OPTS,           // the module has processor-specific configuration options
    8,                      // cnbits: 8 bits in a byte for code segments
    8,                      // dnbits: 8 bits in a byte for other segments
    shnames,                // array of short processor names
                            // the short names are used to specify the processor
                            // with the -p command line switch)
    lnames,                 // array of long processor names
                            // the long names are used to build the processor type
                            // selection menu
    asms,                   // array of target assemblers
    notify,                 // the kernel event notification callback
    reg_names,              // regsiter names
    qnumber(reg_names),     // number of registers

    0,                      // index of first segment register
    1,                      // index of last segment register
    0,                      // size of a segment register in bytes
    0, 1,                   // index of CS & DS registers

    NULL,                   // no known code start sequences
    NULL,                   // no known 'return' instructions

    0,                      // icode of 1st instruction
    0,                      // icode of last instruction + 1
    NULL,                   // array of instructions

    0,                      // sizeof(long double) -- doesn't exist
    { 0, 7, 15, 0 },        // number of symbols after decimal point (must define for floats to work)
                            // 16-bit float (0-does not exist)
                            // normal float
                            // normal double
                            // long double (0-does not exist)
    0,                      // Icode of return instruction (it's ok to give any of possible return instructions)
};
