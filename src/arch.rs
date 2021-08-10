use crate::common::Register;

macro_rules! registers {
    ($struct_name:ident, { $($name:ident = ($val:expr, $disp:expr)),+ $(,)? }
        $(, aliases { $($alias_name:ident = ($alias_val:expr, $alias_disp:expr)),+ $(,)? })?) => {
        #[allow(missing_docs)]
        impl $struct_name {
            $(
                pub const $name: Register = Register($val);
            )+
            $(
                $(pub const $alias_name: Register = Register($alias_val);)+
            )*
        }

        impl $struct_name {
            /// The name of a register, or `None` if the register number is unknown.
            ///
            /// Only returns the primary name for registers that alias with others.
            pub fn register_name(register: Register) -> Option<&'static str> {
                match register {
                    $(
                        Self::$name => Some($disp),
                    )+
                    _ => return None,
                }
            }

	    /// Converts a register name into a register number.
	    pub fn name_to_register(value: &str) -> Option<Register> {
		match value {
                    $(
                        $disp => Some(Self::$name),
                    )+
                    $(
                        $($alias_disp => Some(Self::$alias_name),)+
                    )*
                    _ => return None,
		}
	    }
        }
    };
}

/// ARM architecture specific definitions.
///
/// See [DWARF for the ARM Architecture](https://developer.arm.com/documentation/ihi0040/b/).
#[derive(Debug, Clone, Copy)]
pub struct Arm;

// TODO: add more registers.
registers!(Arm, {
    R0 = (0, "R0"),
    R1 = (1, "R1"),
    R2 = (2, "R2"),
    R3 = (3, "R3"),
    R4 = (4, "R4"),
    R5 = (5, "R5"),
    R6 = (6, "R6"),
    R7 = (7, "R7"),
    R8 = (8, "R8"),
    R9 = (9, "R9"),
    R10 = (10, "R10"),
    R11 = (11, "R11"),
    R12 = (12, "R12"),
    R13 = (13, "R13"),
    R14 = (14, "R14"),
    R15 = (15, "R15"),

    WCGR0 = (104, "wCGR0"),
    WCGR1 = (105, "wCGR1"),
    WCGR2 = (106, "wCGR2"),
    WCGR3 = (107, "wCGR3"),
    WCGR4 = (108, "wCGR4"),
    WCGR5 = (109, "wCGR5"),
    WCGR6 = (110, "wCGR6"),
    WCGR7 = (111, "wCGR7"),

    WR0 = (112, "wR0"),
    WR1 = (113, "wR1"),
    WR2 = (114, "wR2"),
    WR3 = (115, "wR3"),
    WR4 = (116, "wR4"),
    WR5 = (117, "wR5"),
    WR6 = (118, "wR6"),
    WR7 = (119, "wR7"),
    WR8 = (120, "wR8"),
    WR9 = (121, "wR9"),
    WR10 = (122, "wR10"),
    WR11 = (123, "wR11"),
    WR12 = (124, "wR12"),
    WR13 = (125, "wR13"),
    WR14 = (126, "wR14"),
    WR15 = (127, "wR15"),

    WC0 = (192, "wC0"),
    WC1 = (193, "wC1"),
    WC2 = (194, "wC2"),
    WC3 = (195, "wC3"),
    WC4 = (196, "wC4"),
    WC5 = (197, "wC5"),
    WC6 = (198, "wC6"),
    WC7 = (199, "wC7"),

    D0 = (256, "D0"),
    D1 = (257, "D1"),
    D2 = (258, "D2"),
    D3 = (259, "D3"),
    D4 = (260, "D4"),
    D5 = (261, "D5"),
    D6 = (262, "D6"),
    D7 = (263, "D7"),
    D8 = (264, "D8"),
    D9 = (265, "D9"),
    D10 = (266, "D10"),
    D11 = (267, "D11"),
    D12 = (268, "D12"),
    D13 = (269, "D13"),
    D14 = (270, "D14"),
    D15 = (271, "D15"),
    D16 = (272, "D16"),
    D17 = (273, "D17"),
    D18 = (274, "D18"),
    D19 = (275, "D19"),
    D20 = (276, "D20"),
    D21 = (277, "D21"),
    D22 = (278, "D22"),
    D23 = (279, "D23"),
    D24 = (280, "D24"),
    D25 = (281, "D25"),
    D26 = (282, "D26"),
    D27 = (283, "D27"),
    D28 = (284, "D28"),
    D29 = (285, "D29"),
    D30 = (286, "D30"),
    D31 = (287, "D31"),
},
aliases {
    ACC0 = (104, "ACC0"),
    ACC1 = (105, "ACC1"),
    ACC2 = (106, "ACC2"),
    ACC3 = (107, "ACC3"),
    ACC4 = (108, "ACC4"),
    ACC5 = (109, "ACC5"),
    ACC6 = (110, "ACC6"),
    ACC7 = (111, "ACC7"),

    S0 = (256, "S0"),
    S1 = (256, "S1"),
    S2 = (257, "S2"),
    S3 = (257, "S3"),
    S4 = (258, "S4"),
    S5 = (258, "S5"),
    S6 = (259, "S6"),
    S7 = (259, "S7"),
    S8 = (260, "S8"),
    S9 = (260, "S9"),
    S10 = (261, "S10"),
    S11 = (261, "S11"),
    S12 = (262, "S12"),
    S13 = (262, "S13"),
    S14 = (263, "S14"),
    S15 = (263, "S15"),
    S16 = (264, "S16"),
    S17 = (264, "S17"),
    S18 = (265, "S18"),
    S19 = (265, "S19"),
    S20 = (266, "S20"),
    S21 = (266, "S21"),
    S22 = (267, "S22"),
    S23 = (267, "S23"),
    S24 = (268, "S24"),
    S25 = (268, "S25"),
    S26 = (269, "S26"),
    S27 = (269, "S27"),
    S28 = (270, "S28"),
    S29 = (270, "S29"),
    S30 = (271, "S30"),
    S31 = (271, "S31"),

});

/// ARM 64-bit (AArch64) architecture specific definitions.
///
/// See [DWARF for the ARM 64-bit Architecture](https://developer.arm.com/documentation/ihi0057/b/).
#[derive(Debug, Clone, Copy)]
pub struct AArch64;

registers!(AArch64, {
    X0 = (0, "X0"),
    X1 = (1, "X1"),
    X2 = (2, "X2"),
    X3 = (3, "X3"),
    X4 = (4, "X4"),
    X5 = (5, "X5"),
    X6 = (6, "X6"),
    X7 = (7, "X7"),
    X8 = (8, "X8"),
    X9 = (9, "X9"),
    X10 = (10, "X10"),
    X11 = (11, "X11"),
    X12 = (12, "X12"),
    X13 = (13, "X13"),
    X14 = (14, "X14"),
    X15 = (15, "X15"),
    X16 = (16, "X16"),
    X17 = (17, "X17"),
    X18 = (18, "X18"),
    X19 = (19, "X19"),
    X20 = (20, "X20"),
    X21 = (21, "X21"),
    X22 = (22, "X22"),
    X23 = (23, "X23"),
    X24 = (24, "X24"),
    X25 = (25, "X25"),
    X26 = (26, "X26"),
    X27 = (27, "X27"),
    X28 = (28, "X28"),
    X29 = (29, "X29"),
    X30 = (30, "X30"),
    SP = (31, "SP"),

    V0 = (64, "V0"),
    V1 = (65, "V1"),
    V2 = (66, "V2"),
    V3 = (67, "V3"),
    V4 = (68, "V4"),
    V5 = (69, "V5"),
    V6 = (70, "V6"),
    V7 = (71, "V7"),
    V8 = (72, "V8"),
    V9 = (73, "V9"),
    V10 = (74, "V10"),
    V11 = (75, "V11"),
    V12 = (76, "V12"),
    V13 = (77, "V13"),
    V14 = (78, "V14"),
    V15 = (79, "V15"),
    V16 = (80, "V16"),
    V17 = (81, "V17"),
    V18 = (82, "V18"),
    V19 = (83, "V19"),
    V20 = (84, "V20"),
    V21 = (85, "V21"),
    V22 = (86, "V22"),
    V23 = (87, "V23"),
    V24 = (88, "V24"),
    V25 = (89, "V25"),
    V26 = (90, "V26"),
    V27 = (91, "V27"),
    V28 = (92, "V28"),
    V29 = (93, "V29"),
    V30 = (94, "V30"),
    V31 = (95, "V31"),
});

/// Intel i386 architecture specific definitions.
///
/// See Intel386 psABi version 1.1 at the [X86 psABI wiki](https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI).
#[derive(Debug, Clone, Copy)]
pub struct X86;

registers!(X86, {
    EAX = (0, "eax"),
    ECX = (1, "ecx"),
    EDX = (2, "edx"),
    EBX = (3, "ebx"),
    ESP = (4, "esp"),
    EBP = (5, "ebp"),
    ESI = (6, "esi"),
    EDI = (7, "edi"),

    // Return Address register. This is stored in `0(%esp, "")` and is not a physical register.
    RA = (8, "RA"),

    ST0 = (11, "st0"),
    ST1 = (12, "st1"),
    ST2 = (13, "st2"),
    ST3 = (14, "st3"),
    ST4 = (15, "st4"),
    ST5 = (16, "st5"),
    ST6 = (17, "st6"),
    ST7 = (18, "st7"),

    XMM0 = (21, "xmm0"),
    XMM1 = (22, "xmm1"),
    XMM2 = (23, "xmm2"),
    XMM3 = (24, "xmm3"),
    XMM4 = (25, "xmm4"),
    XMM5 = (26, "xmm5"),
    XMM6 = (27, "xmm6"),
    XMM7 = (28, "xmm7"),

    MM0 = (29, "mm0"),
    MM1 = (30, "mm1"),
    MM2 = (31, "mm2"),
    MM3 = (32, "mm3"),
    MM4 = (33, "mm4"),
    MM5 = (34, "mm5"),
    MM6 = (35, "mm6"),
    MM7 = (36, "mm7"),

    MXCSR = (39, "mxcsr"),

    ES = (40, "es"),
    CS = (41, "cs"),
    SS = (42, "ss"),
    DS = (43, "ds"),
    FS = (44, "fs"),
    GS = (45, "gs"),

    TR = (48, "tr"),
    LDTR = (49, "ldtr"),

    FS_BASE = (93, "fs.base"),
    GS_BASE = (94, "gs.base"),
});

/// AMD64 architecture specific definitions.
///
/// See x86-64 psABI version 1.0 at the [X86 psABI wiki](https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI).
#[derive(Debug, Clone, Copy)]
pub struct X86_64;

registers!(X86_64, {
    RAX = (0, "rax"),
    RDX = (1, "rdx"),
    RCX = (2, "rcx"),
    RBX = (3, "rbx"),
    RSI = (4, "rsi"),
    RDI = (5, "rdi"),
    RBP = (6, "rbp"),
    RSP = (7, "rsp"),

    R8 = (8, "r8"),
    R9 = (9, "r9"),
    R10 = (10, "r10"),
    R11 = (11, "r11"),
    R12 = (12, "r12"),
    R13 = (13, "r13"),
    R14 = (14, "r14"),
    R15 = (15, "r15"),

    // Return Address register. This is stored in `0(%rsp, "")` and is not a physical register.
    RA = (16, "RA"),

    XMM0 = (17, "xmm0"),
    XMM1 = (18, "xmm1"),
    XMM2 = (19, "xmm2"),
    XMM3 = (20, "xmm3"),
    XMM4 = (21, "xmm4"),
    XMM5 = (22, "xmm5"),
    XMM6 = (23, "xmm6"),
    XMM7 = (24, "xmm7"),

    XMM8 = (25, "xmm8"),
    XMM9 = (26, "xmm9"),
    XMM10 = (27, "xmm10"),
    XMM11 = (28, "xmm11"),
    XMM12 = (29, "xmm12"),
    XMM13 = (30, "xmm13"),
    XMM14 = (31, "xmm14"),
    XMM15 = (32, "xmm15"),

    ST0 = (33, "st0"),
    ST1 = (34, "st1"),
    ST2 = (35, "st2"),
    ST3 = (36, "st3"),
    ST4 = (37, "st4"),
    ST5 = (38, "st5"),
    ST6 = (39, "st6"),
    ST7 = (40, "st7"),

    MM0 = (41, "mm0"),
    MM1 = (42, "mm1"),
    MM2 = (43, "mm2"),
    MM3 = (44, "mm3"),
    MM4 = (45, "mm4"),
    MM5 = (46, "mm5"),
    MM6 = (47, "mm6"),
    MM7 = (48, "mm7"),

    RFLAGS = (49, "rFLAGS"),
    ES = (50, "es"),
    CS = (51, "cs"),
    SS = (52, "ss"),
    DS = (53, "ds"),
    FS = (54, "fs"),
    GS = (55, "gs"),

    FS_BASE = (58, "fs.base"),
    GS_BASE = (59, "gs.base"),

    TR = (62, "tr"),
    LDTR = (63, "ldtr"),
    MXCSR = (64, "mxcsr"),
    FCW = (65, "fcw"),
    FSW = (66, "fsw"),

    XMM16 = (67, "xmm16"),
    XMM17 = (68, "xmm17"),
    XMM18 = (69, "xmm18"),
    XMM19 = (70, "xmm19"),
    XMM20 = (71, "xmm20"),
    XMM21 = (72, "xmm21"),
    XMM22 = (73, "xmm22"),
    XMM23 = (74, "xmm23"),
    XMM24 = (75, "xmm24"),
    XMM25 = (76, "xmm25"),
    XMM26 = (77, "xmm26"),
    XMM27 = (78, "xmm27"),
    XMM28 = (79, "xmm28"),
    XMM29 = (80, "xmm29"),
    XMM30 = (81, "xmm30"),
    XMM31 = (82, "xmm31"),

    K0 = (118, "k0"),
    K1 = (119, "k1"),
    K2 = (120, "k2"),
    K3 = (121, "k3"),
    K4 = (122, "k4"),
    K5 = (123, "k5"),
    K6 = (124, "k6"),
    K7 = (125, "k7"),
});
