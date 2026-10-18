#pragma once

// List of standard & custom Script opcodes
enum OpCode : unsigned char
{
    // ====================
    // Standard Bitcoin-like opcodes
    // ====================
    OP_0               = 0x00,
    OP_FALSE           = OP_0,
    OP_PUSHDATA1       = 0x4c,
    OP_PUSHDATA2       = 0x4d,
    OP_PUSHDATA4       = 0x4e,
    OP_1NEGATE         = 0x4f,
    OP_RESERVED        = 0x50,
    OP_1               = 0x51,
    OP_TRUE            = OP_1,
    OP_2               = 0x52,
    OP_3               = 0x53,
    OP_4               = 0x54,
    OP_5               = 0x55,
    OP_6               = 0x56,
    OP_7               = 0x57,
    OP_8               = 0x58,
    OP_9               = 0x59,
    OP_10              = 0x5a,
    OP_11              = 0x5b,
    OP_12              = 0x5c,
    OP_13              = 0x5d,
    OP_14              = 0x5e,
    OP_15              = 0x5f,
    OP_16              = 0x60,

    // Flow control
    OP_NOP             = 0x61,
    OP_VER             = 0x62,
    OP_IF              = 0x63,
    OP_NOTIF           = 0x64,
    OP_VERIF           = 0x65,
    OP_VERNOTIF        = 0x66,
    OP_ELSE            = 0x67,
    OP_ENDIF           = 0x68,
    OP_VERIFY          = 0x69,
    OP_RETURN          = 0x6a,

    // Stack ops
    OP_TOALTSTACK      = 0x6b,
    OP_FROMALTSTACK    = 0x6c,
    OP_2DROP           = 0x6d,
    OP_2DUP            = 0x6e,
    OP_3DUP            = 0x6f,
    OP_2OVER           = 0x70,
    OP_2ROT            = 0x71,
    OP_2SWAP           = 0x72,
    OP_IFDUP           = 0x73,
    OP_DEPTH           = 0x74,
    OP_DROP            = 0x75,
    OP_DUP             = 0x76,
    OP_NIP             = 0x77,
    OP_OVER            = 0x78,
    OP_PICK            = 0x79,
    OP_ROLL            = 0x7a,
    OP_ROT             = 0x7b,
    OP_SWAP            = 0x7c,
    OP_TUCK            = 0x7d,

    // Splice ops
    OP_CAT             = 0x7e,
    OP_SUBSTR          = 0x7f,
    OP_LEFT            = 0x80,
    OP_RIGHT           = 0x81,
    OP_SIZE            = 0x82,

    // Bitwise logic
    OP_INVERT          = 0x83,
    OP_AND             = 0x84,
    OP_OR              = 0x85,
    OP_XOR             = 0x86,
    OP_EQUAL           = 0x87,
    OP_EQUALVERIFY     = 0x88,

    // Arithmetic
    OP_1ADD            = 0x8b,
    OP_1SUB            = 0x8c,
    OP_2MUL            = 0x8d,
    OP_2DIV            = 0x8e,
    OP_NEGATE          = 0x8f,
    OP_ABS             = 0x90,
    OP_NOT             = 0x91,
    OP_0NOTEQUAL       = 0x92,
    OP_ADD             = 0x93,
    OP_SUB             = 0x94,
    OP_MUL             = 0x95,
    OP_DIV             = 0x96,
    OP_MOD             = 0x97,
    OP_LSHIFT          = 0x98,
    OP_RSHIFT          = 0x99,
    OP_BOOLAND         = 0x9a,
    OP_BOOLOR          = 0x9b,
    OP_NUMEQUAL        = 0x9c,
    OP_NUMEQUALVERIFY  = 0x9d,
    OP_NUMNOTEQUAL     = 0x9e,
    OP_LESSTHAN        = 0x9f,
    OP_GREATERTHAN     = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN             = 0xa3,
    OP_MAX             = 0xa4,
    OP_WITHIN          = 0xa5,

    // Crypto
    OP_RIPEMD160       = 0xa6,
    OP_SHA1            = 0xa7,
    OP_SHA256          = 0xa8,
    OP_HASH160         = 0xa9,
    OP_HASH256         = 0xaa,
    OP_CODESEPARATOR   = 0xab,
    OP_CHECKSIG        = 0xac,
    OP_CHECKSIGVERIFY  = 0xad,
    OP_CHECKMULTISIG   = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Expansion
    OP_NOP1            = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4            = 0xb3,
    OP_NOP5            = 0xb4,
    OP_NOP6            = 0xb5,
    OP_NOP7            = 0xb6,
    OP_NOP8            = 0xb7,
    OP_NOP9            = 0xb8,
    OP_NOP10           = 0xb9,

    // =====================
    // TRU extended opcodes.
    // =====================

    // This pushes the current block time (or block height) to the stack
    OP_BLOCKTIME       = 0xf0,

    // This could push some external data (like oracle data) onto the stack
    OP_EXTERNALDATA    = 0xf1,

    // This might interpret the top stack item as a "data feed key"
    // (like "StockPrice:AMZN"), fetch the feed, and push the numeric result
    OP_DATAFEED        = 0xf2,

    // This checks if a special "delegate" or "trusted party" signature is valid
    OP_DELEGATECHECK   = 0xf3,  // or OP_TRUSTEDPARTY

    // This reads some chain state variable: e.g. total minted supply, etc.
    OP_CHAINSTATECHECK = 0xf4,

    // This applies a BLAKE2b hash to the top item
    OP_HASHBLAKE2B     = 0xf5,

    // This applies a SHA3 (Keccak) hash to the top item
    OP_SHA3            = 0xf6,

    // New Smart Contract Opcodes
    OP_STORE           = 0xf7,  // Store key-value pair in contract state
    OP_LOAD            = 0xf8,  // Load value from contract state by key
    OP_CALLER          = 0xf9,  // Push sender address to stack
    OP_CONTRACT_ADDR   = 0xfa,  // Push contract address (output address) to stack
    OP_GAS             = 0xfb,  // Push remaining gas to stack
    OP_HALT            = 0xfc,  // Halt execution (e.g., for gas exhaustion)
    OP_REVERT          = 0xfd,  // Revert transaction and state changes
    OP_OUTPUTAMOUNT    = 0xfe,  // Push the amount of the current output to the stack

    // Token-specific opcodes
    OP_MINT_TOKEN      = 0xe0,  // Mint tokens to caller
    OP_TOKEN_BALANCE   = 0xe1,  // Get token balance
    OP_BURN_TOKEN      = 0xe2,  // Burn tokens

    // =====================
    // NOVO Bridge Opcodes (using unused NOP slots)
    // =====================
    OP_NOVO_GENADDR    = 0xb3,  // Generate NOVO deposit address (was OP_NOP4)
    OP_NOVO_DEPOSIT    = 0xb4,  // Confirm NOVO deposit & mint wNOVO (was OP_NOP5)
    OP_NOVO_REDEEM     = 0xb5,  // Burn wNOVO & reveal private key (was OP_NOP6)
    OP_NOVO_VERIFY     = 0xb6,  // Verify NOVO transaction proof (was OP_NOP7)

    // =====================
    // GlobalBoost-Y Bridge Opcodes
    // =====================
    OP_BSTY_GENADDR    = 0xb7,  // Generate BSTY deposit address (was OP_NOP8)
    OP_BSTY_DEPOSIT    = 0xb8,  // Confirm BSTY deposit & mint wBSTY (was OP_NOP9)
    OP_BSTY_REDEEM     = 0xb9,  // Burn wBSTY & reveal private key (was OP_NOP10)
    OP_BSTY_VERIFY     = 0xba,  // Verify BSTY transaction proof (new slot)

    // =====================
    // reserved upgrade NOP space
    // =====================
    // These bytes are consensus-valid no-ops at genesis so they can later
    // be tightened into new functionality by a compatible soft-fork rule.
    // They intentionally have no compileTextScript names yet.
    OP_UPGRADE_NOP1    = 0xbb,
    OP_UPGRADE_NOP2    = 0xbc,
    OP_UPGRADE_NOP3    = 0xbd,
    OP_UPGRADE_NOP4    = 0xbe,
    OP_UPGRADE_NOP5    = 0xbf,
    OP_UPGRADE_NOP6    = 0xc0,
    OP_UPGRADE_NOP7    = 0xc1,
    OP_UPGRADE_NOP8    = 0xc2,


    // Invalid marker (end)
    OP_INVALIDOPCODE   = 0xff
};
