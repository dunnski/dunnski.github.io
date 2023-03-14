---
title: Qbot BB17 YARA rule
date: 2023-03-14 12:00:00
category: [YARA, Malware]
tags: [YARA, malware, campaign]
---

## YARA:

```yara
import "pe"

rule Qakbot_BB17_DLLs {
    meta:
        description = "Matches on Indicators from Qakbot_bb17 Campaigns"
        author = "jt_dunnski"
        imphash = "59b79dadf67766ab27d48f7cfb8bae34"
        export_called_to_exe_Qakbot = "N115"
    strings:
        /*
        Op codes for op1 & op2 identified via VT's Diff feature on Known Qakbot DLLs
        Hash 1: 621c9aea955e4cde012a3cfd192e0096e2037f9aeb272daf0f392e00478481f4
        Hash 2: 628b7be2f1bb39f173458d0595ddfed907157ef25a574d34faaa4bfd80129071
        Hash 3: 7193cff8c047bcb00743121f4f90a7df786c93da0b68366bb40d927215f6907b
        Hash 4: 57336ee2e237a32db2e848fb11af6074bf6d155e59b64d67d56a2c02659d3148
        Excluded Hashes:
        Hash 1: 4d9a1a12cdb6143bd7b918300c49944dc5a836337d5eb0847f72f81f5e56eb50
        Hash 2: 4e822f847073f81c781be433eff6c68db616efad49cee50a5e19997fb46a9da0
        */

        $op1 = {637D3CE221D68936D3D77B22B084F9F949385F07960582D0841C61D77BFDA1E261457B256E26211A5A734EE429310CCB9B8B12C3D59A9B46EF67692A6C568DF9D0126924C28261A22CBE379793E0CA7F907AEF4E0A2FF5A2DDCD35AA6348463C4140D693FEEEA8B15E07FBA19E858C8F4445FB4E4C3B25E4B5}
        $op2 = {7550D37960858CC45C77A06A5849EAA91A188D5399A08B4349BE68AA9E131BB9B7F6D26C33171BDF86B88B13B42B60CC3F9A80D454558FCE43893F66E102EE3A0B52D47B04CF395CD5}
        
        /*
        func found in: D94D603A1F876678B3AE83302D542E487ADC0BC0DFA39665A6E9CA6A85470884
        Original DLL that performed the injection: 21A3F00CF75DE5C4B86FF915E86526F3C3DF962470C9B7EDE296C31AB2BCF74F 
        op3:
            qbot_wideFormatPrint proc near

                        arg_0= dword ptr  8
                        arg_4= dword ptr  0Ch
                        arg_8= dword ptr  10h
                        arg_C= byte ptr  14h

55                      push    ebp
8B EC                   mov     ebp, esp
56                      push    esi
8B 75 0C                mov     esi, [ebp+arg_4]
57                      push    edi
8B 7D 08                mov     edi, [ebp+arg_0]
56                      push    esi
6A 00                   push    0
57                      push    edi
E8 EF DF FF FF          call    sub_1000A130
8D 45 14                lea     eax, [ebp+arg_C]
50                      push    eax
FF 75 10                push    [ebp+arg_8]
56                      push    esi
57                      push    edi
FF 15 00 A2 6F 02       call    dword ptr ds:26FA200h
33 C9                   xor     ecx, ecx
83 C4 1C                add     esp, 1Ch
66 89 4C 77 FE          mov     [edi+esi*2-2], cx
85 C0                   test    eax, eax
79 0A                   jns     short loc_1000C168

        */

        $op3 = {558bec568b750c578b7d08566a0057e8efdfffff8d451450ff75105657ff1500a26f0233c983c41c66894c77fe85c0790a}
        
        /*
        Op4 generated from VTDiff on known Qakbot Injected DLLs
        Hash 1 = c72c68d4a8331451c224ed7d5d6684b25dcafb3cb7cb79b2ec437da43088af2d
        Hash 2 = 3b4770892d8a8ccac1b96c40d368b08ec9d91e7ac8505b6437d0e7b619a3bbfe
        */

        $op4 = {BF76B51E616F0A1B77D9B5B81CFE32D609222C452AEF2ABDFDF2D381346454F0507A9640D0C451D5A848C409C9EC6ADCF34D0A971641C466E4C4420459CCA959CBE7B7FBC97EA2D0E867DF464AA44D8C9EFA234E0F680DA6459357BE4B0B19EE22D792BC533827988177E296CB3D7CDB484EF2AD4A4FAFE929C9AE67236F06E4E12EE4572352}
    
    condition:
        uint16(0) == 0x5A4D and pe.DLL and pe.number_of_signatures == 0 and (pe.imphash() == "59b79dadf67766ab27d48f7cfb8bae34" and pe.exports("N115")) or (any of ($op*))


}
```

