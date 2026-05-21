### Member functions Address
ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
ADRS.setChainAddress(𝑖)
ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
ADRS.setHashAddress(𝑖)
ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)


### Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
Chaining function used in WOTS+ .
Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.
Output: Value of F iterated 𝑠 times on 𝑋.
1: 𝑡𝑚𝑝 ← 𝑋
2: for 𝑗 from 𝑖 to 𝑖 + 𝑠 − 1 do
3: ADRS.setHashAddress(𝑗)
4: 𝑡𝑚𝑝 ← F(PK.seed, ADRS, 𝑡𝑚𝑝)
5: end for
6: return 𝑡𝑚𝑝

### Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
Generates a WOTS+ public key.
Input: Secret seed SK.seed, public seed PK.seed, address ADRS.
Output: WOTS+ public key 𝑝𝑘.
1: skADRS ← ADRS ▷ copy address to create key generation key address
2: skADRS.setTypeAndClear(WOTS_PRF)
3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
4: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
5: skADRS.setChainAddress(𝑖)
6: 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute secret value for chain 𝑖
7: ADRS.setChainAddress(𝑖)
8: 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS) ▷ compute public value for chain 𝑖
9: end for
10: wotspkADRS ← ADRS ▷ copy address to create WOTS+public key address
11: wotspkADRS.setTypeAndClear(WOTS_PK)
12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
13: 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝) ▷ compress public key
14: return 𝑝𝑘

### Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
Generates a WOTS+ signature on an 𝑛-byte message.
Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS.
Output: WOTS+ signature 𝑠𝑖𝑔.
1: 𝑐𝑠𝑢𝑚 ← 0
2: 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1) ▷ convert message to base 𝑤
3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ for 𝑙𝑔𝑤 = 4, left shift by 4
7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤8
8: skADRS ← ADRS ▷ copy address to create key generation key address
9: skADRS.setTypeAndClear(WOTS_PRF)
10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
11: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
12: skADRS.setChainAddress(𝑖)
13: 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS) ▷ compute chain 𝑖 secret value
14: ADRS.setChainAddress(𝑖)
15: 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS) ▷ compute chain 𝑖 signature value
16: end for
17: return 𝑠𝑖𝑔

### Algorithm 8 wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
Computes a WOTS+ public key from a message and its signature.
Input: WOTS+ signature 𝑠𝑖𝑔, message 𝑀, public seed PK.seed, address ADRS.
Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔.
1: 𝑐𝑠𝑢𝑚 ← 0
2: 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1) ▷ convert message to base 𝑤
3: for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do ▷ compute checksum
4: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
5: end for
6: 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 ≪ ((8 − ((𝑙𝑒𝑛2 ⋅ 𝑙𝑔𝑤) mod 8)) mod 8) ▷ for 𝑙𝑔𝑤 = 4, left shift by 4
7: 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈𝑙𝑒𝑛2⋅𝑙𝑔𝑤 ⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2) ▷ convert to base 𝑤8
8: for 𝑖 from 0 to 𝑙𝑒𝑛 − 1 do
9: ADRS.setChainAddress(𝑖)
10: 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑖𝑔[𝑖], 𝑚𝑠𝑔[𝑖], 𝑤 − 1 − 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
11: end for
12: wotspkADRS ← ADRS ▷ copy address to create WOTS+ public key address
13: wotspkADRS.setTypeAndClear(WOTS_PK)
14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
15: 𝑝𝑘𝑠𝑖𝑔 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS, 𝑡𝑚𝑝)
16: return 𝑝𝑘𝑠𝑖𝑔

### Algorithm 9 xmss_node(SK.seed, 𝑖, 𝑧, PK.seed, ADRS)
Computes the root of a Merkle subtree of WOTS+ public keys.
Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed,
address ADRS.
Output: 𝑛-byte root 𝑛𝑜𝑑𝑒.
1: if 𝑧 = 0 then
2: ADRS.setTypeAndClear(WOTS_HASH)
3: ADRS.setKeyPairAddress(𝑖)
4: 𝑛𝑜𝑑𝑒 ← wots_pkGen(SK.seed, PK.seed, ADRS)
5: else
6: 𝑙𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖, 𝑧 − 1, PK.seed, ADRS)
7: 𝑟𝑛𝑜𝑑𝑒 ← xmss_node(SK.seed, 2𝑖 + 1, 𝑧 − 1, PK.seed, ADRS)
8: ADRS.setTypeAndClear(TREE)
9: ADRS.setTreeHeight(𝑧)
10: ADRS.setTreeIndex(𝑖)
11: 𝑛𝑜𝑑𝑒 ← H(PK.seed, ADRS, 𝑙𝑛𝑜𝑑𝑒 ∥ 𝑟𝑛𝑜𝑑𝑒)
12: end if
13: return 𝑛𝑜𝑑𝑒

### Algorithm 10 `xmss_sign(M, SK.seed, idx, PK.seed, ADRS)`

*Generates an XMSS signature.*

**Input:** `n`-byte message `M`, secret seed `SK.seed`, index `idx`, public seed `PK.seed`, address `ADRS`.

**Output:** XMSS signature `SIG_XMSS = (sig || AUTH)`.

```text
1: for j from 0 to h′ − 1 do
2:     k ← ⌊idx / 2^j⌋ ⊕ 1
3:     AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS)
4: end for

5: ADRS.setTypeAndClear(WOTS_HASH)
6: ADRS.setKeyPairAddress(idx)
7: sig ← wots_sign(M, SK.seed, PK.seed, ADRS)
8: SIG_XMSS ← sig || AUTH
9: return SIG_XMSS
```

### Algorithm 11 xmss_pkFromSig(𝑖𝑑𝑥, SIG𝑋𝑀𝑆𝑆, 𝑀, PK.seed, ADRS)
Computes an XMSS public key from an XMSS signature.
Input: Index 𝑖𝑑𝑥, XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH), 𝑛-byte message 𝑀,
public seed PK.seed, address ADRS.
Output: 𝑛-byte root value 𝑛𝑜𝑑𝑒[0].
1: ADRS.setTypeAndClear(WOTS_HASH) ▷ compute WOTS+ pk from WOTS+ 𝑠𝑖𝑔
2: ADRS.setKeyPairAddress(𝑖𝑑𝑥)
3: 𝑠𝑖𝑔 ← SIG𝑋𝑀𝑆𝑆.getWOTSSig() ▷ SIG𝑋𝑀𝑆𝑆[0 ∶ 𝑙𝑒𝑛 ⋅ 𝑛]
4: AUTH ← SIG𝑋𝑀𝑆𝑆.getXMSSAUTH() ▷ SIG𝑋𝑀𝑆𝑆[𝑙𝑒𝑛 ⋅ 𝑛 ∶ (𝑙𝑒𝑛 + ℎ′) ⋅ 𝑛]
5: 𝑛𝑜𝑑𝑒[0] ← wots_pkFromSig(𝑠𝑖𝑔, 𝑀 , PK.seed, ADRS)
6: ADRS.setTypeAndClear(TREE) ▷ compute root from WOTS+ pk and AUTH
7: ADRS.setTreeIndex(𝑖𝑑𝑥)
8: for 𝑘 from 0 to ℎ′ − 1 do
9: ADRS.setTreeHeight(𝑘 + 1)
10: if ⌊𝑖𝑑𝑥/2𝑘⌋ is even then
11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
12: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, 𝑛𝑜𝑑𝑒[0] ∥ AUTH[𝑘])
13: else
14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
15: 𝑛𝑜𝑑𝑒[1] ← H(PK.seed, ADRS, AUTH[𝑘] ∥ 𝑛𝑜𝑑𝑒[0])
16: end if
17: 𝑛𝑜𝑑𝑒[0] ← 𝑛𝑜𝑑𝑒[1]
18: end for
19: return 𝑛𝑜𝑑𝑒[0]

### Algorithm 12 ht_sign(𝑀, SK.seed, PK.seed, 𝑖𝑑𝑥𝑡𝑟𝑒𝑒, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
Generates a hypertree signature.
Input: Message 𝑀, private seed SK.seed, public seed PK.seed, tree index 𝑖𝑑𝑥𝑡𝑟𝑒𝑒,
leaf index 𝑖𝑑𝑥𝑙𝑒𝑎𝑓.
Output: HT signature SIG𝐻𝑇.
1: ADRS ← toByte(0, 32)
2: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
3: SIG𝑡𝑚𝑝 ← xmss_sign(𝑀, SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
4: SIG𝐻𝑇 ← SIG𝑡𝑚𝑝
5: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑀 , PK.seed, ADRS)
6: for 𝑗 from 1 to 𝑑 − 1 do
7: 𝑖𝑑𝑥𝑙𝑒𝑎𝑓 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 mod 2ℎ′
▷ ℎ′ least significant bits of 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
8: 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ← 𝑖𝑑𝑥𝑡𝑟𝑒𝑒 ≫ ℎ′ ▷ remove least significant ℎ′ bits from 𝑖𝑑𝑥𝑡𝑟𝑒𝑒
9: ADRS.setLayerAddress(𝑗)
10: ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
11: SIG𝑡𝑚𝑝 ← xmss_sign(𝑟𝑜𝑜𝑡, SK.seed, 𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.seed, ADRS)
12: SIG𝐻𝑇 ← SIG𝐻𝑇 ∥ SIG𝑡𝑚𝑝
13: if 𝑗 < 𝑑 − 1 then
14: 𝑟𝑜𝑜𝑡 ← xmss_pkFromSig(𝑖𝑑𝑥𝑙𝑒𝑎𝑓, SIG𝑡𝑚𝑝, 𝑟𝑜𝑜𝑡, PK.seed, ADRS)
15: end if
16: end for
17: return SIG𝐻𝑇