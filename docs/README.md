# Shrinking SPHINCS+: SNARK Aggregation for Post-Quantum Blockchains

MEng thesis by **Nicolas Schleicher**, Imperial College London, Department of
Computing (Joint Mathematics and Computer Science), 2026.
Supervised by Prof. William Knottenbelt; second marker Dr. Jonathan
Passerat-Palmbach.

## Overview

Hash-based signatures such as SPHINCS+ are a convincing post-quantum
replacement for the elliptic-curve signatures that blockchains like Bitcoin and
Ethereum currently rely on — but at 8–16 KiB they are roughly 120× larger, so
direct replacement is infeasible and signature aggregation is required. This
thesis provides an end-to-end evaluation of two SNARK-based aggregation systems,
CairoVM (for design-space exploration) and the Ethereum Foundation's leanVM (for
a constraint-optimal prototype). Exploiting leanVM's field-native primitives —
chunk-based bit decomposition and JMP-range specialisation for Merkle tree
traversal — the leanVM prototype reaches compression break-even at 64 signatures
and a 20× compression ratio at up to 140 signatures/second on cloud hardware,
outperforming the break-even of LaBRADOR, the leading lattice-based scheme.

## How to cite

If you use this work, please cite it as:

```bibtex
@mastersthesis{schleicher2026sphincs,
  title        = {Shrinking {SPHINCS+}: {SNARK} Aggregation for Post-Quantum Blockchains},
  author       = {Schleicher, Nicolas},
  school       = {Imperial College London},
  year         = {2026},
  month        = jun,
  type         = {{MEng} thesis},
  address      = {London, United Kingdom},
  note         = {Department of Computing}
}
```
