To Have a Token Evolve **RUN**, starting with the NCFT/SFT:

```text
NCFT
Token ID: 605d50076cdad3c5
Name: Arti
Issuance TX:
d417007e30571294c08fb762ca0c0a3f251a905baf449a60714ea8c4dad91402
```


1. **Open the AI Evolution screen.** In the running advanced wallet, from the main menu enter:

```text
17 AI TOOLS
```

That opens:

```text
TOKEN / AI TOOLS
1. Create AI Token
2. AI Evolution
0. Back
```

Choose:

```text
2
```

Then the AI Evolution menu should show:

```text
1. Preview AI Evolution
2. Commit Exact Preview
3. View Token History
0. Back
```

That two-stage preview/commit flow is intentional: preview writes nothing; only the exact `COMMIT` operation persists the record and queues the anchor. 

3. **Generate NCFT epoch 1.** Choose:

```text
1
```

You should see both confirmed tokens. Select:

```text
Arti [NCFT]
TokenID: 605d50076cdad3c5
```

For provider select:

```text
1
```

For the Demo I will use this A.I ( nemotron ) but you can choose which yours is.... Make sure your .env is set up correctly:

```text
nemotron
```

For the trigger/reason enter:

```text
fresh-genesis-epoch1-Test 
```

The system will make the AI call and generate a preview.

The critical thing to inspect is:

```text
Token       : 605d50076cdad3c5
Type        : NCFT
Provider    : nemotron
Trigger     : fresh-genesis-epoch1
Epoch       : 0 -> 1
PreviousHash: <64 hex>
NewHash     : <64 hex>
```


4. **Commit that exact preview.** Press Enter to return to the AI Evolution menu, then choose:

```text
2
```

The wallet should show the same token, epoch transition, previous hash and new hash.

At:

```text
Confirmation:
```

type exactly:

```text
COMMIT
```

uppercase, no extra characters.

The expected result is approximately:

```text
AI EVOLUTION COMMIT ACCEPTED

Token    : 605d50076cdad3c5
Epoch    : 1
Meta Hash: <hash>

TOKEN-AI-02A atomically persisted epoch/latest/anchor_queue.
...
Confirmation is NOT claimed here.
```



5. **Once the anchor is definitely in the mempool (31 shows Mempool), mine it.** Start the GPU/CPU miner, or use the MENU 34/35 

```text
17 Ai Tools 
→ 2 AI Evolution
→ 1 Preview AI Evolution
→ select Arti / 605d50076cdad3c5
→ provider 1 / nemotron
→ trigger: fresh-genesis-epoch2
```
