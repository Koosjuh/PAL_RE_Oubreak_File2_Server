# Getting PAL Resident Evil Outbreak File #2 past DNAS

So I spent an evening trying to get my PAL copy of Resident Evil Outbreak File #2 to authenticate against my own DNAS server. The Japanese version has a private server (obsrv.org) and has for years. The US version kinda works. The PAL version? Nobody's ever gotten it working. Sony killed DNAS in April 2016 and nobody in Europe captured the handshake packets before it went down, so for ten years anyone with the European disc has just been locked out.

I got it working anyway. This is how, and it's mostly a story of me banging my head against walls and then finding out someone already solved the hard part years ago.

## What DNAS even is

Quick background in case you don't know. DNAS (Dynamic Network Authentication System) is Sony's auth layer that every online PS2 game has to phone home to before it'll let you connect to the actual game server. Your PS2 connects to something like `gate1.eu.dnas.playstation.org`, does some crypto handshake, and if Sony's server likes what it sees, your game gets to continue. If not, you get a cryptic error like `-610` or `-611` and you're done.

Sony shut the DNAS servers down in 2016 which is why basically every PS2 online game stopped working that year.

## The setup

Real PAL PS2 hardware, plugged into a UniFi Cloud Gateway Ultra. A Windows PC running Node.js and PCSX2 on the same network. The plan was to pretend to be Sony — when the PS2 tries to talk to `gate1.eu.dnas.playstation.org`, redirect it to my PC, have my PC respond convincingly enough, game moves on.

Getting the redirect was easy. UniFi has DNS override under Policy → DNS Records. One A-record:

```
gate1.eu.dnas.playstation.org  →  192.168.*.*
```

Done. Now every DNS query from the PS2 for that hostname hits my PC.

Watching the traffic was slightly harder. My UniFi attic switch is a US-8-60W which turns out cannot do port mirroring without breaking the mirrored port, which is a lovely hardware limitation that cost me an hour. The workaround: SSH into the gateway itself and run `tcpdump` on the `br2` interface. Every packet the PS2 sends gets captured raw, as it should.

First thing I saw when I triggered Network Play: the PS2 opens port 443 and sends 102 bytes starting with `0x80`. That's an SSLv2 ClientHello. SSLv2 was deprecated in 2011. My PS2's network stack is older than some of the devs currently working on this stuff.

## The first wall

Obvious first attempt: spin up a Node TLS server with a self-signed cert that has the right Common Name. Serve that. Done, right?

```
15 03 00 00 02 02 46
```

That's what I got back. TLS alert, fatal, description `0x46` — `bad_certificate`. The PS2 didn't trust my cert. No information about what it didn't like. Could be checking the CN. Could be checking the issuer. Could be the signature. Could be the public key. Could be all of them.

This is where every previous attempt at PAL has died. The cert validation logic lives inside DNAS280.IMG, a Sony binary that the game loads from the disc, and that binary is KIRK-encrypted. The PS2's crypto coprocessor decrypts it on the fly. You can dump it out of RAM but you only get the encrypted form. The decrypted code just… doesn't exist anywhere I can look at it.

## Trying to route around it

I loaded the main game ELF (`SLES_533.19`) into Ghidra and started mapping the network state machine. Outbreak's networking is one enormous function at `0x001c9b00` that dispatches through a 73-entry function pointer table at `0x00248600`. The state machine's pretty well-structured actually; I could follow what was happening.

The actual DNAS kickoff happens in `FUN_00195e00`:

```c
void FUN_00195e00(void) {
  FUN_001a2220();              // DNAS loader — this is what does SSL
  lVar2 = FUN_00195cf0();      // check DNAS result
  if (lVar2 != 0) {            // if DNAS succeeded...
    FUN_00111600();
    FUN_00101f80();
    // ... real game init ...
    _DAT_00289af0 = 1;         // set "online ready" flag
    FUN_00183350();            // actual network game code
  }
}
```

Clean. So obviously I wrote a PCSX2 cheat patch to force the success branch always taken. `bne v0, zero` → `beq zero, zero`. Unconditional branch. Save, reboot, try.

Didn't help. The SSL handshake happens *inside* `FUN_001a2220`, before the branch. By the time we hit the check, the damage is already done.

Next idea: just NOP out the DNAS module load entirely. No SSL, no handshake, force the success. That got me a black screen. Game crashed. Turns out the code after DNAS reads state that DNAS initializes — if DNAS doesn't run, there's nothing for the later code to read, so it dereferences garbage and dies.

After a few hours of this I concluded the DNAS module is load-bearing. You can't skip it. You have to actually pass it.

Which is exactly the wall everyone else hit.

## The 2016 Christmas gift

I was about ready to write this off. Went back and actually read the community docs properly instead of just skimming, and found a GitHub repo I'd kinda seen but not paid attention to: [FogNo23/DNASrep](https://github.com/FogNo23/DNASrep). It's the_fog's own DNAS server implementation, open-sourced as a "late Christmas gift" in December 2016 right before his private servers went down.

Inside `etc/dnas/` I found:

```
ca-cert.pem        ← fake VeriSign CA
cert-eu.pem        ← server cert for gate1.eu.dnas.playstation.org
cert-eu-key.pem    ← the matching PRIVATE KEY
cert-jp.pem
cert-us.pem
...
```

I decoded the EU cert. Issuer is "VeriSign, Inc. — Class 3 Public Primary Certification Authority". Subject is `gate1.eu.dnas.playstation.org`. Valid 2016-04-18 through 2026-04-16. The whole thing is self-signed — the_fog made a fake VeriSign CA and used it to sign a fake gateway cert.

This was the piece I was missing. If the PS2's DNAS module just checks the issuer *string* rather than actually chasing the signature chain up to a hardcoded Sony-approved VeriSign root, the_fog's certs will work. And the fact that his server ran publicly for years with these certs for the Japanese audience means they do.

Swapped my self-signed cert for the_fog's cert and key. Tried again. No more `0x46`. The PS2 accepted the certificate and sent back its ClientKeyExchange message — 134 bytes of RSA-encrypted premaster secret.

Progress.

## Building TLS 1.0 from scratch

Here's where it got annoying. Now that the cert was accepted, I wanted to let a real TLS library finish the handshake for me. Node's built-in TLS module refused because the PS2 sends an SSLv2-format ClientHello and Node's TLS stack won't parse that. I tried `node-forge`. Same problem. Every modern TLS library has dropped SSLv2 compatibility because SSLv2 is ancient and terrible, which is fair, except the PS2 doesn't care about my schedule.

So I wrote TLS 1.0 manually. Not the whole thing, just enough to get through a handshake with the one specific ciphersuite the PS2 wants (`TLS_RSA_WITH_RC4_128_MD5`).

Parse the SSLv2 ClientHello. Extract the 16-byte "challenge" field, left-pad to 32 bytes, that becomes clientRandom. Generate a serverRandom, send back a regular TLS 1.0 ServerHello. Send the cert chain. Send ServerHelloDone. Wait for the ClientKeyExchange.

When the PS2 sends the ClientKeyExchange, use Node's `crypto.privateDecrypt` to decrypt the premaster secret with our private key. Run the TLS 1.0 PRF (which is this weird MD5/SHA1 split-key construction they replaced with something saner in TLS 1.2) to derive the master secret. Run the PRF again to derive the key block — MAC keys and write keys for both sides. Implement RC4 (literally 30 lines of JS, it's a tiny algorithm). Initialize RC4 instances with the derived keys.

The PS2 then sends a ChangeCipherSpec and its Finished message (32 bytes: encrypted plaintext Finished plus MAC). I decrypted it. Verified the HMAC-MD5. It matched.

This was the moment I knew I was close — if the MAC verifies, then my derived keys exactly equal the PS2's derived keys, which means I have a shared secret with the PS2. The TLS plumbing works.

But the `Finished` verify_data itself — the 12-byte thing *inside* the decrypted Finished message — didn't match what I computed. The MAC was on the envelope; the content was different.

## The Finished mystery

The Finished verify_data is a PRF over the hash of every handshake message exchanged so far. If my hash differed from the PS2's hash, something about *which bytes went into the hash* was different.

Rather than guess for another hour, I had my server try five different variations and print which (if any) matched the PS2's value:

```
[     ] Synthetic TLS ClientHello (RFC-compliant)   197bd710...
[     ] Raw SSLv2 ClientHello                        098635ce...
[MATCH!] SSLv2 body only (no length)                 a3c34cd6...
[     ] Without any ClientHello                      ...
[     ] Just SSLv2 challenge                         ...
```

The winner: the PS2 hashes the SSLv2 ClientHello *body* (skipping the 2-byte length header) as its ClientHello in the handshake hash. This isn't what RFC 2246 Appendix E.2 specifies. It's a Sony-specific quirk of their SSL implementation.

Can't guess that one. Have to test.

With that fixed, the handshake closed cleanly. TLS done.

## First decrypted DNAS request

The moment the handshake finished, the PS2 sent encrypted application data. I decrypted it and stared at the console for a good thirty seconds:

```
POST /eu-gw/v2.5_i-connect HTTP/1.0
User-Agent: open sesame asdfjkl
Content-Type: image/gif
Content-Length: 308

[308 bytes of encrypted payload]
```

A few things about this:

DNAS is HTTP. Just plain HTTP POST over TLS. All the SSLv2 ceremony and the weird cert chain and the RC4 cipher — that's all just transport wrapper around a normal-ish HTTP request.

The User-Agent is `open sesame asdfjkl`. This is what the_fog's DNAS client sends. A fossil from 2003 that someone typed as a placeholder and forgot to change.

The Content-Type is `image/gif` which it obviously isn't. Someone at Sony/Capcom twenty years ago was probably trying to get through corporate proxies that block unknown MIME types. It works.

The body itself is a structured blob. First 4 bytes are a query type. Offset 0x2c is an 8-byte game ID. The rest is encrypted.

## The v2.5 encryption

the_fog's DNASrep repo includes a PHP script that handles the response side of this protocol. The `v2.5` version is the weird one:

1. SHA1 one region of the request body (offset 0x34, length 0x100)
2. SHA1 another region (offset 0x48, length 0xec)
3. Concatenate the first 0x14 bytes of the second hash with the first 0x0c bytes of the first hash. That's your 32-byte "fullkey"
4. Split the fullkey into four 8-byte chunks: three 3DES keys and an XOR seed
5. Load the response packet file for this game ID / query type
6. Encrypt 32 bytes at offset 0xc8 with those derived keys
7. Then encrypt 288 bytes at offset 0x28 using *different* hardcoded "envelope" keys

Each encryption pass is 3DES-EDE but with a custom chain mode. Each plaintext block gets XORed with a rolling key. After encryption, the ciphertext *becomes* the new rolling key. It's CBC-ish but not exactly CBC.

Porting this to Node 24 hit me with a surprise: Node recently deprecated plain `des-ecb`, so my first implementation crashed with `error:0308010C:digital envelope routines::unsupported`. The fix was using `des-ede3-ecb` (which does all three DES operations internally) with a concatenated 24-byte key.

## The moment it worked

I downloaded every packet file from the DNASrep GitHub repo. Hundreds of captured DNAS query/response pairs, tagged by game ID. Mostly JP. Some US. A few EU. No real way to know if my PAL copy's game ID would match any of them, but it was worth a shot.

Started the server, booted the game fresh, triggered Network Play:

```
=== New connection from 192.168.2.196:56007 ===
[SSLv2 ClientHello] 102 bytes
[TLS] Keys derived
[TLS] Client Finished: VERIFIED
[TLS] Handshake complete

*** COMPLETE DNAS REQUEST ***
URL: /eu-gw/v2.5_i-connect
qrytype=01080000 gameID=f4c26cd13fb1df55
Looking up: packets/f4c26cd13fb1df55_01080000
Found packet, 328 bytes
Encrypted response, 328 bytes
Sent 393 byte response
ALERT level=1 desc=0
PS2 disconnected
```

The `alert level=1 desc=0` is `close_notify`. Normal TLS goodbye. Not an error.

On the PS2, the DNAS authentication screen filled to 100%.

Ten years. Done.

## What actually happened here

This wasn't clever. It was archaeology. Every piece that made this work had been published years ago by someone who assumed the last person had already tried.

the_fog released DNASrep in 2016 with working EU certificates. The obsrv community captured the packets. Sony's design assumed its servers were the only thing capable of running the protocol, and once those servers went down the protocol itself was preserved in frozen form on GitHub waiting for someone to pick it up.

What was missing was just the glue. The PAL game wants to do SSLv2 ClientHello. Node refuses to speak SSLv2. node-forge refuses. Every TLS library refuses. Bridging that meant writing TLS 1.0 by hand with a specific Sony-quirk modification to how the handshake hash is computed, then gluing that to a PHP-based DNAS protocol that was designed to run on Apache.

Also: pure luck that my PAL game's ID `f4c26cd13fb1df55` happened to be in the captured packets. Someone, sometime in early 2016, sat in front of a European PS2 with a packet sniffer and authenticated to the real Sony EU gateway with their copy of Outbreak File #2. I have no idea who they were. They made this possible.

## What's next

DNAS is just the gate. After DNAS passes, the game tries to connect to the actual Capcom game server — `app01.reo.capcom.sf.yav4.com` based on strings I pulled out of the binary. That server's protocol is a completely different beast and I have zero captures of what it speaks. That's the next project.

For now though I have a PAL PS2 that says "yes" to my Node.js server running on a laptop, which is ten years further than anybody else has gotten.

## The things I tried that didn't work

For completeness, because writeups that only show the successful path are misleading:

- Patching the game to skip DNAS entirely. The DNAS code is too load-bearing. Downstream stuff reads state that only exists if DNAS actually ran.
- Self-signed cert with "VeriSign" in the issuer. Rejected as `0x46`.
- Dumping `insdnas.bin` from EE RAM to reverse it. It's encrypted in RAM too.
- `node-forge` TLS stack. Refuses SSLv2 ClientHello wrapper.
- RFC 2246 Appendix E.2 handshake hash format. Sony's implementation disagrees with the RFC.

## The things that worked

- the_fog's cert/key/CA chain from the DNASrep repo
- Manual TLS 1.0 with RC4_128_MD5
- Using the SSLv2 body (without the 2-byte length prefix) as the handshake hash ClientHello
- 3DES-EDE via Node's `des-ede3-ecb` instead of the deprecated `des-ecb`
- SHA1-derived per-request keys layered under fixed envelope keys
- My PAL game ID being in the captured packets by sheer luck

---

Thanks to the_fog for the 2016 gift that made any of this possible, and to obsrv.org for keeping the scene alive. All reverse engineering done on my own legitimately owned hardware and software.
