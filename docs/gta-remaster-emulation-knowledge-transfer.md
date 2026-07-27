<!--
Copyright (C) 2026 SharpEmu Emulator Project
SPDX-License-Identifier: GPL-2.0-or-later
-->

# GTA Remaster PS5 Emulation — Knowledge Transfer

Portable findings from booting **GTA: San Andreas – The Definitive Edition**
(`PPSA03524` v01.003.000) and **GTA V** (`PPSA04264`) toward their main menus.

This document is engine/HLE-focused so it transfers to a **different emulator**
(target: Kyty). All binary addresses are given as **IDA file offsets**
(imagebase 0) — never as runtime VAs — because the guest module base varies per
run (see §6.2). Add the target emulator's module base to use them.

Scope/safety: everything below is behavioral interoperability analysis of a
legally-owned, locally-dumped title (function offsets + observed runtime
behavior). No keys, decrypted assets, or proprietary code are reproduced.

---

## 0. TL;DR for the new emulator

1. **Both GTA remasters are Unreal Engine titles** (UE "Gameface" project) using
   **Scaleform** for UI and **sceAvPlayer + ffmpeg-style decode** for intro
   movies (the R★ stinger). Getting to the menu means surviving: intro movie
   playback → UE MediaFramework → Scaleform frontend.
2. **Two generic emulator bugs were the big wins** (§2). One (a mis-encoded CAS
   in generated sync code) causes the community-known *"video freezes, audio
   keeps going"* per-movie freeze. The other (RAGE/Scaleform `memory:` file
   device) blocks GTA V's menu. Both are worth checking/porting immediately.
3. **The remaining hard blocker** is a **UE MediaFramework media-tick
   starvation** (§3): a circular producer/consumer stall that engages ~554 ms
   into the intro movie. Fully reverse-engineered here; prime fix hypothesis is
   audio-output played-sample/clock feedback (§3.5).

---

## 1. The titles and their boot media path

- **GTA SA:DE** `PPSA03524`, **GTA V** `PPSA04264`. Both: UE4-derived engine,
  main module ~126 MB, `Gameface.uproject` command line, Scaleform UI.
- Boot plays intro movie(s): `…/gameface/Content/Movies/1080/
  GTA_SA_RSTAR_STINGER_FINAL_1920x1080.mp4` (~16.3 s, H.264 + AAC 48 kHz stereo).
- Movie is driven through **sceAvPlayer** (HLE) with **AV sync mode 1**
  (audio-master). Video is pulled via `sceAvPlayerGetVideoData`, audio via
  `sceAvPlayerGetAudioData`; the title also registers an **event callback**
  (state Ready/Play/Pause/Stop).
- The UE side wraps AvPlayer in its **MediaFramework** (FMediaPlayer / a
  media-ticker thread + sample sinks feeding the audio mixer and a video
  texture).

Observed end states while wedged: **video frozen** (single frame, HUD ~1.8 fps),
**audio continues briefly then stops**, boot never advances. This matches the
community reports for these titles on other emulators — so the mechanism in §3
is very likely engine-generic, not sharpemu-specific.

---

## 2. GENERIC BUGS FOUND & FIXED (port/verify these first)

### 2.1 Mis-encoded CAS in generated synchronization code — the "movie freeze"

**Impact:** the community-visible *per-movie coin-flip freeze* (video freezes,
audio keeps playing for a bit) — reproduced on GTA V North Yankton and GTA SA
intro. Root caused by CPU capture (a thread burning 2m31s spinning).

**Root cause:** sharpemu emits a per-fault "managed-entry" serialization
spinlock in machine code. Its acquire compare-exchange was emitted as
`lock cmpxchg [rcx], r10` (`F0 4C 0F B1 11`) but must be
`lock cmpxchg [r9], r10` (`F0 4D 0F B1 11`). The **REX.B bit was missing**
(`0x4C` vs `0x4D`), so the CAS targeted `[rcx]` (stack garbage) instead of the
lock word in `[r9]`. Result: a thread randomly spins forever on an already-free
lock. Fix: `0x4C → 0x4D` at both emission sites.

**Transfer to Kyty:** Kyty is a static recompiler/JIT with a different execution
model, so this exact stub won't exist. The **transferable lesson**: audit any
hand-emitted x86-64 atomic/lock instructions in generated trampolines,
exception-entry glue, or TLS/lock fast-paths — verify the **REX prefix encodes
the intended base register** (`REX.B` selects r8–r15 for the r/m field).
A single wrong prefix bit silently redirects an atomic to the wrong address and
produces exactly this "random freeze under contention" signature.

### 2.2 RAGE/Scaleform `memory:` in-memory file device — GTA V menu blocker

**Impact:** GTA V hot-loops `stat()` on paths like
`memory:$0x14D4060000,101371,0:00158_hud_reticle.gfx` (RAGE's in-memory file
device for Scaleform `.gfx` assets). If `stat` returns not-found, the frontend
never loads → stall before menu. Implementing it advanced GTA V to an
**interactive frontend menu**.

**Path grammar:** `memory:$<addrHex>,<sizeDec>,<offsetDec>:<name>`
- `addrHex` — in-memory blob address (optional `0x` prefix)
- `sizeDec` — byte length (use as the stat size)
- `offsetDec` — offset within the blob
- `name` — human label

**Fix:** in the kernel `stat` (and by extension `open`) HLE, detect the
`memory:` device, parse the fields, and return a synthetic regular-file stat
with `st_size = sizeDec` and current timestamps.

**Transfer to Kyty:** directly applicable — same engine, same paths. Kyty's
`sceKernelStat`/file-open HLE must recognize the `memory:` device for RAGE/
Scaleform. This is a RAGE-engine requirement, not sharpemu-specific.

---

## 3. THE HARD BLOCKER — UE MediaFramework media-tick starvation (unsolved)

Fully reverse-engineered from the SA eboot. This is the intro-movie wedge.

### 3.1 Symptom / repro

- Coin-flip per run: **(a)** movie 1 plays fully to `end_of_stream` (16.343 s)
  then wedges post-movie; **(b)** wedges mid-movie-1 at **~554 ms**.
- Both fail to progress. Video freezes; the audio *mixer* thread keeps running
  (so audio hardware output continues) while the *movie's* audio delivery stops.
- HUD ~1.8 fps ≈ **554 ms/frame** — the main thread is gated ~554 ms each frame
  waiting on the media, times out, renders the frozen frame, repeats.

### 3.2 The media-tick object graph (IDA offsets, imagebase 0)

| Offset | Role |
|---|---|
| `0x3777650` | **FMediaTicker::Run** — the task-ring worker thread body (the "spinner") |
| `0x37764B0` | media object **ctor** (328 bytes) |
| `0x3777490` | media object **dtor** |
| `0x3775FE0` | UE class-factory **static-init** (registers the class; name `L"…tTargets"`) |
| `0x1BF1EB0` | **work-source factory** — builds the refcounted event wrapper |
| `0x1BF2390` | **inner FPThreadEvent ctor** (installs vtable `qword_5DF0D10`) |
| `0x1BFEA40` | **FPThreadEvent::Trigger** (vtable slot im2) |
| `0x1BF5310` | **FPThreadEvent::Wait** (vtable slot im4) |
| `0x1BFEA90` | FPThreadEvent::Reset (im3) |
| `0x1BFEA30` | FPThreadEvent getter (`[event+0x17]`) (im1) |
| `0x1C044B0` | work-source Wait **thunk** (forwards to inner event) |
| vtable `0x5F9B360` | media-ticker sub-object vtable |
| vtable `0x5DF1C08` | work-source wrapper vtable |
| vtable `0x5DF0D10` | inner FPThreadEvent vtable |

Layout:
- **Media object** (ctor `0x37764B0`, 328 B): embeds the FMediaTicker sub-object
  at **+0xA8** (vtable `0x5F9B360`); two **capacity-4** work rings at +96 and
  +184; the **work-source** at **+0xF8** = `sub_1BF1EB0(1, …)`.
- **FMediaTicker::Run** (`0x3777650`): `[ticker+0x28]` bit0 = stop flag (loop
  runs while clear). Body: call `workSource.Wait(INFINITE)`; if woken → drain the
  task ring `[ticker+0x40]` (count at `[ticker+0x38]`/`[+0x48]`, entries tagged
  `0x04_00000001`); else idle via `sub_49E17D0(5000)` (~5 ms sleep) +
  `sub_49E1640` (gettimeofday) and re-poll.
- **Work-source** (vtable `0x5DF1C08`): 24-byte refcounted wrapper; `method[4]`
  (`0x1C044B0`) is a thunk that forwards to the **inner** object at
  `[wrapper+16]` (`inner.vtable[4]`, timeout forwarded in rdx).
- **Inner event** (ctor `0x1BF2390`, vtable `0x5DF0D10`): an **FPThreadEvent**
  (manual-reset; ctor arg = 1). **Signaled flag = `[event+0x20]`**;
  **wait cond = `[event+0x40]`**.
  - **Trigger** (`0x1BFEA40`): lock; if manual-reset `[event+0x17]` set
    `[event+0x20]=2` + broadcast, else `[event+0x20]=1` + signal; unlock.
  - **Wait** (`0x1BF5310`): block on cond `[event+0x40]` until
    `[event+0x20]`∈{1,2}; auto-reset 1→0; timeout `0xFFFFFFFF` = infinite.

### 3.3 Wedge mechanism (what actually happens)

1. FMediaTicker Runs, waiting on the inner event for work.
2. During the first **~27 audio frames (~554 ms)** the event **is Triggered**
   (playback proceeds; `GetAudioData` is pulled 1024 samples/frame = 21.3 ms).
3. At ~554 ms the **producer stops Triggering** — a buffer/threshold point. The
   ticker's waits then time out, and the whole pipeline enters a **circular
   starvation**: GameThread ↔ RenderThread ↔ FMediaTicker.
4. Steady-state census:
   - **Running:** FMediaTicker (spin/poll), AudioMixerRenderThread
     (free-running — this is why audio hardware output continues), minor
     heartbeats (Http/RTHeartBeat/SceNet).
   - **Blocked** on the UE cond wrapper (import ret in the `pthread_cond_wait`
     glue): **all task-graph PoolThreads (0–18), RHIThread, AudioThread,
     AgcSubmissionThread, AgcCleanupThread, SystemEventGatherThread, FAsyncPurge,
     RenderThread 1** (which rendered ~12.5 M imports then parked).
   - **GameThread** is the *primary* (loader) thread, **not** a
     `scePthreadCreate` thread, so it's absent from the pthread census; it runs
     ~10 % CPU in the intro/movie-wait loop.
   - The entire UE **task graph is idle** — no media/decode tasks are ever
     enqueued once the producer stops.

### 3.4 Eliminations (do NOT re-chase these on Kyty)

- **NOT** a frozen wall clock — `gettimeofday` advances throughout.
- **NOT** a lost pthread cond signal — the wait primitive works; timeouts are
  genuine (the flag is simply never set).
- **NOT** an emulator wait-primitive bug — FPThreadEvent Wait via
  `pthread_cond_(timed)wait` functions correctly.
- **NOT** a startup ffmpeg-spin-up underrun — priming the audio decoder at Start
  (prebuffer) wedges at the *same* ~27-frame point.
- **NOT** `sceAudioOut2` queue backpressure — `GetQueueLevel` returns
  empty/drainable; the sink is never gated there.
- **NOT** `sceAudioOut2PortGetState` — it returns a static blob with no
  played-sample/clock counter.
- The producer is **virtual-only** (`Trigger` has zero direct xrefs — always
  called through `vtable[2]`), so it cannot be named by static analysis alone.

### 3.5 Prime hypothesis for the fix (test this on Kyty)

The stall engages at a **fixed ~554 ms buffer threshold**, independent of the
audio prebuffer/queue models. The most likely cause is the **audio-output
played-position / media master-clock feedback**:

> In AV-sync-mode-1 (audio master), the UE media sink buffers ~554 ms ahead,
> then waits for the **playback position (rendered/played sample count or output
> timestamp)** to advance before requesting/producing the next samples. If the
> emulator's `sceAudioOut`/`sceAudioOut2` path does **not** report an
> **accurately advancing played-sample count / output time** that the guest
> media clock consumes, the sink believes it is still full, stops pulling from
> AvPlayer, stops Triggering the media-tick event, and the pipeline starves.

**Concrete Kyty action items:**
- Ensure `sceAudioOutOutput`/`sceAudioOut2` advance a **monotonic played-sample
  counter** and any **output-timestamp query** the title reads, paced to the DAC
  rate (48 kHz), not free-running or frozen.
- Verify whichever export the UE audio clock samples (candidates:
  `sceAudioOut2ContextGetQueueLevel` "level", a played-samples/`GetLastOutputTime`
  query, or the AvPlayer-delivered audio timestamp) returns a value that keeps
  advancing across the 554 ms boundary.
- To confirm the mechanism cheaply: log `pthread_cond_signal/broadcast` on the
  media event's cond (`[event+0x40]`) and confirm signals **cease at ~554 ms**;
  then find the last thread that signaled it (the producer) and what it waited
  on next.

### 3.6 Guardrails (learned the hard way)

Do **not** "fix" this with a title hack: forced EOS, a media-clock deadline
watchdog, forcing FEvents, or editing the media clock. Those mask the bug and
break other titles. The correct fix is generic playback-clock/feedback
correctness.

---

## 4. GTA V status

- Same **CAS freeze (§2.1)** — was the North Yankton freeze; fixed.
- **`memory:` stat (§2.2)** → reached an **interactive frontend menu**.
- **Remaining:** (a) Scaleform frontend not composited (GPU/render-target
  follow-up — the menu is interactive but not visibly drawn); (b) an
  async-compute (`acb.compute`) cross-queue label producer shows "none observed"
  — needs a live AGC trace to confirm the cross-queue GPU label wait.

---

## 5. Reusable tooling & methodology

- **Guest object-graph sampling via host thread context.** Because sharpemu runs
  guest code at guest VA == host VA (direct execution), a background sampler can
  `GetThreadContext` a guest thread and read its registers + walk guest memory
  (vtables, object fields, even disassemble at the guest RIP with an x86 decoder)
  — all live. This is how the whole §3.2 graph was recovered. Kyty's recompiler
  model differs, but the **principle** (dump the media object/event graph at a
  known code point) transfers via Kyty's own memory access.
- **UE strips RTTI** — no C++ type names in the binary. Identify classes by their
  **ctor/dtor vtable-assignment pairs** and xref patterns, not type_info.
- **Virtual methods have no useful direct xrefs** — to name a producer/caller you
  need a runtime capture (flag-write watch or cond-signal thread correlation),
  not static xref.

---

## 6. Environment/tooling pitfalls (so you don't relearn them)

### 6.1 Live debuggers throttle a direct-execution emulator
A CDB software/hardware breakpoint on any *hot* path (e.g. a generic
`FEvent::Trigger`) slows the emulator so much it never reaches movie playback.
CDB is only useful **post-mortem** on an *already-wedged* process (`!runaway`,
`~*k`, memory reads). It **cannot** walk guest call stacks (guest frames aren't
on the host stack). For live capture use **in-emulator logging/instrumentation**.

### 6.2 Module base varies per run
The main module loads at the preferred base **`0x800000000`** when free, else it
is **relocated** (one observed delta was `0x7FFFDA770`). Always read the loader's
reported image base for the run and compute runtime addresses as
`base + IDA_offset`. Never hardcode a runtime VA across runs.

### 6.3 Movie decode needs an un-sandboxed process
The intro movie is decoded by spawning an ffmpeg/ffprobe child. If the emulator
is launched inside a restricted sandbox, the **grandchild ffprobe spawn is
blocked** (`Access is denied`) and the movie never loads — a *harness* artifact,
not an emulator bug. Launch the emulator outside such a sandbox for movie tests.

### 6.4 Observed NIDs / helper subs (SA eboot)
- `Op8TBGY5KHg` — UE cond-wrapper park (blocked threads' import return)
- `27bAgiJmOh0` — `pthread_cond_timedwait`
- `tn3VlD0hG60` — `scePthreadMutexUnlock`
- `EI-5-jlq2dE` — `scePthreadGetthreadid`
- `PE2zHMqLSHs` — audio-mixer render-thread import
- Helper subs: `0x49E11C0`/`0x49E11E0` lock/unlock, `0x49E1220` cond broadcast,
  `0x49E6FF0` cond signal, `0x49E1230`/`0x49E1240` cond timedwait/wait,
  `0x49E1640` gettimeofday, `0x49E17D0` usleep.

---

## 7. Reference branches (sharpemu fork, for the diffs)

- `veh-entry-cas-lock-cmpxchg-r9` — the CAS/REX.B fix + encoding regression test.
- `rage-memory-file-stat` — the `memory:` device stat fix + parse tests.
- `sa-media-ticker-diagnostics` — the guest-RIP sampler extensions used to
  recover §3 (dumps registers, object qwords, disassembly, and the media
  event/work-source vtable chain), plus the investigation source snapshot.

---

## 8. One-paragraph handoff

The two remaster titles are UE + Scaleform + sceAvPlayer. Port the `memory:`
file-device stat (trivial, unblocks GTA V's menu) and audit generated atomic
encodings for the CAS/REX.B class of bug (the movie-freeze). The remaining wall
is a UE MediaFramework media-tick starvation that engages ~554 ms into the intro
movie: FMediaTicker waits on an FPThreadEvent that the producer stops Triggering
at a buffer threshold, idling the whole task graph. It is not a clock, signal, or
wait-primitive bug — the strongest lead is that the emulator's audio-output
played-sample/clock feedback doesn't advance, so the audio-master media sink
stalls at its buffer depth. Make `sceAudioOut(2)` report an accurate, advancing
played-position/output-timestamp and re-test across the 554 ms boundary.
