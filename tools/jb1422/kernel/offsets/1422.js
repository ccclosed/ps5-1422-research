// offsets/1422.js — Tier-1 offset-пакет для PS5 firmware 14.22 (сборка 2026_1027).
// Совместим по форме с window.KRW из Relapse (m2k7m / arg0WAK, 7.00–13.60).
//
// ЧТО ПОДТВЕРЖДЕНО (дампы/скан 14.22):
//   kernelData, allproc, security_flags, rootvnode, retStatic-окно.
// ЧТО НЕ ПОДТВЕРЖДЕНО (нужен дамп 14.22) и потому = null + подсказки:
//   oid.*, walkCounter, nodeMutex, rodataProbe, gadgetmap, syscall_map, wk_*.
// Код (relapse1422.js) не падает на null: он пытается ДОБЫТЬ эти значения
// сканом ядра в рантайме (discover*), а при неудаче логирует точку блокера.
//
// Значения 13.60 приведены рядом как опорная точка и для оценки дельт.

const OFFSET_KERNEL_DATA_1422 = 0x00CE0000;   // было 0x00CC0000 в 13.60, дельта +0x20000
const OFFSET_KERNEL_ALLPROC_1422 = 0x035B9EA0; // было 0x03589E80, дельта +0x30020
const OFFSET_KERNEL_SECURITY_FLAGS_1422 = 0x01A84064; // было 0x01A5C064, дельта +0x28000
const OFFSET_KERNEL_ROOTVNODE_1422 = 0x03E3B510;      // было 0x03E0B510, дельта +0x30000

// KASLR: ret-адрес в ответе RTM_GET. В 13.60 retStatic был ровно 0x00AE2DA0.
// Для 14.22 известен ОКНО 0x00AFEAF1…0x00B14191 и predict 0x00B06869 (low16 = 0x6869).
const OFFSET_RET_STATIC_PREDICT_1422 = 0x00B06869;
const OFFSET_RET_STATIC_WINDOW_1422 = { lo: 0x00AFEAF1, hi: 0x00B14191 };

window.KRW = {
	firmware: "14.22",
	built: "2026_1027",
	kernelData: OFFSET_KERNEL_DATA_1422,
	allproc: OFFSET_KERNEL_ALLPROC_1422,
	rootvnode: OFFSET_KERNEL_ROOTVNODE_1422,
	securityFlags: OFFSET_KERNEL_SECURITY_FLAGS_1422,

	kaslr: {
		mode: "rtmsg2",
		retStatic: OFFSET_RET_STATIC_PREDICT_1422,
		retLow16: 0x6869,
		window: OFFSET_RET_STATIC_WINDOW_1422,
		retSlot: 184,            // смещение ret внутри author-record (как в оригинале)
		verifyByAllproc: true,   // после вычета проверяем kbase чтением allproc
	},

	// ---- СТАБИЛЬНЫЕ поля структуры: одинаковы в 7.00…13.60, ожидаются и в 14.22 ----
	aio: {
		// Подтверждено БАЙТАМИ по дампу 13.60 (rizin 0.9.1; адреса/байты — recon/aio-waiter-vector.md §0.1).
		// 663 aio_multi_wait: handler RVA 0x3b01f0;  669 aio_submit_cmd: handler RVA 0x3b2060
		source: "scan-13.60",
		waiterSize: 0x38,        // imul rdi,r14,0x38 @0x3b0576; zone 0x1ab5a50; stride add r14,0x38 @0x3b05de
		groupWaiters: 0x50,      // aio_group+0x50 = waiter-list head: mov [r13+0x50],r14 @0x3b080c; init 0 @0x3b239a
		groupSize: 0x58,         // sizeof(aio_group): mov edi,0x58 @0x3b2360 (zone 0x1ab5970); batch imul 0x58 @0x3b23bd
		requestSize: 0x28,       // stride узлов submit_cmd: add r12,0x28 @0x3b2567 / add r15,0x28 @0x3b25bf
		group: { num: 0x00, state: 0x08, waiters: 0x50 },
		idTable: { pages: 0x220, slotStride: 0x30, entryType: 0x160 },
	},
	proc: { pid: 0x0bc, ucred: 0x040, fd: 0x048, aioInfo: 0x0c48, dynlib: 0x3e8 },
	kernelPid: 0,
	ucred: {
		uid: 0x04, ruid: 0x08, svuid: 0x0c, ngroups: 0x10, rgid: 0x14, svgid: 0x18,
		sceAuthId: 0x58, sceCaps: 0x60, sceCaps1: 0x68, sceAttrs: 0x80,
	},
	sysCoreAuthId: { lo: 0x00000007, hi: 0x48000000 },
	filedesc: { files: 0x00, cdir: 0x08, rdir: 0x10, jdir: 0x18 },
	filedescTable: { nfiles: 0x00, ofiles: 0x08, entryStride: 0x30, fileData: 0x00 },
	pipe: { count: 0x00, in: 0x04, out: 0x08, size: 0x0c, buffer: 0x10, pair: 0xe8, defaultSize: 0x4000 },
	dynlib: { syscallStart: 0xf0, syscallEnd: 0xf8, restrictFlags: 0x118, libkernelRef: 0x18 },
	vmsapce: { pRoot: 0x1d0, vmPmap: 0x2e8 },

	// ---- НЕ ПОДТВЕРЖДЕНО для 14.22: null + подсказки для рантайм-поиска ----
	oid: null,          // в 13.60: a.base 0x028cef68, b.base 0x028cee40, c.base 0x02bf1c38
	oidHint: {
		originalKind: 0x80048002,
		writableKind: 0x70048002,
		v1360: { aBase: 0x028cef68, bBase: 0x028cee40, cBase: 0x02bf1c38, cMib: [9, 8] },
		scanWindow: 0x00100000,   // искать в ±1 МиБ вокруг подсказки 13.60
		scanBaseHint: 0x028cef68,
	},
	walkCounter: null,  // в 13.60: addr 0x03d831b8, mib [9, 7]
	walkCounterHint: { addr1360: 0x03d831b8, mib: [9, 7] },
	nodeMutex: null,    // в 13.60: 0x01a9bab8
	nodeMutexHint: { v1360: 0x01a9bab8 },
	rodataProbe: null,  // в 13.60: rva 0x01379d6c
	rodataProbeHint: { rva1360: 0x01379d6c, text: "_aio_submit_cmd\u0000_aio_multi_wait" },

	// ---- Карты, которых у нас для 14.22 нет ----
	gadgetmap: null,    // в оригинале: wk_gadgetmap (rva гаджетов libkernel text)
	syscall_map: null,  // в оригинале: rva syscall-стабов libkernel
	wk: null,           // webkit-офсеты (host constructor, vtable, stack_chk_guard)

	// ---- Тюнинг гонки (перенесён из оригинала без изменений) ----
	tuning: {
		waiters: 18,
		requests: 13,
		churnBefore: 32,
		churnAfter: 256,
		sprays: 64,
		workerBlockers: 24,
		waitTimeoutUs: 10000,
	},

	// ---- Состояние переноса: что именно отсутствует (для лога/отчёта) ----
	missing: [
		"oid.a/b/c (абсолютные адреса sysctl_oid в rodata 14.22)",
		"walkCounter.addr (mib [9,7])",
		"nodeMutex",
		"rodataProbe.rva (строка _aio_submit_cmd)",
		"gadgetmap / syscall_map (rva в libkernel 14.22)",
		"wk_* (webkit-офсеты 14.22)",
	],
};

if (typeof module !== "undefined" && module.exports) module.exports = window.KRW;