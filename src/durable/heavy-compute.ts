import { pbkdf2Async } from "@noble/hashes/pbkdf2.js"
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js"
import { DurableObject } from "cloudflare:workers"

import type { Pbkdf2OffloadResponse } from "../services/pbkdf2-offload"
import { b64Decode, b64Encode } from "../util"

/**
 * Stateless Durable Object that runs server-side PBKDF2-HMAC-SHA256 via
 * @noble/hashes (pure JS). The workerd native PBKDF2 cap (100k iterations)
 * doesn't apply here because noble runs as V8 compute, not through BoringSSL.
 *
 * A single DO instance ("vaultur:heavy") accepts POST /pbkdf2 with
 * { password, salt, iterations, dkLen } in base64 and returns { digest }.
 *
 * Configure by adding the VAULTUR_HEAVY binding in wrangler.jsonc. This binding
 * is required: the main Worker offloads ALL server-side PBKDF2 here and never
 * derives inline.
 */
export class HeavyCompute extends DurableObject {
	override async fetch(request: Request): Promise<Response> {
		if (request.method !== "POST") {
			return new Response("Method not allowed", { status: 405 })
		}
		const url = new URL(request.url)
		if (!url.pathname.endsWith("/pbkdf2")) {
			return new Response("Not found", { status: 404 })
		}
		const contentLength = request.headers.get("content-length")
		if (
			contentLength &&
			(!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_REQUEST_BYTES)
		) {
			return badRequest("PBKDF2 request is too large")
		}

		let rawBody: unknown
		try {
			rawBody = JSON.parse(await readBody(request))
		} catch {
			return badRequest("Invalid PBKDF2 request body or request is too large")
		}
		if (!isJsonObject(rawBody)) return badRequest("Invalid PBKDF2 request body")

		const password = decodeBase64Field(rawBody.password)
		const salt = decodeBase64Field(rawBody.salt)
		if (!password || !salt) return badRequest("Invalid PBKDF2 input")

		const iterations = rawBody.iterations
		if (!isBoundedInteger(iterations, MIN_ITERATIONS, MAX_ITERATIONS)) {
			return badRequest("Invalid PBKDF2 iteration count")
		}
		const dkLen = rawBody.dkLen
		if (!isBoundedInteger(dkLen, MIN_DK_LEN, MAX_DK_LEN)) {
			return badRequest("Invalid PBKDF2 digest length")
		}

		const digest = await pbkdf2Async(nobleSha256, password, salt, {
			c: iterations,
			dkLen
		})
		return Response.json({ digest: b64Encode(digest) } satisfies Pbkdf2OffloadResponse)
	}
}

// Keep these bounds in step with Config.passwordIterations (1..2,000,000).
// The application currently derives 32-byte digests; 64 leaves room for
// protocol-compatible callers while preventing unbounded memory allocation.
const MIN_ITERATIONS = 1
const MAX_ITERATIONS = 2_000_000
const MIN_DK_LEN = 1
const MAX_DK_LEN = 64
const MAX_INPUT_BYTES = 4 * 1024
const MAX_REQUEST_BYTES = 32 * 1024
const MAX_BASE64_LENGTH = 4 * Math.ceil(MAX_INPUT_BYTES / 3)
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/

function badRequest(message: string): Response {
	return Response.json({ error: message }, { status: 400 })
}

/** Read a request body with a hard cap even when Content-Length is absent. */
async function readBody(request: Request): Promise<string> {
	const reader = request.body?.getReader()
	if (!reader) throw new Error("missing body")
	const chunks: Uint8Array[] = []
	let size = 0
	try {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			if (!value) continue
			size += value.byteLength
			if (size > MAX_REQUEST_BYTES) {
				await reader.cancel()
				throw new Error("body too large")
			}
			chunks.push(value)
		}
	} finally {
		reader.releaseLock()
	}
	const body = new Uint8Array(size)
	let offset = 0
	for (const chunk of chunks) {
		body.set(chunk, offset)
		offset += chunk.byteLength
	}
	return new TextDecoder().decode(body)
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max
}

/** Decode only canonical, bounded base64 to avoid Buffer's permissive parsing. */
function decodeBase64Field(value: unknown): Uint8Array | null {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_BASE64_LENGTH ||
		value.length % 4 !== 0 ||
		!BASE64_RE.test(value)
	) {
		return null
	}
	const decoded = b64Decode(value)
	if (decoded.length === 0 || decoded.length > MAX_INPUT_BYTES) return null
	return b64Encode(decoded) === value ? decoded : null
}
