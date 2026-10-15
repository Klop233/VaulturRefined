import { SELF } from "cloudflare:test"
import { describe, expect, it, vi } from "vitest"

const jsonHeaders = (ip: string) => ({
	"Content-Type": "application/json",
	"CF-Connecting-IP": ip
})

describe("public registration hardening", () => {
	it("rejects an oversized registration payload before parsing it", async () => {
		const body = JSON.stringify({
			email: "too-large@vaultur.dev",
			name: "x".repeat(70 * 1024),
			masterPasswordHash: "hash",
			key: "key",
			kdf: 0,
			kdfIterations: 100_000
		})
		const response = await SELF.fetch("https://vault.test/identity/accounts/register", {
			method: "POST",
			headers: jsonHeaders("198.51.100.40"),
			body
		})

		expect(response.status).toBe(413)
		const error = (await response.json()) as Record<string, any>
		expect(error.object).toBe("error")
		expect(error.errorModel.message).toBe("Payload Too Large")

		// The Bitwarden clients also use the /api alias; it must have the same
		// prelogin body guard instead of being an unbounded parser bypass.
		const apiResponse = await SELF.fetch("https://vault.test/api/accounts/prelogin", {
			method: "POST",
			headers: jsonHeaders("198.51.100.40"),
			body
		})
		expect(apiResponse.status).toBe(413)
	})

	it.each(["/accounts/prelogin", "/accounts/prelogin/password"])(
		"rejects oversized prelogin payloads on %s",
		async (path) => {
			const response = await SELF.fetch(`https://vault.test/identity${path}`, {
				method: "POST",
				headers: jsonHeaders("198.51.100.42"),
				body: JSON.stringify({ email: "x".repeat(9 * 1024) })
			})
			expect(response.status).toBe(413)
		}
	)

	it.each(["/accounts/prelogin", "/accounts/prelogin/password"])(
		"rate-limits repeated prelogin requests by client IP on %s",
		async (path) => {
			// Keep the burst in one fixed window even on slow test runners.
			const clock = vi.spyOn(Date, "now").mockReturnValue(Date.now())
			try {
				const url = `https://vault.test/identity${path}`
				const headers = jsonHeaders("198.51.100.41")
				for (let i = 0; i < 10; i++) {
					const response = await SELF.fetch(url, {
						method: "POST",
						headers,
						body: JSON.stringify({ email: `unknown-${i}@vaultur.dev` })
					})
					expect(response.status).toBe(200)
				}

				const blocked = await SELF.fetch(url, {
					method: "POST",
					headers,
					body: JSON.stringify({ email: "unknown-final@vaultur.dev" })
				})
				expect(blocked.status).toBe(429)
				expect(((await blocked.json()) as Record<string, any>).errorModel.message).toContain(
					"Too many requests"
				)
			} finally {
				clock.mockRestore()
			}
		}
	)
})
