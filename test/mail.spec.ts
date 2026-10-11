import { describe, expect, it } from "vitest"

import type { Config } from "../src/config"
import { escapeHtml, mail, type Mailer } from "../src/services/mail"

const config = { domain: "https://vault.test" } as Config

function captureMailer() {
	const messages: Array<{ to: string; subject: string; html: string; text: string }> = []
	const mailer: Mailer = {
		enabled: true,
		async send(to, subject, html, text) {
			messages.push({ to, subject, html, text })
		}
	}
	return { mailer, messages }
}

describe("transactional mail escaping", () => {
	it("escapes text and HTML attribute characters", () => {
		expect(escapeHtml(`<img src="x" onerror='alert(1)'>&`)).toBe(
			"&lt;img src=&quot;x&quot; onerror=&#39;alert(1)&#39;&gt;&amp;"
		)
	})

	it("keeps escaped hints safe in HTML and readable in the text alternative", async () => {
		const { mailer, messages } = captureMailer()
		await mail.passwordHint(mailer, config, "user@example.test", `<b>keep & safe</b>`)

		expect(messages).toHaveLength(1)
		const message = messages[0]!
		expect(message.html).toContain("&lt;b&gt;keep &amp; safe&lt;/b&gt;")
		expect(message.text).toContain("<b>keep & safe</b>")
	})

	it("removes subject newlines and escapes dynamic organization content", async () => {
		const { mailer, messages } = captureMailer()
		await mail.orgInvite(
			mailer,
			config,
			"user@example.test",
			`<img src=x onerror=alert(1)>\r\nBcc: attacker@example.test`,
			"org-id",
			"member-id",
			"token",
			false
		)

		expect(messages).toHaveLength(1)
		const message = messages[0]!
		expect(message.subject).not.toMatch(/[\r\n]/)
		expect(message.html).toContain("&lt;img src=x onerror=alert(1)&gt;")
		expect(message.html).not.toContain("<img src=x")
	})

	it("does not emit dangerous URL schemes in links", async () => {
		const { mailer, messages } = captureMailer()
		await mail.welcome(mailer, { domain: "javascript:alert(1)" } as Config, "user@example.test")

		expect(messages[0]!.html).not.toContain('href="javascript:')
		expect(messages[0]!.html).toContain('href="#"')
	})
})
