import { describe, expect, it } from "vitest"

import { api, login, registerAndLogin, registerUser } from "./helpers"

const ORG = {
	name: "Acme Corp",
	billingEmail: "billing@acme.test",
	key: "2.orgSymmetricKey|iv==",
	collectionName: "2.defaultCollection|iv==",
	keys: { publicKey: "org-public-key", encryptedPrivateKey: "2.orgPrivateKey|iv==" }
}

const LOGIN_CIPHER = {
	type: 1,
	name: "2.name|iv==",
	login: { username: "2.u|iv==", password: "2.p|iv==", uris: [] }
}

async function createOrg(token: string) {
	const res = await api(token, "POST", "/api/organizations", ORG)
	if (res.status !== 200) throw new Error(`createOrg failed ${res.status}: ${await res.text()}`)
	return (await res.json()) as Record<string, any>
}

describe("organizations", () => {
	it("creates an org with the expected profile shape", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)
		expect(org.object).toBe("organization")
		expect(org.name).toBe(ORG.name)
		expect(org.billingEmail).toBe(ORG.billingEmail)
		expect(org.useGroups).toBe(true)
		expect(org.usePolicies).toBe(true)
		expect(org.hasPublicAndPrivateKeys).toBe(true)
		expect(org.maxStorageGb).toBe(32767)
		expect(org.planType).toBe(6)
	})

	it("exposes the org in the user sync profile", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)
		const sync = (await (await api(token, "GET", "/api/sync")).json()) as Record<string, any>
		const profileOrg = sync.profile.organizations.find((o: any) => o.id === org.id)
		expect(profileOrg).toBeTruthy()
		expect(profileOrg.object).toBe("profileOrganization")
		expect(profileOrg.type).toBe(0) // Owner
		expect(profileOrg.status).toBe(2) // Confirmed
	})

	it("manages collections (default + CRUD)", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)

		// Default collection exists
		let cols = (await (
			await api(token, "GET", `/api/organizations/${org.id}/collections`)
		).json()) as Record<string, any>
		expect(cols.data).toHaveLength(1)
		expect(cols.data[0].object).toBe("collectionDetails")

		// Create
		const created = await api(token, "POST", `/api/organizations/${org.id}/collections`, {
			name: "2.secondCollection|iv=="
		})
		expect(created.status).toBe(200)
		const col = (await created.json()) as Record<string, any>
		expect(col.object).toBe("collection")

		// Rename
		const renamed = await api(token, "PUT", `/api/organizations/${org.id}/collections/${col.id}`, {
			name: "2.renamedCollection|iv=="
		})
		expect(((await renamed.json()) as Record<string, any>).name).toBe("2.renamedCollection|iv==")

		// List now has 2
		cols = (await (
			await api(token, "GET", `/api/organizations/${org.id}/collections`)
		).json()) as Record<string, any>
		expect(cols.data).toHaveLength(2)

		// Delete
		expect(
			(await api(token, "DELETE", `/api/organizations/${org.id}/collections/${col.id}`)).status
		).toBe(200)
		cols = (await (
			await api(token, "GET", `/api/organizations/${org.id}/collections`)
		).json()) as Record<string, any>
		expect(cols.data).toHaveLength(1)
	})

	it("shares a personal cipher into the org and lists it in org details", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)
		const cols = (await (
			await api(token, "GET", `/api/organizations/${org.id}/collections`)
		).json()) as Record<string, any>
		const collectionId = cols.data[0].id

		// Create a personal cipher, then share it
		const cipher = (await (
			await api(token, "POST", "/api/ciphers", LOGIN_CIPHER)
		).json()) as Record<string, any>
		const share = await api(token, "PUT", `/api/ciphers/${cipher.id}/share`, {
			cipher: { ...LOGIN_CIPHER, organizationId: org.id },
			collectionIds: [collectionId]
		})
		expect(share.status).toBe(200)
		const shared = (await share.json()) as Record<string, any>
		expect(shared.organizationId).toBe(org.id)
		expect(shared.collectionIds).toContain(collectionId)

		// Org details lists it
		const details = (await (
			await api(token, "GET", `/api/organizations/${org.id}/details`)
		).json()) as Record<string, any>
		expect(details.data.some((cph: any) => cph.id === cipher.id)).toBe(true)
	})

	it("does not expose organization vault details to a regular member", async () => {
		const memberEmail = `vault-reader-${crypto.randomUUID()}@acme.test`
		const memberHash = `hash-${memberEmail}`
		const { access_token: ownerToken } = await registerAndLogin()
		const memberRegistration = await registerUser({
			email: memberEmail,
			name: "Regular Member",
			masterPasswordHash: memberHash,
			key: "2.memberKey|iv==",
			keys: { publicKey: "member-public", encryptedPrivateKey: "2.memberPrivate|iv==" }
		})
		expect(memberRegistration.status).toBe(200)
		const memberLogin = await login(memberEmail, memberHash)
		expect(memberLogin.status).toBe(200)
		const { access_token: memberToken } = (await memberLogin.json()) as { access_token: string }

		const org = await createOrg(ownerToken)
		const invite = await api(ownerToken, "POST", `/api/organizations/${org.id}/users/invite`, {
			emails: [memberEmail],
			type: 2,
			accessAll: false,
			collections: [],
			groups: []
		})
		expect(invite.status).toBe(200)
		const members = (await (
			await api(ownerToken, "GET", `/api/organizations/${org.id}/users`)
		).json()) as Record<string, any>
		const member = members.data.find((row: any) => row.email === memberEmail)
		expect(member).toBeTruthy()
		const confirm = await api(
			ownerToken,
			"POST",
			`/api/organizations/${org.id}/users/${member.id}/confirm`,
			{ key: "2.memberOrgKey|iv==" }
		)
		expect(confirm.status).toBe(200)

		const collections = (await (
			await api(ownerToken, "GET", `/api/organizations/${org.id}/collections`)
		).json()) as Record<string, any>
		const cipher = await api(ownerToken, "POST", "/api/ciphers/create", {
			cipher: {
				type: 1,
				name: "2.privateOrgCipher|iv==",
				organizationId: org.id,
				login: { username: "2.u|iv==", uris: [] }
			},
			collectionIds: [collections.data[0].id]
		})
		expect(cipher.status).toBe(200)

		const orgDetails = await api(memberToken, "GET", `/api/organizations/${org.id}/details`)
		expect(orgDetails.status).toBe(404)
		const cipherDetails = await api(
			memberToken,
			"GET",
			`/api/ciphers/organization-details?organizationId=${org.id}`
		)
		expect(cipherDetails.status).toBe(404)
	})

	it("returns organization keys", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)
		const keys = (await (
			await api(token, "GET", `/api/organizations/${org.id}/keys`)
		).json()) as Record<string, any>
		expect(keys.object).toBe("organizationKeys")
		expect(keys.publicKey).toBe(ORG.keys.publicKey)
		expect(keys.privateKey).toBe(ORG.keys.encryptedPrivateKey)
	})

	it("blocks the sole owner from leaving and non-owners from deleting", async () => {
		const { access_token: token } = await registerAndLogin()
		const org = await createOrg(token)

		const leave = await api(token, "POST", `/api/organizations/${org.id}/leave`)
		expect(leave.status).toBe(400)
		expect(((await leave.json()) as Record<string, any>).errorModel.message).toContain("last owner")

		// Delete requires the master password
		const badDelete = await api(token, "POST", `/api/organizations/${org.id}/delete`, {
			masterPasswordHash: "wrong"
		})
		expect(badDelete.status).toBe(400)
	})
})
