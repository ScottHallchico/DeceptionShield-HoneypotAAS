import { test } from "node:test";
import assert from "node:assert";
import request from "supertest";
import app from "../index.js";

test("Midnight Bridge API Tests", async (t) => {

  await t.test("GET /health should return status ok and simulate mode", async () => {
    const res = await request(app).get("/health");
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, "ok");
    assert.strictEqual(res.body.simulate, true, "Should be running in simulate mode for testing");
  });

  await t.test("GET /stats should initially return 0 attestations", async () => {
    const res = await request(app).get("/stats");
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.totalAttestations, 0);
  });

  const testIndicatorHash = "0x1111111111111111111111111111111111111111111111111111111111111111";

  await t.test("GET /query/:hash should return 0 for unknown indicator", async () => {
    const res = await request(app).get(`/query/${testIndicatorHash}`);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.corroborationCount, 0);
    assert.strictEqual(res.body.highConfidenceCount, 0);
  });

  await t.test("POST /attest should increment attestation counts (low severity)", async () => {
    const res = await request(app)
      .post("/attest")
      .send({ indicatorHash: testIndicatorHash, severityScore: 50 });
    
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, "confirmed");
    assert.ok(res.body.txHash.startsWith("0x"));

    // Verify state updated
    const queryRes = await request(app).get(`/query/${testIndicatorHash}`);
    assert.strictEqual(queryRes.body.corroborationCount, 1);
    assert.strictEqual(queryRes.body.highConfidenceCount, 0, "High confidence count should not increment for severity < 70");
  });

  await t.test("POST /attest should increment high confidence count (high severity)", async () => {
    const res = await request(app)
      .post("/attest")
      .send({ indicatorHash: testIndicatorHash, severityScore: 85 });
    
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, "confirmed");

    // Verify state updated
    const queryRes = await request(app).get(`/query/${testIndicatorHash}`);
    assert.strictEqual(queryRes.body.corroborationCount, 2);
    assert.strictEqual(queryRes.body.highConfidenceCount, 1, "High confidence count should increment for severity >= 70");
  });

  await t.test("GET /stats should now return 2 total attestations", async () => {
    const res = await request(app).get("/stats");
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.totalAttestations, 2);
  });

});
