const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const { app, database } = require("../server");

test.after(() => database.close());

test("login page renders security headers and a CSRF token", async () => {
  const response = await request(app).get("/login");
  assert.equal(response.status, 200);
  assert.match(response.headers["x-content-type-options"], /nosniff/);
  assert.match(response.text, /name="_csrf"/);
});

test("registration rejects a short password", async () => {
  const agent = request.agent(app);
  const page = await agent.get("/register");
  const token = page.text.match(/name="_csrf" value="([^"]+)"/)[1];
  const response = await agent.post("/register").type("form").send({
    _csrf: token,
    email: "test@example.com",
    password: "short"
  });
  assert.equal(response.status, 400);
  assert.match(response.text, /12 to 128 characters/);
});
