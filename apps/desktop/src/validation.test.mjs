import assert from "node:assert/strict";
import test from "node:test";
import { validateDevice, validateNotifications, validatePassword } from "./validation.ts";

test("device thresholds accept backend boundaries and reject crossing or fractional values", () => {
  assert.doesNotThrow(() => validateDevice("Device", -20, -25, "01".repeat(16), "", false));
  assert.doesNotThrow(() => validateDevice("Device", -100, -110, "", "", true));
  for (const [near, far] of [[-101, -110], [-19, -25], [-100, -111], [-20, -24], [-60, -60], [-60.5, -80]])
    assert.throws(() => validateDevice("Device", near, far, "", "", true));
});

test("identity import requires exactly one source on a new device", () => {
  assert.doesNotThrow(() => validateDevice("Device", -60, -80, "", "C:\\chosen\\identity.dpapi", false));
  assert.throws(() => validateDevice("Device", -60, -80, "01".repeat(16), "C:\\chosen\\identity.dpapi", false));
  assert.throws(() => validateDevice("Device", -60, -80, "", "identity.dpapi", false));
  assert.throws(() => validateDevice("Device", -60, -80, "", "C:\\chosen\\identity.txt", false));
  assert.throws(() => validateDevice("Device", -60, -80, "", "", false));
});

test("password requires a bound identity and respects the backend UTF-8 byte limit", () => {
  assert.throws(() => validatePassword("test value", false));
  assert.throws(() => validatePassword("密".repeat(342), true));
  assert.throws(() => validatePassword("a\0b", true));
  assert.doesNotThrow(() => validatePassword("a".repeat(1024), true));
});

test("notification validation rejects unsafe URLs and malformed Bark keys", () => {
  assert.doesNotThrow(() => validateNotifications("https://example.invalid/push?tag=watch", "test_key-123"));
  for (const endpoint of ["http://example.invalid", "https://@example.invalid", "https://example.invalid/#token", "https://example.invalid/a b"])
    assert.throws(() => validateNotifications(endpoint, ""));
  assert.throws(() => validateNotifications("https://example.invalid", "short"));
  assert.throws(() => validateNotifications("https://example.invalid", "has space in it"));
});
