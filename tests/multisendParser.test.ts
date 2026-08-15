import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { concatHex, encodeFunctionData, numberToHex, type Hex } from "viem";
import { MULTISEND_ABI, MultiSendDecodeError, decodeMultiSendCalldata, parseMultiSendPayload } from "../src/safe/multisend.js";
import { TARGET, UNKNOWN_TARGET, multiSendData, packSuboperation } from "./multisendFixtures.js";

describe("Safe MultiSend binary parser", () => {
  test("decodes one CALL with bigint value and empty calldata", () => {
    const parsed = parseMultiSendPayload(packSuboperation({ value: 2n ** 200n }));
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0]?.operation, "CALL");
    assert.equal(parsed[0]?.target, TARGET);
    assert.equal(parsed[0]?.value, 2n ** 200n);
    assert.equal(parsed[0]?.data, "0x");
    assert.equal(parsed[0]?.selector, "0x");
  });

  test("preserves multiple operations and CALL/DELEGATECALL order", () => {
    const parsed = parseMultiSendPayload(concatHex([
      packSuboperation({ target: TARGET, operation: "CALL", data: "0x12345678" }),
      packSuboperation({ target: UNKNOWN_TARGET, operation: "DELEGATECALL", data: "0xaabbccdd" })
    ]));
    assert.deepEqual(parsed.map((item) => [item.index, item.operation, item.target, item.selector]), [
      [0, "CALL", TARGET, "0x12345678"],
      [1, "DELEGATECALL", UNKNOWN_TARGET, "0xaabbccdd"]
    ]);
  });

  test("accepts an empty payload as a complete zero-operation batch", () => {
    assert.deepEqual(parseMultiSendPayload("0x"), []);
    assert.equal(decodeMultiSendCalldata(multiSendData([])), "0x");
  });

  test("rejects invalid operation and truncated address", () => {
    assert.throws(() => parseMultiSendPayload("0x0" as Hex), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "MALFORMED_CALLDATA");
    assert.throws(() => parseMultiSendPayload(packSuboperation({ operation: 2 })), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "INVALID_OPERATION");
    assert.throws(() => parseMultiSendPayload("0x00"), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "TRUNCATED_ADDRESS");
  });

  test("rejects truncation in value and dataLength fields", () => {
    const operationAndAddress = concatHex(["0x00", TARGET]);
    assert.throws(() => parseMultiSendPayload(operationAndAddress), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "TRUNCATED_VALUE");
    const partialValue = concatHex([operationAndAddress, numberToHex(0n, { size: 32 }), "0x00"]);
    assert.throws(() => parseMultiSendPayload(partialValue), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "TRUNCATED_DATA_LENGTH");
  });

  test("rejects dataLength beyond remaining bytes and residual bytes", () => {
    const header = concatHex(["0x00", TARGET, numberToHex(0n, { size: 32 }), numberToHex(4n, { size: 32 })]);
    assert.throws(() => parseMultiSendPayload(concatHex([header, "0x1234"])), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "DATA_LENGTH_EXCEEDS_REMAINING");
    const validPlusResidual = concatHex([packSuboperation(), "0xff"]);
    assert.throws(() => parseMultiSendPayload(validPlusResidual), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "TRUNCATED_ADDRESS");
  });

  test("distinguishes malformed outer ABI from a valid payload over per-operation limits", () => {
    assert.throws(() => decodeMultiSendCalldata("0x8d80ff0a00" as Hex), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "MALFORMED_CALLDATA");
    const data = packSuboperation({ data: "0x12345678" });
    assert.throws(() => parseMultiSendPayload(data, { maxSuboperationDataBytes: 3 }), (error) =>
      error instanceof MultiSendDecodeError && error.kind === "SUBOPERATION_DATA_LIMIT" && error.validButOverLimit);
  });

  test("decodes the standard multiSend(bytes) ABI exactly", () => {
    const payload = packSuboperation({ target: UNKNOWN_TARGET });
    const calldata = encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [payload] });
    assert.equal(decodeMultiSendCalldata(calldata), payload);
  });
});
