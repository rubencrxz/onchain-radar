import type { RpcClient } from "../rpc.js";
import type { ClassifiedSafeAction, SafeTransaction } from "./types.js";

export type SafeStateObservation = {
  beforeBlock: string;
  afterBlock: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
};

export async function observeSafeActionState(params: {
  rpc: RpcClient;
  transaction: SafeTransaction;
  action: ClassifiedSafeAction;
}): Promise<SafeStateObservation | undefined> {
  if (!params.action.known || params.action.semanticCategory !== "ADMINISTRATIVE_CONTROL") return undefined;
  if (params.rpc.supportsSafeStateReads === false) return undefined;
  const beforeBlock = params.transaction.blockNumber === 0n ? 0n : params.transaction.blockNumber - 1n;
  const afterBlock = params.transaction.blockNumber;
  const before: Record<string, unknown> = {};
  const after: Record<string, unknown> = {};
  const name = params.action.functionName;

  if (["changeThreshold", "addOwnerWithThreshold", "removeOwner"].includes(name) && params.rpc.getSafeThreshold !== undefined) {
    before.threshold = (await params.rpc.getSafeThreshold({ safe: params.transaction.safeAddress, blockNumber: beforeBlock })).toString();
    after.threshold = (await params.rpc.getSafeThreshold({ safe: params.transaction.safeAddress, blockNumber: afterBlock })).toString();
  }

  if (["addOwnerWithThreshold", "removeOwner", "swapOwner"].includes(name) && params.rpc.isSafeOwner !== undefined) {
    const owners = ownerParameters(params.action.functionName, params.action.parameters);
    for (const [label, owner] of owners) {
      before[label] = await params.rpc.isSafeOwner({ safe: params.transaction.safeAddress, owner, blockNumber: beforeBlock });
      after[label] = await params.rpc.isSafeOwner({ safe: params.transaction.safeAddress, owner, blockNumber: afterBlock });
    }
  }

  if (["enableModule", "disableModule"].includes(name) && params.rpc.isSafeModuleEnabled !== undefined) {
    const module = readAddress(params.action.parameters.module);
    if (module !== undefined) {
      before.moduleEnabled = await params.rpc.isSafeModuleEnabled({ safe: params.transaction.safeAddress, module, blockNumber: beforeBlock });
      after.moduleEnabled = await params.rpc.isSafeModuleEnabled({ safe: params.transaction.safeAddress, module, blockNumber: afterBlock });
    }
  }

  return Object.keys(before).length === 0
    ? undefined
    : { beforeBlock: beforeBlock.toString(), afterBlock: afterBlock.toString(), before, after };
}

function ownerParameters(
  functionName: string,
  parameters: Record<string, unknown>
): Array<[string, `0x${string}`]> {
  const values: Array<[string, unknown]> = functionName === "swapOwner"
    ? [["oldOwner", parameters.oldOwner], ["newOwner", parameters.newOwner]]
    : [["owner", parameters.owner]];
  return values.flatMap(([label, value]) => {
    const address = readAddress(value);
    return address === undefined ? [] : [[label, address]];
  });
}

function readAddress(value: unknown): `0x${string}` | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) ? value as `0x${string}` : undefined;
}
