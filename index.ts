// CAP never authorizes.
//
// Public surface of the holder-side companion signer: one signing function
// per artifact kind, the key-handle contract, and the closed error
// vocabulary. Verification of assembled artifacts goes through
// @charter-agreement-protocol/verifier — exactly one verification
// implementation.

export {
  signDescriptor,
  signReceipt,
  signAcceptance,
  signTermination,
  type KeyHandle,
  type KeySnapshot,
  type ChainView,
  type SignError,
  type SignResult,
} from "./signer.ts";
