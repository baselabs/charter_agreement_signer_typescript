// CAP never authorizes.
//
// Public surface of the holder-side companion signer: one signing function
// per artifact kind, the key-handle contract, and the closed error
// vocabulary. ALL protocol logic — framing, the producer claims gate, the
// R1-R3 refusal guards, assembly, and verification of the assembled
// artifact — goes through @charter-agreement-protocol/verifier: exactly
// one implementation. This package holds the custody half only.

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
