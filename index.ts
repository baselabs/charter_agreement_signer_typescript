// CAP never authorizes.
//
// Public surface of the holder-side companion signer: one signing function
// per artifact kind, the key-handle contract, and the closed error
// vocabulary. Protocol checks run through prepareSigning and finishSigning
// in @charter-agreement-protocol/verifier. This package keeps custody.

export {
  signDescriptor,
  signReceipt,
  signAcceptance,
  signTermination,
  type KeyHandle,
  type KeySnapshot,
  type ChainView,
  type SigningOptions,
  type DescriptorOptions,
  type SignError,
  type SignResult,
} from "./signer.ts";
